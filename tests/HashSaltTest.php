<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Symfony\WiretapBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Core keeps a digest of a body it did not store (omitted, or truncated) only
 * as an HMAC under RedactionConfig::$hashSalt, and none at all without one.
 * The bundle never set that salt, so every such body lost the "did this body
 * change between calls" comparison.
 *
 * The bodies here carry the full-body SHA-256 the capture layer supplies
 * (ssx/wiretap-auto always does), and go through the redactor the container
 * built, so what is asserted is exactly what would reach the log.
 */
function hashSaltTruncatedBody(): string
{
    return str_repeat('the quick brown fox jumps over the lazy dog ', 10);
}

function hashSaltBinaryBody(): string
{
    return "\x89PNG\r\n\x1a\n" . str_repeat("\x00\x01\x02\x03", 16);
}

/**
 * @param array<string, mixed> $wiretap
 * @param array<string, mixed> $framework
 *
 * @return array{truncated: list<?string>, binary: list<?string>}
 */
function hashSaltDigests(array $wiretap = [], array $framework = []): array
{
    $kernel = new TestKernel(
        array_replace(['enabled' => true, 'presets' => []], $wiretap),
        bin2hex(random_bytes(6)),
        $framework,
    );
    $kernel->boot();

    /** @var Recorder $recorder */
    $recorder = $kernel->getContainer()->get('test.service_container')->get(Recorder::class);
    $redactor = $recorder->redactor();
    $digests = ['truncated' => [], 'binary' => []];

    for ($i = 0; $i < 2; ++$i) {
        $truncated = $redactor->redactBody(CapturedBody::captured(
            bytes: substr(hashSaltTruncatedBody(), 0, 32),
            size: strlen(hashSaltTruncatedBody()),
            contentType: 'text/plain',
            truncated: true,
            sha256: hash('sha256', hashSaltTruncatedBody()),
        ));

        $binary = $redactor->redactBody(CapturedBody::captured(
            bytes: hashSaltBinaryBody(),
            contentType: 'image/png',
            sha256: hash('sha256', hashSaltBinaryBody()),
        ));

        expect($truncated->truncated)->toBeTrue()
            ->and($binary->omittedReason)->toBe(CapturedBody::OMITTED_BINARY);

        $digests['truncated'][] = $truncated->sha256;
        $digests['binary'][] = $binary->sha256;
    }

    $kernel->shutdown();

    return $digests;
}

/**
 * @param array{truncated: list<?string>, binary: list<?string>} $digests
 */
function expectKeyedWith(array $digests, string $key): void
{
    expect($digests['truncated'][0])->toBe(hash_hmac('sha256', hash('sha256', hashSaltTruncatedBody()), $key))
        ->and($digests['truncated'][1])->toBe($digests['truncated'][0])
        ->and($digests['binary'][0])->toBe(hash_hmac('sha256', hash('sha256', hashSaltBinaryBody()), $key))
        ->and($digests['binary'][1])->toBe($digests['binary'][0]);
}

describe('digest of a body that was not stored', function (): void {
    it('keeps a stable digest keyed from the kernel secret by default', function (): void {
        // Derived from the secret, not the secret itself: the sampler is
        // already keyed with kernel.secret.
        expectKeyedWith(hashSaltDigests(), hash_hmac('sha256', 'wiretap-redaction', 'test'));
    });

    it('derives from an env-backed secret at runtime', function (): void {
        $_SERVER['WIRETAP_TEST_SECRET'] = 'secret-from-env';

        try {
            $digests = hashSaltDigests(framework: ['secret' => '%env(WIRETAP_TEST_SECRET)%']);
        } finally {
            unset($_SERVER['WIRETAP_TEST_SECRET']);
        }

        expectKeyedWith($digests, hash_hmac('sha256', 'wiretap-redaction', 'secret-from-env'));
    });

    it('never keeps the raw SHA-256 of the bytes it did not store', function (): void {
        $digests = hashSaltDigests();

        expect($digests['truncated'][0])->not->toBe(hash('sha256', hashSaltTruncatedBody()))
            ->and($digests['binary'][0])->not->toBe(hash('sha256', hashSaltBinaryBody()));
    });
});

describe('redaction.hash_salt', function (): void {
    it('overrides the key derived from the kernel secret', function (): void {
        expectKeyedWith(
            hashSaltDigests(['redaction' => ['hash_salt' => 'explicit-redaction-salt']]),
            'explicit-redaction-salt',
        );
    });

    it('keeps no digest when set to an empty value', function (string $salt): void {
        $digests = hashSaltDigests(['redaction' => ['hash_salt' => $salt]]);

        expect($digests['truncated'])->toBe([null, null])
            ->and($digests['binary'])->toBe([null, null]);
    })->with(['empty' => '', 'blank' => '  ']);

    it('keeps no digest and does not throw when the env secret is empty', function (): void {
        // FrameworkBundle refuses an empty literal secret at compile time, so
        // the reachable case is an env-backed one that resolves to nothing.
        $_SERVER['WIRETAP_TEST_SECRET'] = '';

        try {
            $digests = hashSaltDigests(framework: ['secret' => '%env(WIRETAP_TEST_SECRET)%']);
        } finally {
            unset($_SERVER['WIRETAP_TEST_SECRET']);
        }

        expect($digests['truncated'])->toBe([null, null])
            ->and($digests['binary'])->toBe([null, null]);
    });

    it('keeps no digest and does not throw without a kernel secret at all', function (): void {
        // The bundle does not require FrameworkBundle, and without it there is
        // no kernel.secret parameter to derive from.
        $container = new ContainerBuilder();
        $bundle = new WiretapBundle();
        $container->registerExtension($bundle->getContainerExtension());
        $container->loadFromExtension('wiretap', [
            'enabled' => true,
            'presets' => [],
            'path' => sys_get_temp_dir() . '/wiretap-symfony-no-secret',
        ]);
        $bundle->build($container);
        $container->compile();

        /** @var Recorder $recorder */
        $recorder = $container->get(Recorder::class);

        $body = $recorder->redactor()->redactBody(CapturedBody::captured(
            bytes: hashSaltBinaryBody(),
            contentType: 'image/png',
            sha256: hash('sha256', hashSaltBinaryBody()),
        ));

        expect($body->omittedReason)->toBe(CapturedBody::OMITTED_BINARY)
            ->and($body->sha256)->toBeNull();
    });
});
