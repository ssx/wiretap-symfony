<?php

declare(strict_types=1);

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\Tests\HttpClientConsumer;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Stands in for an application's mock_response_factory, echoing the headers
 * the transport was asked to send.
 */
final class EchoingMockResponseFactory
{
    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        return new MockResponse(
            (string) json_encode(['headers' => $options['headers'] ?? []]),
            ['response_headers' => ['content-type: application/json']],
        );
    }
}

/**
 * A kernel with a scoped client, exposed through a consumer so the container
 * keeps it.
 *
 * @param array<string, mixed> $wiretap
 * @param array<string, mixed> $httpClient
 */
function coverageKernel(array $wiretap, array $httpClient): TestKernel
{
    $kernel = new TestKernel(
        $wiretap,
        bin2hex(random_bytes(6)),
        ['http_client' => $httpClient],
        static function (ContainerBuilder $container): void {
            $container->register('test.mock_response_factory', EchoingMockResponseFactory::class);
            $container->register('test.scoped_consumer', HttpClientConsumer::class)
                ->setPublic(true)
                ->setArguments([new Reference('partner.client')]);
        },
    );
    $kernel->boot();

    return $kernel;
}

/**
 * @return array{Recorder, InMemorySink}
 */
function coverageRecorder(TestKernel $kernel): array
{
    /** @var Recorder $recorder */
    $recorder = $kernel->getContainer()->get('test.service_container')->get(Recorder::class);
    $recorder->setSink($sink = new InMemorySink());

    return [$recorder, $sink];
}

afterEach(function (): void {
    putenv('WIRETAP_ENABLED');
    Wiretap::reset();
});

describe('clients configured in the framework', function (): void {
    beforeEach(function (): void {
        $this->server = startEchoServer();
        $this->base = 'http://127.0.0.1:' . ECHO_SERVER_PORT;
    });

    afterEach(function (): void {
        stopStallingServer($this->server);
    });

    it('learns a credential from framework default_options', function (): void {
        // default_options are applied inside the transport, below where
        // capture looked, so a default credential was never learned and its
        // echo was stored in plaintext.
        $kernel = coverageKernel(['enabled' => true, 'presets' => []], [
            'default_options' => ['headers' => ['X-Api-Key' => 'framework-default-secret-1']],
            'scoped_clients' => ['partner.client' => ['base_uri' => $this->base . '/partner/']],
        ]);
        [$recorder, $sink] = coverageRecorder($kernel);

        $echo = $kernel->getContainer()->get('test.consumer')->client
            ->request('GET', $this->base . '/default')->getContent();

        // The request itself is untouched.
        expect($echo)->toContain('framework-default-secret-1');

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and((string) json_encode($sink->all()))->not->toContain('framework-default-secret-1');
    });

    it('captures a scoped client, and redacts its configured headers', function (): void {
        // Only `http_client` was decorated, so a scoped client produced no
        // record at all.
        $kernel = coverageKernel(['enabled' => true, 'presets' => []], [
            'scoped_clients' => [
                'partner.client' => [
                    'base_uri' => $this->base . '/partner/',
                    'headers' => ['X-Api-Key' => 'scoped-client-secret-2'],
                ],
            ],
        ]);
        [$recorder, $sink] = coverageRecorder($kernel);

        $echo = $kernel->getContainer()->get('test.scoped_consumer')->client
            ->request('GET', 'thing')->getContent();

        expect($echo)->toContain('scoped-client-secret-2');

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->uri)->toContain('/partner/thing')
            ->and((string) json_encode($sink->all()))->not->toContain('scoped-client-secret-2');
    });
});

describe('a mock_response_factory', function (): void {
    it('is still captured, now that the transport is decorated', function (): void {
        // The framework's MockHttpClient decorates http_client.transport too.
        // If it sat outside the capture decorator it would never call it, and
        // every test using a mock factory would silently record nothing.
        $kernel = coverageKernel(['enabled' => true, 'presets' => []], [
            'mock_response_factory' => 'test.mock_response_factory',
            'scoped_clients' => [
                'partner.client' => ['base_uri' => 'https://partner.example.test/'],
            ],
        ]);
        [$recorder, $sink] = coverageRecorder($kernel);

        $kernel->getContainer()->get('test.consumer')->client
            ->request('GET', 'https://api.example.test/x')->getContent();
        $recorder->flush();

        expect($sink->all())->toHaveCount(1);
    });
});

describe('a bundle configured as disabled', function (): void {
    it('publishes its disabled recorder, so the environment cannot turn capture on', function (): void {
        // boot() skipped publishing when disabled, so the global holder built
        // core's default from WIRETAP_ENABLED instead: bundle `enabled: false`
        // still recorded, to a sink and with redaction the bundle never
        // configured.
        putenv('WIRETAP_ENABLED=1');

        $kernel = coverageKernel(['enabled' => false, 'redaction' => ['body_paths' => ['ssn']]], [
            'mock_response_factory' => 'test.mock_response_factory',
            'scoped_clients' => [
                'partner.client' => ['base_uri' => 'https://partner.example.test/'],
            ],
        ]);

        $container = $kernel->getContainer()->get('test.service_container');

        expect(Wiretap::recorder())->toBe($container->get(Recorder::class))
            ->and(Wiretap::recorder()->isEnabled())->toBeFalse();
    });
});
