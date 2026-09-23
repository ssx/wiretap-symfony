<?php

declare(strict_types=1);

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\SymfonyContextEnricher;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * @param array<string, mixed> $wiretap
 */
function configuredRecorder(array $wiretap): Recorder
{
    $kernel = new TestKernel(array_replace(['enabled' => true, 'presets' => []], $wiretap), bin2hex(random_bytes(6)));
    $kernel->boot();

    /** @var Recorder $recorder */
    $recorder = $kernel->getContainer()->get('test.service_container')->get(Recorder::class);
    $recorder->setSink(new InMemorySink());

    return $recorder;
}

/**
 * @param array<string, mixed> $options
 */
function recordThrough(Recorder $recorder, string $url, array $options = [], ?MockResponse $response = null): \Ssx\Wiretap\Exchange
{
    $client = new WiretapHttpClient(
        new MockHttpClient($response ?? new MockResponse('{}')),
        static fn (): Recorder => $recorder,
    );

    try {
        $client->request('GET', $url, $options)->getContent();
    } catch (\Throwable) {
        // A 4xx/5xx is still an exchange.
    }

    $recorder->flush();
    $sink = $recorder->sink();
    assert($sink instanceof InMemorySink);

    return $sink->all()[0];
}

afterEach(fn () => Wiretap::reset());

describe('an HTTP error response', function (): void {
    it('keeps the body out of error.message', function (): void {
        // Symfony builds the exception message from a problem+json `detail`.
        // The body was omitted, so body_paths never saw the value, and the
        // message carried it into the record verbatim.
        $recorder = new Recorder(
            sink: $sink = new InMemorySink(),
            redactor: new \Ssx\Wiretap\Redaction\Redactor(new \Ssx\Wiretap\Redaction\RedactionConfig(bodyPaths: ['detail'])),
        );
        $client = new WiretapHttpClient(new MockHttpClient(new MockResponse(
            '{"detail":"ordinarysecretvalue"}',
            ['http_code' => 400, 'response_headers' => ['content-type: application/problem+json']],
        )), static fn (): Recorder => $recorder);

        $response = $client->request('GET', 'https://api.example.test/x');

        try {
            $response->getHeaders();
        } catch (\Throwable $e) {
            // What the application sees is unchanged.
            expect($e->getMessage())->toContain('ordinarysecretvalue');
        }

        $recorder->flush();
        $record = $sink->all()[0];

        expect((string) json_encode($record))->not->toContain('ordinarysecretvalue')
            ->and($record->error?->message)->toBe('HTTP 400 response')
            ->and($record->failed())->toBeTrue();
    });
});

describe('the inbound route in context', function (): void {
    /**
     * @param array<string, mixed> $attributes
     */
    function contextFor(string $path, array $attributes): array
    {
        $request = Request::create($path);
        $request->attributes->add($attributes);
        $stack = new RequestStack();
        $stack->push($request);

        $recorder = new Recorder(sink: $sink = new InMemorySink());
        $recorder->addEnricher(new SymfonyContextEnricher($stack));

        (new WiretapHttpClient(new MockHttpClient(new MockResponse('{}')), static fn (): Recorder => $recorder))
            ->request('POST', 'https://mail.example.test/send')->getContent();
        $recorder->flush();

        return $sink->all()[0]->context;
    }

    it('does not store a path that carries route parameters', function (): void {
        // /reset-password/<token> was stored as context, which no redaction
        // rule looks at. The route name says which endpoint it was.
        $context = contextFor('/reset-password/9f86d081884c7d659a2feaa0c55ad015', [
            '_route' => 'password_reset',
            '_route_params' => ['token' => '9f86d081884c7d659a2feaa0c55ad015'],
        ]);

        expect((string) json_encode($context))->not->toContain('9f86d081884c7d659a2feaa0c55ad015')
            ->and($context['route'] ?? null)->toBe('password_reset');
    });

    it('keeps the path of a route without parameters', function (): void {
        $context = contextFor('/checkout', ['_route' => 'checkout', '_route_params' => ['_locale' => 'en']]);

        expect($context['uri'] ?? null)->toBe('/checkout');
    });

    it('does not store a path no route matched', function (): void {
        $context = contextFor('/unmatched/secret-looking-thing', []);

        expect($context)->not->toHaveKey('uri');
    });
});

describe('redaction configuration', function (): void {
    it('adds configured headers and query parameters to the defaults', function (): void {
        // There was no way to name a header like Ocp-Apim-Subscription-Key,
        // so it was stored in full.
        $recorder = configuredRecorder(['redaction' => [
            'headers' => ['Ocp-Apim-Subscription-Key'],
            'query' => ['subscription-key'],
        ]]);

        $record = recordThrough($recorder, 'https://api.cognitive.test/v1?subscription-key=a1b2c3d4e5f6a7b8', [
            'headers' => [
                'Ocp-Apim-Subscription-Key' => 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
                'Authorization' => 'Basic dXNlcjpwYXNzd29yZA==',
            ],
        ]);
        $stored = (string) json_encode($record);

        expect($stored)->not->toContain('a1b2c3d4e5f6a7b8')
            // Adding one header must not stop the defaults applying.
            ->and($stored)->not->toContain('dXNlcjpwYXNzd29yZA');
    });

    it('keeps only the named headers in allow mode', function (): void {
        // Allow mode must not have the default denylist merged into it: that
        // would put X-Api-Key on the list of headers to keep.
        $recorder = configuredRecorder(['redaction' => [
            'header_mode' => 'allow',
            'headers' => ['Accept'],
        ]]);

        $record = recordThrough($recorder, 'https://api.example.test/', [
            'headers' => ['Accept' => 'application/json', 'X-Api-Key' => 'allow-mode-secret-99'],
        ]);

        expect((string) json_encode($record))->not->toContain('allow-mode-secret-99')
            ->and($record->requestHeaders->pairs())->toContain(['Accept', 'application/json']);
    });

    it('turns on a detector and applies a custom pattern', function (): void {
        $recorder = configuredRecorder(['redaction' => [
            'patterns' => ['email' => true],
            'custom' => ['/\bacct_[A-Za-z0-9]{16}\b/'],
        ]]);

        $record = recordThrough($recorder, 'https://api.example.test/', [], new MockResponse(
            '{"who":"someone@example.org","acct":"acct_ABCDEFGHIJKLMNOP"}',
            ['response_headers' => ['content-type: application/json']],
        ));
        $stored = (string) json_encode($record);

        expect($stored)->not->toContain('someone@example.org')
            ->and($stored)->not->toContain('acct_ABCDEFGHIJKLMNOP');
    });

    it('rejects a header mode it does not know', function (): void {
        // A protective switch with a typo must not quietly mean "off".
        expect(fn () => configuredRecorder(['redaction' => ['header_mode' => 'alow']]))
            ->toThrow(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
    });
});

describe('the sampling key', function (): void {
    function samplingSalt(Recorder $recorder): ?string
    {
        $sampler = (new ReflectionProperty($recorder, 'sampler'))->getValue($recorder);
        assert($sampler instanceof Sampler);

        return (new ReflectionProperty($sampler, 'samplingSalt'))->getValue($sampler);
    }

    it('defaults to the kernel secret', function (): void {
        // Sampling is keyed on the correlation id, which is adopted from an
        // inbound X-Request-Id or traceparent. Unsalted, a caller could pick
        // an id offline that keeps their traffic out of the capture.
        expect(samplingSalt(configuredRecorder([])))->toBe('test');
    });

    it('can be set explicitly', function (): void {
        expect(samplingSalt(configuredRecorder(['sampling_salt' => 'explicit-salt'])))->toBe('explicit-salt');
    });
});
