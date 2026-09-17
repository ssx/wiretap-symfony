<?php

declare(strict_types=1);

use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Boot a kernel with the bundle configured.
 *
 * @param array<string, mixed> $config
 */
function bootKernel(array $config): TestKernel
{
    $kernel = new TestKernel($config, bin2hex(random_bytes(6)));
    $kernel->boot();

    return $kernel;
}

/**
 * The compiled container makes most services private. FrameworkBundle's
 * `test: true` exposes them through test.service_container, which is the
 * supported way to reach them from a test.
 */
function svc(TestKernel $kernel, string $id): mixed
{
    return $kernel->getContainer()->get('test.service_container')->get($id);
}

/**
 * The decorator over a mock transport.
 *
 * Built directly rather than by replacing a service on a compiled container,
 * which is not supported for a private service. The decorator and the
 * container-built recorder are what is under test; the transport underneath is
 * irrelevant.
 *
 * @param list<MockResponse> $responses
 */
function mockedClient(TestKernel $kernel, array $responses): WiretapHttpClient
{
    return new WiretapHttpClient(new MockHttpClient($responses), recorder($kernel));
}

function recorder(TestKernel $kernel): Recorder
{
    return svc($kernel, Recorder::class);
}

function exchangesIn(string $path): array
{
    return iterator_to_array((new NdjsonReader($path))->query(new ExchangeQuery(limit: 50)), false);
}

beforeEach(function (): void {
    $this->path = sys_get_temp_dir() . '/wiretap-symfony-' . bin2hex(random_bytes(6));
});

afterEach(function (): void {
    // Guarded rather than suppressed with @: PHPUnit installs an error handler
    // that fires regardless of suppression, so a teardown removing a directory
    // a test never created would report a warning on a passing test.
    if (is_dir($this->path)) {
        foreach (glob($this->path . '/*') ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }

        rmdir($this->path);
    }

    Wiretap::reset();
});

describe('the bundle', function (): void {
    it('registers a recorder and a reader', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        expect(recorder($kernel))->toBeInstanceOf(Recorder::class)
            ->and(svc($kernel, NdjsonReader::class))->toBeInstanceOf(NdjsonReader::class)
            ->and(recorder($kernel)->isEnabled())->toBeTrue();
    });

    it('decorates the real http_client chain, so an injected client is recorded', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path, 'presets' => []]);

        /** @var \Ssx\Wiretap\Symfony\Tests\HttpClientConsumer $consumer */
        $consumer = $kernel->getContainer()->get('test.consumer');

        // Symfony wraps our decorator in its own (UriTemplateHttpClient among
        // them), so asserting on the outermost class would be asserting on
        // Symfony's internals. What matters is that the chain records.
        $response = $consumer->client->request('GET', 'http://127.0.0.1:1/nothing-listening', [
            'timeout' => 2,
        ]);

        try {
            $response->getStatusCode();
        } catch (\Throwable) {
            // A connection failure is still an exchange.
        }

        recorder($kernel)->flush();
        $exchanges = exchangesIn($this->path);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->uri)->toContain('127.0.0.1:1')
            ->and($exchanges[0]->failed())->toBeTrue();
    });

    it('publishes its recorder to the global holder, so the curl hooks agree', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        // The bundle resolves the recorder during boot precisely so this holds
        // without anything having asked the container for it first.
        expect(Wiretap::recorder())->toBe(recorder($kernel));
    });

    it('defaults to disabled', function (): void {
        $kernel = bootKernel(['path' => $this->path]);

        expect(recorder($kernel)->isEnabled())->toBeFalse();
    });
});

describe('capture through the decorator', function (): void {
    it('records a request and its response', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);
        $client = mockedClient($kernel, [new MockResponse('{"id":42}', [
            'http_code' => 201,
            'response_headers' => ['content-type' => 'application/json'],
        ])]);

        $response = $client->request('POST', 'https://api.example.com/v1/orders', [
            'headers' => ['Content-Type' => 'application/json'],
            'json' => ['sku' => 'ABC'],
        ]);

        // Symfony responses are lazy: the exchange is not complete until
        // something reads it.
        expect($response->getStatusCode())->toBe(201);

        recorder($kernel)->flush();
        $exchanges = exchangesIn($this->path);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->method)->toBe('POST')
            ->and($exchanges[0]->status)->toBe(201)
            ->and($exchanges[0]->requestBody->bytes)->toContain('ABC')
            ->and($exchanges[0]->responseBody->bytes)->toContain('42');
    });

    it('leaves the response usable by the application', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);
        $response = mockedClient($kernel, [new MockResponse('{"ok":true}', ['http_code' => 200])])
            ->request('GET', 'https://api.example.com/v1');

        // Capture must not consume the content the caller is about to read.
        expect($response->getContent())->toBe('{"ok":true}')
            ->and($response->toArray())->toBe(['ok' => true]);
    });

    it('records exactly once however many times the response is read', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);
        $response = mockedClient($kernel, [new MockResponse('{"ok":true}', ['http_code' => 200])])
            ->request('GET', 'https://api.example.com/v1');

        $response->getStatusCode();
        $response->getHeaders();
        $response->getContent();
        $response->toArray();

        recorder($kernel)->flush();

        expect(exchangesIn($this->path))->toHaveCount(1);
    });

    it('records a 4xx without the error escaping the capture path', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);
        $response = mockedClient($kernel, [new MockResponse('{"error":"nope"}', ['http_code' => 422])])
            ->request('GET', 'https://api.example.com/v1');

        expect($response->getStatusCode())->toBe(422);

        recorder($kernel)->flush();
        $exchanges = exchangesIn($this->path);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->status)->toBe(422)
            ->and($exchanges[0]->responseBody->bytes)->toContain('nope')
            ->and($exchanges[0]->failed())->toBeTrue();
    });

    it('records nothing for a blocklisted host but still performs the request', function (): void {
        $kernel = bootKernel([
            'enabled' => true, 'path' => $this->path,
            'blocklist' => ['*.stripe.com'], 'presets' => [],
        ]);
        $response = mockedClient($kernel, [new MockResponse('{"charged":true}', ['http_code' => 200])])
            ->request('POST', 'https://api.stripe.com/v1/charges');

        // Blocking capture must never block traffic.
        expect($response->getContent())->toContain('charged');

        recorder($kernel)->flush();

        expect(exchangesIn($this->path))->toBeEmpty();
    });

    it('applies configured redaction body paths', function (): void {
        $kernel = bootKernel([
            'enabled' => true,
            'path' => $this->path,
            'presets' => [],
            'redaction' => ['body_paths' => ['card.cvv']],
        ]);

        mockedClient($kernel, [new MockResponse('{}', ['http_code' => 200])])
            ->request('POST', 'https://api.example.com/pay', [
                'json' => ['card' => ['cvv' => '123', 'brand' => 'visa']],
            ])->getStatusCode();

        recorder($kernel)->flush();
        $written = json_encode(exchangesIn($this->path));

        expect($written)->not->toContain('"123"')
            ->and($written)->toContain('visa');
    });
});
