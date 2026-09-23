<?php

declare(strict_types=1);

use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\HttpClient\Exception\ServerException;
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

        unset($response);

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
        // something reads it. Reading the content is also what permits body
        // capture — status alone deliberately does not pull the body.
        expect($response->getStatusCode())->toBe(201)
            ->and($response->getContent())->toContain('42');

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

        expect($response->getStatusCode())->toBe(422)
            ->and($response->getContent(false))->toContain('nope');

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

describe('hardening found by review', function (): void {
    it('does not consume an unbuffered response', function (): void {
        // Capture called getContent() from getStatusCode(). With buffer=>false
        // that consumed the body, and the application's own getContent() then
        // threw "Cannot get the content of the response twice".
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        $response = mockedClient($kernel, [new MockResponse('streamed payload', ['http_code' => 200])])
            ->request('GET', 'https://api.example.com/v1', ['buffer' => false]);

        expect($response->getStatusCode())->toBe(200)
            ->and($response->getContent())->toBe('streamed payload');
    });

    it('does not pull a body when only the status is read', function (): void {
        // A headers-only operation must not download a large or endless body.
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        $response = mockedClient($kernel, [new MockResponse('body', ['http_code' => 200])])
            ->request('GET', 'https://api.example.com/v1');

        $response->getStatusCode();
        unset($response);
        recorder($kernel)->flush();

        $exchanges = exchangesIn($this->path);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->status)->toBe(200)
            ->and($exchanges[0]->responseBody->isPresent())->toBeFalse();
    });

    it('keeps the declared content type on a string body', function (): void {
        // Passing null lost the type, so the redactor could not choose form
        // parsing and body_paths did nothing on a urlencoded body.
        $kernel = bootKernel([
            'enabled' => true,
            'path' => $this->path,
            'presets' => [],
            'redaction' => ['body_paths' => ['password']],
        ]);

        mockedClient($kernel, [new MockResponse('{}', ['http_code' => 200])])
            ->request('POST', 'https://api.example.com/login', [
                'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
                'body' => 'password=ordinary-secret&user=alice',
            ])->getContent();

        recorder($kernel)->flush();
        $written = json_encode(exchangesIn($this->path));

        expect($written)->not->toContain('ordinary-secret')
            ->and($written)->toContain('alice');
    });

    it('does not serialise a JsonSerializable body twice', function (): void {
        // Serialising here as well as in Symfony invoked user code twice: a
        // counter captured 1 and transmitted 2, and side effects happened
        // twice.
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        $payload = new class implements JsonSerializable {
            public int $calls = 0;

            public function jsonSerialize(): mixed
            {
                ++$this->calls;

                return ['counter' => $this->calls];
            }
        };

        mockedClient($kernel, [new MockResponse('{}', ['http_code' => 200])])
            ->request('POST', 'https://api.example.com/v1', ['json' => $payload])
            ->getContent();

        expect($payload->calls)->toBe(1);
    });

    it('learns a credential Symfony generated from auth_bearer', function (): void {
        // The token never appears in the caller's headers, so a response
        // echoing it was recorded verbatim.
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path, 'presets' => []]);

        mockedClient($kernel, [new MockResponse('{"echo":"opaque-secret-123"}', ['http_code' => 200])])
            ->request('GET', 'https://api.example.com/v1', ['auth_bearer' => 'opaque-secret-123'])
            ->getContent();

        recorder($kernel)->flush();

        expect(json_encode(exchangesIn($this->path)))->not->toContain('opaque-secret-123');
    });

    it('records a transport failure that happened after a status arrived', function (): void {
        // curl can deliver 200 headers and then fail mid-body. Discarding the
        // error because a status existed recorded a failed transfer as a
        // success, and always-keep-failures sampling then dropped it.
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        $response = mockedClient($kernel, [
            new MockResponse(['chunk', new \Symfony\Component\HttpClient\Exception\TransportException('broke mid-body')], ['http_code' => 200]),
        ])->request('GET', 'https://api.example.com/v1');

        try {
            $response->getContent();
        } catch (\Throwable) {
            // expected
        }

        recorder($kernel)->flush();
        $exchanges = exchangesIn($this->path);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->error)->not->toBeNull()
            ->and($exchanges[0]->failed())->toBeTrue();
    });
});

describe('resource fixes found by review', function (): void {
    it('gates a relative url against its resolved base_uri', function (): void {
        // The gate saw only `/private`, so a base_uri pointing at a blocked
        // host had its body read and only then rejected. Nothing was stored,
        // but the payload existed.
        $kernel = bootKernel([
            'enabled' => true,
            'path' => $this->path,
            'presets' => [],
            'blocklist' => ['blocked.test'],
        ]);

        $response = mockedClient($kernel, [new MockResponse('{"card":"4111111111111111"}', ['http_code' => 200])])
            ->request('GET', '/private', ['base_uri' => 'https://blocked.test']);

        // The request still happens; only capture is refused.
        expect($response->getContent())->toContain('4111');

        recorder($kernel)->flush();

        expect(exchangesIn($this->path))->toBeEmpty();
    });

    it('yields the caller its own response object when streaming', function (): void {
        // Yielding the inner response broke `$key === $response` and any
        // response-keyed map, which is how a multiplexed stream is driven.
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);
        $client = mockedClient($kernel, [new MockResponse('streamed', ['http_code' => 200])]);

        $response = $client->request('GET', 'https://api.example.com/v1');

        $seen = [];

        foreach ($client->stream($response) as $key => $chunk) {
            $seen[] = $key === $response;
        }

        expect($seen)->not->toBeEmpty()
            ->and(array_unique($seen))->toBe([true]);
    });

    it('records a response consumed entirely through stream()', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);
        $client = mockedClient($kernel, [new MockResponse('streamed', ['http_code' => 200])]);

        $response = $client->request('GET', 'https://api.example.com/v1');

        foreach ($client->stream($response) as $chunk) {
            // consume
        }

        recorder($kernel)->flush();

        expect(exchangesIn($this->path))->toHaveCount(1);
    });

    it('accepts the documented console options', function (): void {
        // An IS_ARRAY argument rejects unknown options, so every documented
        // flag threw "The --failed option does not exist".
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path]);

        $command = new \Ssx\Wiretap\Symfony\Command\WiretapCommand($this->path, 7);
        $tester = new \Symfony\Component\Console\Tester\CommandTester($command);

        $tester->execute(['subcommand' => 'list', '--failed' => true, '--limit' => '5']);

        expect($tester->getStatusCode())->toBe(0)
            ->and($tester->getDisplay())->not->toBe('');
    });
});

describe('error chunks in a stream', function (): void {
    beforeEach(function (): void {
        $this->server = startStallingServer();
        $this->slowUrl = 'http://127.0.0.1:' . STALLING_SERVER_PORT . '/slow';
    });

    afterEach(function (): void {
        stopStallingServer($this->server);
    });

    it('does not throw from current() before the caller can inspect the chunk', function (): void {
        // ErrorChunk::isLast() throws. Calling it unconditionally meant
        // Symfony's own documented pattern — foreach stream, then
        // `if ($chunk->isTimeout()) continue;` — threw from inside current()
        // before the caller's check could run. This happened even with
        // capture disabled, because the decorator is always installed.
        $client = new WiretapHttpClient(
            new \Symfony\Component\HttpClient\NativeHttpClient(),
            new Recorder(sink: new InMemorySink(), enabled: false),
        );

        $response = $client->request('GET', $this->slowUrl);
        $sawTimeout = false;

        foreach ($client->stream($response, 0.3) as $chunk) {
            if ($chunk->isTimeout()) {
                $sawTimeout = true;

                break;
            }
        }

        expect($sawTimeout)->toBeTrue();
    });

    it('behaves exactly as the undecorated client does', function (): void {
        $drive = static function ($client, string $url): string {
            $response = $client->request('GET', $url);

            try {
                foreach ($client->stream($response, 0.3) as $chunk) {
                    if ($chunk->isTimeout()) {
                        return 'timeout-chunk';
                    }
                }
            } catch (\Throwable $e) {
                return 'threw ' . $e::class;
            }

            return 'completed';
        };

        $plain = $drive(new \Symfony\Component\HttpClient\NativeHttpClient(), $this->slowUrl);
        $wrapped = $drive(
            new WiretapHttpClient(
                new \Symfony\Component\HttpClient\NativeHttpClient(),
                new Recorder(sink: new InMemorySink(), enabled: false),
            ),
            $this->slowUrl,
        );

        expect($wrapped)->toBe($plain)
            ->and($plain)->toBe('timeout-chunk');
    });

    it('records an exchange abandoned after an idle timeout', function (): void {
        $kernel = bootKernel(['enabled' => true, 'path' => $this->path, 'presets' => []]);

        $client = new WiretapHttpClient(
            new \Symfony\Component\HttpClient\NativeHttpClient(),
            recorder($kernel),
        );

        $response = $client->request('GET', $this->slowUrl);

        foreach ($client->stream($response, 0.3) as $chunk) {
            // isTimeout() both inspects and acknowledges. Symfony's ErrorChunk
            // destructor rethrows an error nobody acknowledged, in the plain
            // client too — so a consumer that only calls getError() is
            // misusing the API, not hitting a wiretap bug.
            if ($chunk->isTimeout()) {
                break;
            }
        }

        // An idle timeout does not end the transfer, so the record is not
        // finished until the application lets go of the response.
        unset($response);

        recorder($kernel)->flush();

        expect(exchangesIn($this->path))->toHaveCount(1);
    });
});

describe('an unread response that is dropped', function (): void {
    /**
     * Symfony raises for an unread 4xx/5xx from the response's own destructor,
     * but only while that response has not been initialised. Capture used to
     * call getHeaders(false) from its destructor, which initialises it without
     * throwing — so the inner destructor then skipped its status check and the
     * application's exception disappeared. The plain client threw; the wrapped
     * one silently succeeded.
     *
     * @param callable(): HttpClientInterface $make
     */
    function droppedResponseOutcome(callable $make): ?string
    {
        try {
            $response = $make()->request('GET', 'https://api.example.test/boom');
            unset($response);
            gc_collect_cycles();

            return null;
        } catch (\Throwable $e) {
            return $e::class;
        }
    }

    it('raises exactly what the undecorated client raises', function (): void {
        $plain = droppedResponseOutcome(
            static fn (): HttpClientInterface => new MockHttpClient(
                new MockResponse('{"error":1}', ['http_code' => 500]),
            ),
        );

        $wrapped = droppedResponseOutcome(static function (): HttpClientInterface {
            $inner = new MockHttpClient(new MockResponse('{"error":1}', ['http_code' => 500]));

            return new WiretapHttpClient(
                $inner,
                static fn (): Recorder => new Recorder(sink: new InMemorySink()),
            );
        });

        expect($plain)->toBe(ServerException::class)
            ->and($wrapped)->toBe($plain);
    });

    it('still records the exchange it dropped', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $client = new WiretapHttpClient(
            new MockHttpClient(new MockResponse('{"error":1}', ['http_code' => 500])),
            static fn (): Recorder => $recorder,
        );

        try {
            $response = $client->request('GET', 'https://api.example.test/boom');
            unset($response);
            gc_collect_cycles();
        } catch (\Throwable) {
            // The application's exception is the point of the test above.
        }

        $recorder->flush();

        // Not captured at the cost of the exception: both happen.
        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->uri)->toContain('/boom');
    });

    it('does not raise for a dropped 200, matching the plain client', function (): void {
        $outcome = droppedResponseOutcome(static function (): HttpClientInterface {
            $inner = new MockHttpClient(new MockResponse('{"ok":1}', ['http_code' => 200]));

            return new WiretapHttpClient(
                $inner,
                static fn (): Recorder => new Recorder(sink: new InMemorySink()),
            );
        });

        expect($outcome)->toBeNull();
    });
});
