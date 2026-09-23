<?php

declare(strict_types=1);

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\NativeHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpClient\Response\StreamableInterface;
use Symfony\Component\HttpClient\Retry\GenericRetryStrategy;
use Symfony\Component\HttpClient\RetryableHttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * @return array{WiretapHttpClient, InMemorySink, Recorder}
 */
function wrapped(HttpClientInterface $inner, ?Sampler $sampler = null): array
{
    $sink = new InMemorySink();
    $recorder = new Recorder(sink: $sink, sampler: $sampler ?? new Sampler());

    return [new WiretapHttpClient($inner, static fn (): Recorder => $recorder), $sink, $recorder];
}

describe('a response that can be streamed as a resource', function (): void {
    it('keeps toStream() when the inner response has it', function (): void {
        // The wrapper dropped StreamableInterface, so toStream() was a fatal
        // "undefined method" — only for URLs that were captured, so the same
        // code worked or crashed depending on the blocklist.
        [$client] = wrapped(new MockHttpClient(new MockResponse('streamed-as-resource')));

        $response = $client->request('GET', 'https://api.example.test/file');

        expect($response)->toBeInstanceOf(StreamableInterface::class)
            ->and(stream_get_contents($response->toStream()))->toBe('streamed-as-resource');
    });

    it('uploads a wrapped response as a multipart file part', function (): void {
        // Symfony only turns a response into a file part if it is
        // StreamableInterface. Without it, `body => ['file' => $response]`
        // silently sent an empty part instead of the download.
        [$client] = wrapped(new MockHttpClient(new MockResponse('file-bytes-123')));
        $download = $client->request('GET', 'https://api.example.test/download');

        $sent = null;
        $upstream = new MockHttpClient(static function (string $method, string $url, array $options) use (&$sent): MockResponse {
            $sent = '';
            $body = $options['body'];

            while (is_callable($body) && '' !== ($piece = $body(8192))) {
                $sent .= $piece;
            }

            return new MockResponse('ok');
        });

        $upstream->request('POST', 'https://upload.example.test/', ['body' => ['file' => $download]])->getContent();

        expect($sent)->toContain('file-bytes-123');
    });

    it('does not claim to be streamable when the inner response is not', function (): void {
        $plain = new class implements ResponseInterface {
            public function getStatusCode(): int { return 200; }
            public function getHeaders(bool $throw = true): array { return []; }
            public function getContent(bool $throw = true): string { return 'x'; }
            public function toArray(bool $throw = true): array { return []; }
            public function cancel(): void {}
            public function getInfo(?string $type = null): mixed { return $type === null ? [] : null; }
        };

        $inner = new class($plain) implements HttpClientInterface {
            public function __construct(private ResponseInterface $response) {}
            public function request(string $method, string $url, array $options = []): ResponseInterface { return $this->response; }
            public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): \Symfony\Contracts\HttpClient\ResponseStreamInterface { throw new \LogicException(); }
            public function withOptions(array $options): static { return $this; }
        };

        [$client] = wrapped($inner);

        expect($client->request('GET', 'https://api.example.test/')->getContent())->toBe('x')
            ->and($client->request('GET', 'https://api.example.test/'))->not->toBeInstanceOf(StreamableInterface::class);
    });
});

describe('a buffer option that is a closure', function (): void {
    it('leaves an error body readable after the exception, as the plain client does', function (): void {
        // A closure decides buffering per response, so it cannot be assumed
        // to mean "buffered". Treating it that way let capture read the body
        // while the exception was handled, and the application's own
        // getContent(false) then threw "Cannot get the content twice".
        $drive = static function (HttpClientInterface $client): string {
            $response = $client->request('GET', 'https://api.example.test/', [
                'buffer' => static fn (array $headers): bool => false,
            ]);

            try {
                $response->getContent();
            } catch (\Throwable) {
                // The 500. The application then reads the body anyway.
            }

            try {
                return $response->getContent(false);
            } catch (\Throwable $e) {
                return 'threw: ' . $e->getMessage();
            }
        };

        $plain = $drive(new MockHttpClient(new MockResponse('error body', ['http_code' => 500])));
        [$client] = wrapped(new MockHttpClient(new MockResponse('error body', ['http_code' => 500])));

        expect($plain)->toBe('error body')
            ->and($drive($client))->toBe($plain);
    });
});

describe('a json payload nested past the inspection depth', function (): void {
    it('is not serialised a second time', function (): void {
        // The depth guard answered "no objects here" once it hit its limit,
        // so an object below it went to json_encode and Symfony serialised
        // it again: side effects in jsonSerialize() ran twice.
        $payload = new class implements JsonSerializable {
            public int $calls = 0;

            public function jsonSerialize(): mixed
            {
                return ++$this->calls;
            }
        };

        $json = $payload;

        for ($i = 0; $i < 67; ++$i) {
            $json = [$json];
        }

        [$client, $sink, $recorder] = wrapped(new MockHttpClient(new MockResponse('{}')));
        $client->request('POST', 'https://api.example.test/', ['json' => $json])->getContent();
        $recorder->flush();

        expect($payload->calls)->toBe(1)
            ->and($sink->all()[0]->requestBody->isPresent())->toBeFalse();
    });
});

describe('errors seen while streaming', function (): void {
    it('records a transport error in the stream as a failure', function (): void {
        // The error chunk was committed with no error, so the record said the
        // transfer succeeded, and a sampler keeping failures dropped it.
        [$client, $sink, $recorder] = wrapped(
            new MockHttpClient(new MockResponse(['partial', new TransportException('connection reset')])),
        );

        $response = $client->request('GET', 'https://api.example.test/');

        try {
            foreach ($client->stream($response) as $chunk) {
                $chunk->getContent();
            }
        } catch (TransportException) {
            // What the plain client throws too.
        }

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->error?->message)->toContain('connection reset')
            ->and($sink->all()[0]->failed())->toBeTrue();
    });

    it('keeps a failed attempt that RetryableHttpClient retried', function (): void {
        // retry_failed drives the stream and sees the error chunk. Recorded as
        // a success, the failed attempt was sampled away even with
        // always-keep-failures on — the case that option exists for.
        $attempt = 0;
        $mock = new MockHttpClient(static function () use (&$attempt): MockResponse {
            return ++$attempt === 1
                ? new MockResponse('', ['error' => 'Could not resolve host'])
                : new MockResponse('{"ok":true}');
        });

        [$client, $sink, $recorder] = wrapped($mock, new Sampler(rateBasisPoints: 0, alwaysKeepFailures: true));

        $content = (new RetryableHttpClient($client, new GenericRetryStrategy(delayMs: 1), 2))
            ->request('GET', 'https://api.example.test/pay')
            ->getContent();
        $recorder->flush();

        expect($content)->toBe('{"ok":true}')
            ->and($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->error?->message)->toContain('Could not resolve host');
    });
});

describe('an idle timeout in a stream', function (): void {
    beforeEach(function (): void {
        $this->server = startStallingServer(resumes: true);
        $this->url = 'http://127.0.0.1:' . $this->server[2] . '/resumes';
    });

    afterEach(function (): void {
        stopStallingServer($this->server);
    });

    it('does not finish the record, because the transfer can still complete', function (): void {
        // A timeout chunk means "nothing arrived yet", not "over". Committing
        // there wrote the record before the body existed, and the once-only
        // guard then skipped the read that would have captured it.
        [$client, $sink, $recorder] = wrapped(new NativeHttpClient());

        $response = $client->request('GET', $this->url);

        foreach ($client->stream($response, 0.3) as $chunk) {
            if ($chunk->isTimeout()) {
                break;
            }
        }

        expect($response->getContent())->toBe('partial-rest!!');

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->error)->toBeNull()
            ->and($sink->all()[0]->responseBody->bytes)->toBe('partial-rest!!');
    });

    it('behaves exactly as the undecorated client does', function (): void {
        $drive = static function (HttpClientInterface $client, string $url): string {
            $response = $client->request('GET', $url);
            $events = [];

            foreach ($client->stream($response, 0.3) as $chunk) {
                $events[] = $chunk->isTimeout() ? 'timeout' : 'data:' . $chunk->getContent();
            }

            return implode(',', $events) . '|' . $response->getContent();
        };

        [$client] = wrapped(HttpClient::create());

        expect($drive($client, $this->url))->toBe($drive(HttpClient::create(), $this->url));
    });
});
