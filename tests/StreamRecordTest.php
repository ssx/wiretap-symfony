<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Psr18Client;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * @return array{WiretapHttpClient, InMemorySink, Recorder}
 */
function recordingClient(HttpClientInterface $inner): array
{
    $sink = new InMemorySink();
    $recorder = new Recorder(sink: $sink, sampler: new Sampler());

    return [new WiretapHttpClient($inner, static fn (): Recorder => $recorder), $sink, $recorder];
}

function jsonMock(string $body): MockHttpClient
{
    return new MockHttpClient(static fn (): MockResponse => new MockResponse($body, [
        'response_headers' => ['content-type: application/json'],
    ]));
}

describe('a response read through toStream()', function (): void {
    it('is recorded when the stream is read, not when the wrapper is dropped', function (): void {
        // The application keeps only the resource, so the wrapper was
        // destroyed at once and recorded a transfer that had not happened
        // yet: no status, no headers, no failure.
        [$client, $sink, $recorder] = recordingClient(jsonMock('{"hello":"body"}'));

        $stream = $client->request('GET', 'https://api.example.test/s')->toStream(false);

        expect(stream_get_contents($stream))->toBe('{"hello":"body"}');

        fclose($stream);
        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->status)->toBe(200)
            ->and($sink->all()[0]->error)->toBeNull()
            ->and($sink->all()[0]->responseBody->bytes)->toBe('{"hello":"body"}');
    });

    it('records a body that ends early as a failure', function (): void {
        [$client, $sink, $recorder] = recordingClient(new MockHttpClient(
            new MockResponse(['partial', new TransportException('End of response with 93 bytes missing')]),
        ));

        $stream = $client->request('GET', 'https://api.example.test/t')->toStream(false);
        set_error_handler(static fn (): bool => true);

        try {
            stream_get_contents($stream);
        } finally {
            restore_error_handler();
        }

        fclose($stream);
        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and((string) $sink->all()[0]->error?->message)->toContain('bytes missing')
            ->and($sink->all()[0]->failed())->toBeTrue();
    });

    it('reads, seeks and reports exactly as the unwrapped stream does', function (): void {
        $drive = static function (HttpClientInterface $client): array {
            $stream = $client->request('GET', 'https://api.example.test/s')->toStream(false);
            $first = stream_get_contents($stream);
            $eof = feof($stream);
            $rewound = rewind($stream);
            $second = stream_get_contents($stream);
            $meta = stream_get_meta_data($stream);

            return [$first, $eof, $rewound, $second, $meta['seekable'], $meta['mode']];
        };

        [$client] = recordingClient(jsonMock('{"hello":"body"}'));

        expect($drive($client))->toBe($drive(jsonMock('{"hello":"body"}')));
    });

    it('hands back the response the application holds from wrapper_data', function (): void {
        [$client] = recordingClient(jsonMock('{}'));
        $response = $client->request('GET', 'https://api.example.test/s');

        $wrapper = stream_get_meta_data($response->toStream(false))['wrapper_data'];

        expect($wrapper->getResponse())->toBe($response);
    });
});

describe('a PSR-18 client over the decorator', function (): void {
    it('records the body it streams to the application', function (): void {
        // Psr18Client reads a streamable response through toStream(). The
        // record was written before the body existed, so it lost the body,
        // and a body that ended early was recorded as a success.
        [$client, $sink, $recorder] = recordingClient(jsonMock('{"psr":18}'));
        $factory = new Psr17Factory();

        $response = (new Psr18Client($client, $factory, $factory))
            ->sendRequest($factory->createRequest('GET', 'https://api.example.test/p'));

        expect((string) $response->getBody())->toBe('{"psr":18}');

        unset($response);
        gc_collect_cycles();
        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->status)->toBe(200)
            ->and($sink->all()[0]->responseBody->bytes)->toBe('{"psr":18}');
    });
});

describe('an idle timeout the application gives up on', function (): void {
    it('is recorded as the failure the application saw', function (): void {
        // The timeout chunk's isLast() throws TimeoutException to the
        // application, which abandons the response. Nothing marked the
        // record, so it said the transfer had succeeded.
        [$client, $sink, $recorder] = recordingClient(new MockHttpClient(new MockResponse(['', 'late'])));

        $response = $client->request('GET', 'https://api.example.test/idle');

        try {
            foreach ($client->stream($response, 0.05) as $chunk) {
                $chunk->isLast();
            }
        } catch (\Symfony\Contracts\HttpClient\Exception\TimeoutExceptionInterface) {
            // The application gives up.
        }

        unset($response, $chunk);
        gc_collect_cycles();
        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and((string) $sink->all()[0]->error?->message)->toContain('Idle timeout')
            ->and($sink->all()[0]->failed())->toBeTrue();
    });

    it('is recorded when the response is cancelled after the timeout', function (): void {
        // RetryableHttpClient cancels an attempt that timed out before it
        // retries. cancel() committed with no error, so each timed-out
        // attempt read as a success.
        [$client, $sink, $recorder] = recordingClient(new MockHttpClient(new MockResponse(['', 'late'])));

        $response = $client->request('GET', 'https://api.example.test/idle');

        foreach ($client->stream($response, 0.05) as $chunk) {
            if ($chunk->isTimeout()) {
                $response->cancel();

                break;
            }
        }

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and((string) $sink->all()[0]->error?->message)->toContain('Idle timeout');
    });
});
