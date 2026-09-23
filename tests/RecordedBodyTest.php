<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpClient\RetryableHttpClient;

/**
 * @return array{WiretapHttpClient, InMemorySink, Recorder}
 */
function bodyRecordingClient(MockHttpClient $inner, int $maxBodyBytes = 1_048_576): array
{
    $sink = new InMemorySink();
    $recorder = new Recorder(sink: $sink, sampler: new Sampler());

    return [new WiretapHttpClient($inner, static fn (): Recorder => $recorder, $maxBodyBytes), $sink, $recorder];
}

function chunkedJson(): MockHttpClient
{
    return new MockHttpClient(static fn (): MockResponse => new MockResponse(['{"order":', '42,"ok":', 'true}'], [
        'response_headers' => ['content-type: application/json'],
    ]));
}

describe('a json request body', function (): void {
    it('is recorded as the bytes Symfony sent', function (): void {
        // Encoded with different flags, 10.0 was stored as 10 and quotes,
        // ampersands, angle brackets, slashes and non-ASCII characters were
        // stored unescaped: not the request that was made.
        $sent = null;
        [$client, $sink, $recorder] = bodyRecordingClient(new MockHttpClient(
            static function (string $method, string $url, array $options) use (&$sent): MockResponse {
                $sent = $options['body'];

                return new MockResponse('ok');
            },
        ));

        $client->request('POST', 'https://api.example.test/pay', ['json' => [
            'amount' => 10.0,
            'callback' => 'https://shop.test/cb',
            'note' => "O'Neil & <Co> \"quoted\"",
            'city' => 'Zürich',
        ]])->getContent();
        $recorder->flush();

        expect($sent)->toBeString()
            ->and($sink->all()[0]->requestBody->bytes)->toBe($sent)
            ->and($sink->all()[0]->requestBody->size)->toBe(strlen((string) $sent));
    });
});

describe('a response read through stream()', function (): void {
    it('keeps the body when the application streams it and then calls toArray()', function (): void {
        // Symfony's documented pattern. The stream committed the record with
        // the body omitted as streaming, and the once-only guard then skipped
        // the toArray() that would have captured it.
        [$client, $sink, $recorder] = bodyRecordingClient(chunkedJson());

        $response = $client->request('GET', 'https://api.example.test/orders/42');

        foreach ($client->stream($response) as $chunk) {
            // Driving the transfer, as the pattern does.
        }

        expect($response->toArray())->toBe(['order' => 42, 'ok' => true]);

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->responseBody->bytes)->toBe('{"order":42,"ok":true}')
            ->and($sink->all()[0]->responseBody->contentType)->toBe('application/json');
    });

    it('keeps the body under retry_failed, where every attempt is unbuffered', function (): void {
        // AsyncResponse makes each attempt with buffer => false and reads it
        // through stream(), so every record said "streaming".
        [$client, $sink, $recorder] = bodyRecordingClient(chunkedJson());
        $retrying = new RetryableHttpClient($client);

        expect($retrying->request('GET', 'https://api.example.test/orders/42')->toArray())
            ->toBe(['order' => 42, 'ok' => true]);

        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->responseBody->bytes)->toBe('{"order":42,"ok":true}');
    });

    it('keeps an unbuffered body the application streamed, without reading it again', function (): void {
        [$client, $sink, $recorder] = bodyRecordingClient(chunkedJson());

        $response = $client->request('GET', 'https://api.example.test/orders/42', ['buffer' => false]);
        $received = '';

        foreach ($client->stream($response) as $chunk) {
            $received .= $chunk->getContent();
        }

        $recorder->flush();

        expect($received)->toBe('{"order":42,"ok":true}')
            ->and($sink->all()[0]->responseBody->bytes)->toBe($received);
    });

    it('omits a streamed body over the ceiling, and still says how large it was', function (): void {
        [$client, $sink, $recorder] = bodyRecordingClient(chunkedJson(), maxBodyBytes: 10);

        $response = $client->request('GET', 'https://api.example.test/orders/42', ['buffer' => false]);

        foreach ($client->stream($response) as $chunk) {
            $chunk->getContent();
        }

        $recorder->flush();

        expect($sink->all()[0]->responseBody->bytes)->toBeNull()
            ->and($sink->all()[0]->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_NOT_READABLE)
            ->and($sink->all()[0]->responseBody->size)->toBe(strlen('{"order":42,"ok":true}'));
    });
});
