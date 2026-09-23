<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Ssx\Wiretap\TransferClaim;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The decorator claims the requests it records so that ssx/wiretap-auto's
 * curl hooks, if they are running, do not record them a second time.
 */
beforeEach(fn () => TransferClaim::reset());
afterEach(fn () => TransferClaim::reset());

/**
 * The options the transport resolved for one request, through the decorator
 * or, with no recorder, without it. The transport carries a default
 * extra.curl, as a framework `default_options` would.
 *
 * @param array<string, mixed> $options
 * @return array<string, mixed>
 */
function transportOptions(?Recorder $recorder, array $options = []): array
{
    $seen = [];
    $transport = (new MockHttpClient(static function (string $method, string $url, array $resolved) use (&$seen): MockResponse {
        $seen = $resolved;

        return new MockResponse('{}', ['response_headers' => ['Content-Type' => 'application/json']]);
    }))->withOptions(['extra' => ['curl' => [CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4]]]);

    $client = $recorder === null ? $transport : new WiretapHttpClient($transport, $recorder);
    $client->request('GET', 'https://api.example.com/v1', $options)->getContent();

    return $seen;
}

it('claims the request in extra once the hooks honour it, keeping the default extra.curl', function (): void {
    TransferClaim::honour();

    $extra = transportOptions(new Recorder(sink: new InMemorySink()))['extra'];

    expect($extra[TransferClaim::KEY] ?? null)->toBeTrue()
        // A per-request extra.curl would have replaced this outright.
        ->and($extra['curl'] ?? null)->toBe([CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4]);
});

it('keeps extra the application passed per request', function (): void {
    TransferClaim::honour();

    $extra = transportOptions(new Recorder(sink: new InMemorySink()), ['extra' => ['trace_content' => false]])['extra'];

    expect($extra)->toMatchArray(['trace_content' => false, TransferClaim::KEY => true]);
});

it('adds nothing at all when the hooks do not honour it', function (): void {
    $through = transportOptions(new Recorder(sink: new InMemorySink()));
    $direct = transportOptions(null);

    // Same keys in the same order, and equal values.
    expect(array_keys($through))->toBe(array_keys($direct))
        ->and($through)->toEqual($direct);
});

it('does not claim a request it is not recording, so the hooks still can', function (): void {
    TransferClaim::honour();

    $recorder = new Recorder(
        sink: new InMemorySink(),
        blocklist: new Blocklist([new ArrayBlocklistProvider(['api.example.com'])]),
    );

    expect(transportOptions($recorder)['extra'])->not->toHaveKey(TransferClaim::KEY);
});

it('leaves a claim value the application set alone', function (): void {
    TransferClaim::honour();

    $extra = transportOptions(new Recorder(sink: new InMemorySink()), ['extra' => [TransferClaim::KEY => false]])['extra'];

    expect($extra[TransferClaim::KEY])->toBeFalse();
});
