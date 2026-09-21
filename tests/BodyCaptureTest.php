<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Counts how many times anything serialised it. Symfony reads it once to send
 * the request; a second read is capture invoking user code a second time.
 */
function countingPayload(): object
{
    return new class implements JsonSerializable {
        public int $reads = 0;

        public function jsonSerialize(): array
        {
            return ['counter' => ++$this->reads];
        }
    };
}

/**
 * @param array<string, mixed> $options
 */
function captureRequest(array $options, int $maxBodyBytes = 1_048_576, ?Redactor $redactor = null): CapturedBody
{
    $recorder = new Recorder(
        sink: $sink = new InMemorySink(),
        redactor: $redactor ?? new Redactor(),
    );

    $client = new WiretapHttpClient(
        new MockHttpClient(static fn (): MockResponse => new MockResponse('{}')),
        static fn (): Recorder => $recorder,
        maxBodyBytes: $maxBodyBytes,
    );

    $client->request('POST', 'https://api.example.test/x', $options)->getContent();
    $recorder->flush();

    return $sink->all()[0]->requestBody;
}

describe('json payloads containing objects', function (): void {
    it('does not serialise a nested object that Symfony will serialise', function (): void {
        // The guard checked only the top-level value, so ['nested' => $obj]
        // went straight to json_encode and invoked the object anyway. A
        // counter-based serializer was then recorded as {"counter":1} while
        // {"counter":2} was transmitted — the record disagreeing with the
        // request — and a serializer that throws could stop the request.
        $payload = countingPayload();

        $body = captureRequest(['json' => ['nested' => $payload]]);

        expect($payload->reads)->toBe(1)
            ->and($body->isPresent())->toBeFalse()
            ->and($body->omittedReason)->toBe(CapturedBody::OMITTED_NOT_READABLE);
    });

    it('finds an object however deeply it is buried', function (): void {
        $payload = countingPayload();

        $body = captureRequest(['json' => ['a' => ['b' => ['c' => [$payload]]]]]);

        expect($payload->reads)->toBe(1)
            ->and($body->isPresent())->toBeFalse();
    });

    it('still captures a payload of plain values', function (): void {
        $body = captureRequest(['json' => ['plain' => 'value', 'n' => 5, 'deep' => ['ok' => true]]]);

        expect($body->bytes)->toBe('{"plain":"value","n":5,"deep":{"ok":true}}');
    });
});

describe('bodies over the capture ceiling', function (): void {
    it('omits them rather than storing an unredactable prefix', function (): void {
        // Truncating produced a JSON prefix the redactor cannot decode, so
        // configured body_paths silently did nothing and the named field was
        // persisted in full inside that prefix.
        $payload = json_encode(['password' => 'ordinarysecretvalue', 'pad' => str_repeat('x', 200)]);

        $body = captureRequest(
            ['body' => $payload, 'headers' => ['Content-Type' => 'application/json']],
            maxBodyBytes: 100,
            redactor: new Redactor(new RedactionConfig(bodyPaths: ['password'])),
        );

        expect($body->isPresent())->toBeFalse()
            ->and($body->omittedReason)->toBe(CapturedBody::OMITTED_NOT_READABLE)
            // Still says what was sent, and how much of it.
            ->and($body->size)->toBe(strlen((string) $payload));
    });

    it('captures a body that fits, and redacts it structurally', function (): void {
        $payload = json_encode(['password' => 'ordinarysecretvalue', 'keep' => 'visible']);

        $body = captureRequest(
            ['body' => $payload, 'headers' => ['Content-Type' => 'application/json']],
            redactor: new Redactor(new RedactionConfig(bodyPaths: ['password'])),
        );

        expect($body->isPresent())->toBeTrue()
            ->and($body->bytes)->not->toContain('ordinarysecretvalue')
            ->and($body->bytes)->toContain('visible');
    });

    it('does not persist a digest of the unredacted body', function (): void {
        // An unkeyed SHA-256 of the body as sent, stored beside a redacted
        // copy of it, is an offline oracle for anything short.
        $body = captureRequest(['json' => ['pin' => '1234']]);

        expect($body->sha256)->toBeNull();
    });
});
