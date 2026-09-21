<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\Internal\UrlResolver;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

afterEach(fn () => putenv('WIRETAP_BLOCK'));

describe('URL resolution', function (): void {
    it('resolves exactly as Symfony resolves', function (string $base, string $url, string $expected): void {
        // Verified against Symfony itself by driving the same pairs through
        // MockHttpClient and reading getInfo('url'). Concatenating base and
        // path disagreed on rooted and dot-segment paths, and the gate was
        // then asked about a URL the request never went to.
        expect(UrlResolver::resolve($url, ['base_uri' => $base]))->toBe($expected);
    })->with([
        'rooted path replaces the base path' => [
            'https://example.test/public/', '/private', 'https://example.test/private',
        ],
        'relative path extends it' => [
            'https://example.test/public/', 'private', 'https://example.test/public/private',
        ],
        'dot segments are resolved' => [
            'https://example.test/public/', '../other', 'https://example.test/other',
        ],
        'an absolute URL wins outright' => [
            'https://example.test/public/', 'https://other.test/x', 'https://other.test/x',
        ],
    ]);

    it('passes a URL through when there is no base', function (): void {
        expect(UrlResolver::resolve('https://plain.test/a', []))->toBe('https://plain.test/a');
    });

    it('hands back what it was given rather than throwing', function (): void {
        // An unparseable URL is Symfony's to report, not ours to crash on.
        expect(UrlResolver::resolve('http://:::::', []))->toBeString();
    });
});

/**
 * A payload that counts how many times it was serialised.
 *
 * Capture reading a body it was told not to touch is invisible from the
 * outside — the recorder's final check discards the exchange either way, so
 * counting records proves nothing. Counting serialisations does: Symfony
 * reads it once to send the request, and a second read means instrumentation
 * read it too.
 */
function serialisationProbe(): object
{
    return new class implements JsonSerializable {
        public int $reads = 0;

        public function jsonSerialize(): array
        {
            ++$this->reads;

            return ['value' => 'payload'];
        }
    };
}

describe('the pre-capture gate', function (): void {
    it('does not read the body of a request it is configured to block', function (): void {
        // The gate saw base + '/private' concatenated, which is not where the
        // request goes, so it admitted a blocked request and read its body.
        // Nothing was stored — the recorder's final check caught it — but the
        // payload had already been pulled into memory, which is the whole
        // thing a pre-capture gate exists to prevent.
        putenv('WIRETAP_BLOCK=https://example.test/private*');

        $probe = serialisationProbe();
        $recorder = new Recorder(
            sink: $sink = new InMemorySink(),
            blocklist: new Blocklist([new EnvBlocklistProvider()]),
        );

        $client = (new WiretapHttpClient(
            new MockHttpClient(static fn (): MockResponse => new MockResponse('{}')),
            static fn (): Recorder => $recorder,
        ))->withOptions(['base_uri' => 'https://example.test/public/']);

        $client->request('POST', '/private', ['json' => ['nested' => $probe]])->getContent();
        $recorder->flush();

        // One read, by Symfony, to actually send the request. Two means
        // capture serialised it as well — which is the blocked payload being
        // pulled into memory by instrumentation.
        expect($probe->reads)->toBe(1)
            ->and($sink->all())->toBeEmpty();
    });

    it('still captures a path that is not blocked', function (): void {
        putenv('WIRETAP_BLOCK=https://example.test/private*');

        $recorder = new Recorder(
            sink: $sink = new InMemorySink(),
            blocklist: new Blocklist([new EnvBlocklistProvider()]),
        );

        $client = (new WiretapHttpClient(
            new MockHttpClient(static fn (): MockResponse => new MockResponse('{}')),
            static fn (): Recorder => $recorder,
        ))->withOptions(['base_uri' => 'https://example.test/public/']);

        $client->request('GET', 'allowed')->getContent();
        $recorder->flush();

        expect($sink->all())->toHaveCount(1)
            ->and($sink->all()[0]->uri)->toContain('/public/allowed');
    });
});

describe('options set through withOptions', function (): void {
    it('learns a bearer token set as a default, so an echo of it is redacted', function (): void {
        // The defaults went to the inner client and capture never saw them,
        // so the token was never learned as a secret and a response echoing
        // it back was stored in plaintext.
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $client = (new WiretapHttpClient(
            new MockHttpClient(static fn (): MockResponse => new MockResponse(
                '{"echo":"ordinarysecretvalue"}',
                ['response_headers' => ['content-type' => 'application/json']],
            )),
            static fn (): Recorder => $recorder,
        ))->withOptions(['auth_bearer' => 'ordinarysecretvalue']);

        $client->request('GET', 'https://api.example.test/x')->getContent();
        $recorder->flush();

        expect($sink->all()[0]->responseBody->bytes)->not->toContain('ordinarysecretvalue');
    });

    it('treats a default buffer=>false as unbuffered', function (): void {
        // Read as buffered, capture consumed a body that can only be read
        // once and the application's getContent() then failed.
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $client = (new WiretapHttpClient(
            new MockHttpClient(static fn (): MockResponse => new MockResponse('streamed-body')),
            static fn (): Recorder => $recorder,
        ))->withOptions(['buffer' => false]);

        $client->request('GET', 'https://api.example.test/y')->getContent(false);
        $recorder->flush();

        expect($sink->all()[0]->responseBody->isPresent())->toBeFalse();
    });

    it('lets a per-request option override the default', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $client = (new WiretapHttpClient(
            new MockHttpClient(static fn (): MockResponse => new MockResponse('body')),
            static fn (): Recorder => $recorder,
        ))->withOptions(['buffer' => false]);

        $client->request('GET', 'https://api.example.test/z', ['buffer' => true])->getContent(false);
        $recorder->flush();

        expect($sink->all()[0]->responseBody->isPresent())->toBeTrue();
    });

    it('accumulates defaults across chained withOptions calls', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $client = (new WiretapHttpClient(
            new MockHttpClient(static fn (): MockResponse => new MockResponse(
                '{"echo":"ordinarysecretvalue"}',
                ['response_headers' => ['content-type' => 'application/json']],
            )),
            static fn (): Recorder => $recorder,
        ))
            ->withOptions(['auth_bearer' => 'ordinarysecretvalue'])
            ->withOptions(['base_uri' => 'https://api.example.test/v1/']);

        $client->request('GET', 'thing')->getContent();
        $recorder->flush();

        expect($sink->all()[0]->responseBody->bytes)->not->toContain('ordinarysecretvalue')
            ->and($sink->all()[0]->uri)->toContain('/v1/thing');
    });
});
