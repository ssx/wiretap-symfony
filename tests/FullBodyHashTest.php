<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Core keeps a digest of a body it did not store (truncated, or omitted as
 * binary) only as an HMAC under the redaction salt, and only when the capture
 * layer supplies the SHA-256 of the whole body. The decorator never computed
 * one, so the salt the bundle derives from kernel.secret had nothing to key:
 * every such body from Symfony's HttpClient carried no digest at all.
 */
function fbhText(): string
{
    // Past core's 64 KiB storage limit, inside the 1 MiB capture ceiling.
    return str_repeat('the quick brown fox jumps over the lazy dog ', 3000);
}

function fbhPng(): string
{
    return "\x89PNG\r\n\x1a\n" . str_repeat("\x00\x01\x02\x03", 4096);
}

function fbhBig(): string
{
    return str_repeat('b', 3 * 1_048_576);
}

/** kernel.secret is 'test' in TestKernel. */
function fbhKey(): string
{
    return hash_hmac('sha256', 'wiretap-redaction', 'test');
}

function fbhKeyed(string $body): string
{
    return hash_hmac('sha256', hash('sha256', $body), fbhKey());
}

/**
 * Serves each body in 16 KiB chunks, so the digest has to be built across
 * many chunks, and remembers what the transport was asked to send.
 */
final class FullBodyMockResponseFactory
{
    /** @var list<string> */
    public static array $sent = [];

    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        $body = $options['body'] ?? '';
        self::$sent[] = hash('sha256', is_string($body) ? $body : '(not a string)');

        [$content, $type] = match (parse_url($url, PHP_URL_PATH)) {
            '/png' => [fbhPng(), 'image/png'],
            '/big' => [fbhBig(), 'text/plain'],
            default => [fbhText(), 'text/plain'],
        };

        return new MockResponse(str_split($content, 16384), ['response_headers' => ['content-type: ' . $type]]);
    }
}

/**
 * @param array<string, mixed> $wiretap
 *
 * @return array{HttpClientInterface, Recorder, InMemorySink, TestKernel}
 */
function fbhKernel(array $wiretap = []): array
{
    $kernel = new TestKernel(
        array_replace_recursive(['enabled' => true, 'presets' => []], $wiretap),
        bin2hex(random_bytes(6)),
        ['http_client' => ['mock_response_factory' => 'test.full_body_mock']],
        static function (ContainerBuilder $container): void {
            $container->register('test.full_body_mock', FullBodyMockResponseFactory::class);
        },
    );
    $kernel->boot();

    /** @var Recorder $recorder */
    $recorder = $kernel->getContainer()->get('test.service_container')->get(Recorder::class);
    $recorder->setSink($sink = new InMemorySink());

    return [$kernel->getContainer()->get('test.consumer')->client, $recorder, $sink, $kernel];
}

/**
 * Each way an application reads a response, returning what it read.
 *
 * @return array<string, \Closure(HttpClientInterface, string, array<string, mixed>): string>
 */
function fbhReaders(): array
{
    return [
        'getContent' => static fn (HttpClientInterface $c, string $url, array $o): string => $c->request('POST', $url, $o)->getContent(),
        'stream' => static function (HttpClientInterface $c, string $url, array $o): string {
            $seen = '';
            $response = $c->request('POST', $url, $o);

            foreach ($c->stream($response) as $chunk) {
                $seen .= sprintf('%d:%s|', $chunk->getOffset(), hash('crc32b', $chunk->getContent()));
            }

            return $seen;
        },
        'toStream' => static function (HttpClientInterface $c, string $url, array $o): string {
            $stream = $c->request('POST', $url, $o)->toStream();
            $read = (string) stream_get_contents($stream);
            fclose($stream);

            return $read;
        },
    ];
}

/**
 * @param array<string, mixed> $wiretap
 * @param array<string, mixed> $options
 */
function fbhExchange(string $reader, string $path, array $wiretap = [], array $options = []): Exchange
{
    [$client, $recorder, $sink, $kernel] = fbhKernel($wiretap);

    fbhReaders()[$reader]($client, 'https://api.example.test' . $path, $options);
    $recorder->flush();
    $kernel->shutdown();

    return $sink->all()[0];
}

beforeEach(function (): void {
    FullBodyMockResponseFactory::$sent = [];
});

describe('a body core does not store in full', function (): void {
    it('keeps a keyed digest of a truncated response', function (string $reader): void {
        $body = fbhExchange($reader, '/text')->responseBody;

        expect($body->truncated)->toBeTrue()
            ->and($body->sha256)->toBe(fbhKeyed(fbhText()));
    })->with(['getContent', 'stream', 'toStream']);

    it('keeps a keyed digest of an omitted binary response', function (string $reader): void {
        $body = fbhExchange($reader, '/png')->responseBody;

        expect($body->omittedReason)->toBe(CapturedBody::OMITTED_BINARY)
            ->and($body->sha256)->toBe(fbhKeyed(fbhPng()));
    })->with(['getContent', 'stream']);

    it('keeps a keyed digest of a truncated request body', function (): void {
        $body = fbhExchange('getContent', '/text', options: [
            'body' => fbhText(),
            'headers' => ['Content-Type' => 'text/plain'],
        ])->requestBody;

        expect($body->truncated)->toBeTrue()
            ->and($body->sha256)->toBe(fbhKeyed(fbhText()));
    });

    it('never stores the raw SHA-256 of what it did not store', function (): void {
        expect(fbhExchange('stream', '/text')->responseBody->sha256)->not->toBe(hash('sha256', fbhText()));
    });
});

describe('a body that did not pass through whole', function (): void {
    it('keeps no digest', function (\Closure $read): void {
        [$client, $recorder, $sink, $kernel] = fbhKernel();

        $read($client);
        $recorder->flush();
        $kernel->shutdown();

        expect($sink->all()[0]->responseBody->sha256)->toBeNull();
    })->with([
        'streamed, then cancelled after the first chunk' => [static function (HttpClientInterface $c): void {
            $response = $c->request('GET', 'https://api.example.test/text');

            foreach ($c->stream($response) as $chunk) {
                if ($chunk->getContent() !== '') {
                    $response->cancel();

                    break;
                }
            }
        }],
        'past the capture ceiling' => [static function (HttpClientInterface $c): void {
            foreach ($c->stream($c->request('GET', 'https://api.example.test/big')) as $chunk) {
                $chunk->getContent();
            }
        }],
        'unbuffered, so capture may not read it' => [static function (HttpClientInterface $c): void {
            $c->request('GET', 'https://api.example.test/text', ['buffer' => false])->getContent();
        }],
        'only its status read' => [static function (HttpClientInterface $c): void {
            $c->request('GET', 'https://api.example.test/text')->getStatusCode();
        }],
    ]);
});

describe('redaction.hash_full_body', function (): void {
    it('keeps no digest when switched off', function (string $reader): void {
        $exchange = fbhExchange($reader, '/text', ['redaction' => ['hash_full_body' => false]], [
            'body' => fbhText(),
            'headers' => ['Content-Type' => 'text/plain'],
        ]);

        expect($exchange->responseBody->truncated)->toBeTrue()
            ->and($exchange->responseBody->sha256)->toBeNull()
            ->and($exchange->requestBody->sha256)->toBeNull();
    })->with(['getContent', 'stream']);

    it('follows WIRETAP_HASH_FULL_BODY when not configured', function (): void {
        $_SERVER['WIRETAP_HASH_FULL_BODY'] = 'false';

        try {
            $body = fbhExchange('stream', '/text')->responseBody;
        } finally {
            unset($_SERVER['WIRETAP_HASH_FULL_BODY']);
        }

        expect($body->sha256)->toBeNull();
    });

    it('is forced off without a salt, whatever it says', function (): void {
        $body = fbhExchange('stream', '/text', ['redaction' => ['hash_salt' => '', 'hash_full_body' => true]])->responseBody;

        expect($body->sha256)->toBeNull();
    });

    it('is forced off when redaction is off, so nothing unkeyed is written', function (): void {
        $body = fbhExchange('stream', '/png', ['redaction' => ['enabled' => false, 'hash_full_body' => true]])->responseBody;

        expect($body->sha256)->toBeNull();
    });
});

/**
 * Hashing only ever looks at bytes already in hand, so nothing the
 * application or the transport sees may differ with it on.
 */
describe('what the application sees', function (): void {
    it('is identical with and without hashing', function (string $reader, string $path): void {
        $run = static function (bool $hash) use ($reader, $path): array {
            FullBodyMockResponseFactory::$sent = [];
            [$client, $recorder, , $kernel] = fbhKernel(['redaction' => ['hash_full_body' => $hash]]);

            $read = fbhReaders()[$reader]($client, 'https://api.example.test' . $path, [
                'body' => fbhText(),
                'headers' => ['Content-Type' => 'text/plain'],
            ]);
            $recorder->flush();
            $kernel->shutdown();

            return ['read' => hash('sha256', $read), 'sent' => FullBodyMockResponseFactory::$sent];
        };

        expect($run(true))->toBe($run(false));
    })->with(['getContent', 'stream', 'toStream'])->with(['/text', '/png', '/big']);
});
