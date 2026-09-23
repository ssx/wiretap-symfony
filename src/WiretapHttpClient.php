<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Symfony\Internal\UrlResolver;
use Ssx\Wiretap\Support\Ulid;
use Ssx\Wiretap\Timings;
use Ssx\Wiretap\TransferClaim;
use Ssx\Wiretap\TransferError;
use Symfony\Component\HttpClient\Response\StreamableInterface;
use Symfony\Contracts\HttpClient\Exception\HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * Decorates Symfony's HttpClient.
 *
 * Symfony's client is not Guzzle and has no middleware concept, so the
 * decorator is the supported extension point — it is how TraceableHttpClient
 * and the profiler panel work too.
 *
 * The recorder is resolved per call rather than captured in the constructor:
 * the container builds this once, at compile time, long before a test might
 * call Wiretap::fake().
 */
final class WiretapHttpClient implements HttpClientInterface
{
    /** @var \Closure(): Recorder */
    private readonly \Closure $resolveRecorder;

    private readonly bool $hashFullBody;

    /**
     * @param Recorder|callable(): Recorder $recorder
     */
    public function __construct(
        private readonly HttpClientInterface $inner,
        Recorder|callable $recorder,
        /**
         * A hard memory ceiling, not the redaction limit. Capturing only 64
         * KiB handed the redactor truncated JSON it could not parse, so
         * configured body-path rules silently did nothing.
         */
        private readonly int $maxBodyBytes = 1_048_576,
        /**
         * Defaults accumulated through withOptions().
         *
         * These used to be handed to the inner client and forgotten, so
         * capture never saw them. Two things went wrong as a result:
         * withOptions(['auth_bearer' => '...']) meant the token was never
         * learned as a secret, and a response echoing it was recorded in
         * plaintext; and withOptions(['buffer' => false]) was read as buffered,
         * so capture consumed a body that could only be read once and the
         * application's getContent() then failed.
         *
         * @var array<string, mixed>
         */
        private readonly array $defaultOptions = [],
        /**
         * Whether to supply the SHA-256 of each body that passes through
         * whole, for core to key into the digest of a body it does not store
         * in full. A callable is asked once, here.
         *
         * Only ever over bytes already in hand: a request body the options
         * carry as a string, a response body the application was handed
         * through stream() or getContent(). Nothing is read to compute it,
         * and a body that did not pass through whole, or is past the capture
         * ceiling, gets none.
         *
         * @var bool|callable(): bool
         */
        bool|callable $hashFullBody = false,
    ) {
        $this->resolveRecorder = $recorder instanceof Recorder
            ? static fn (): Recorder => $recorder
            : \Closure::fromCallable($recorder);

        if (is_bool($hashFullBody)) {
            $this->hashFullBody = $hashFullBody;
        } else {
            try {
                $this->hashFullBody = (bool) $hashFullBody();
            } catch (\Throwable) {
                // Instrumentation must never change application behaviour.
                $this->hashFullBody = false;
            }
        }
    }

    /**
     * Per-request options over the accumulated defaults.
     *
     * Symfony's own rule: a per-request option replaces the default of the
     * same name, except headers, which merge by name with the request winning.
     *
     * @param  array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function effectiveOptions(array $options): array
    {
        if ($this->defaultOptions === []) {
            return $options;
        }

        $effective = array_merge($this->defaultOptions, $options);

        $defaultHeaders = $this->defaultOptions['headers'] ?? null;
        $requestHeaders = $options['headers'] ?? null;

        if (is_array($defaultHeaders) && is_array($requestHeaders)) {
            $effective['headers'] = array_merge($defaultHeaders, $requestHeaders);
        }

        return $effective;
    }

    /**
     * @param array<string, mixed> $options
     */
    /**
     * @param array<string, mixed> $options
     */
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        $recorder = ($this->resolveRecorder)();

        // Everything below decides what to capture, so it has to see the
        // options the request will actually run with, defaults included.
        $effective = $this->effectiveOptions($options);

        // Resolve against base_uri before gating, the way Symfony resolves it.
        // Passing the raw argument showed the gate only `/private` for a
        // base_uri pointing at a blocked host, so the blocked body was read and
        // only then rejected. Nothing was stored, but the payload existed —
        // which is what the gate exists to prevent.
        if (!$recorder->shouldCapture(UrlResolver::resolve($url, $effective))) {
            return $this->inner->request($method, $url, $options);
        }

        $startedAt = microtime(true);
        $id = Ulid::generate($startedAt);
        $sequence = Correlation::nextSequence();
        $correlationId = Correlation::id();

        $requestHeaders = $this->rememberGeneratedCredentials($effective, $this->requestHeaders($effective));
        $requestBody = $this->requestBody($effective);

        $response = $this->inner->request($method, $url, self::claim($options));

        // Only claim StreamableInterface when the inner response has it.
        // Symfony checks for it to offer toStream() and to accept a response
        // as a multipart file part; losing it made toStream() a fatal error
        // and uploaded an empty part, and claiming it for a response that
        // lacks it would change behaviour the other way. The instanceof is
        // safe without symfony/http-client installed: an unknown interface
        // is simply not matched.
        $wrapperClass = $response instanceof StreamableInterface
            ? StreamableWiretapResponse::class
            : WiretapResponse::class;

        return new $wrapperClass(
            $response,
            function (
                ResponseInterface $resolved,
                ?\Throwable $error,
                bool $mayReadBody,
                bool $mayInitialise,
                ?array $observed = null,
            ) use (
                $recorder, $id, $correlationId, $sequence, $method, $url,
                $requestHeaders, $requestBody, $startedAt
            ): void {
                $recorder->record($this->buildExchange(
                    $resolved, $error, $mayReadBody, $mayInitialise, $id, $correlationId, $sequence,
                    $method, $url, $requestHeaders, $requestBody, $startedAt, $observed,
                ));
            },
            // `buffer => false` means the body can only be read once, so
            // capture must not be the one to read it. Read from the effective
            // options: set through withOptions() it was invisible here, and
            // capture consumed the application's only read.
            buffered: self::isBuffered($effective['buffer'] ?? true),
            maxObservedBytes: $this->maxBodyBytes,
            hashObserved: $this->hashFullBody,
        );
    }

    /**
     * Tell ssx/wiretap-auto's curl hooks that this request is recorded here.
     *
     * Without it, running both recorded every call twice, with no link
     * between the records: once here, with bodies, and once by the hooks
     * underneath CurlHttpClient. The claim goes in `extra`, which Symfony
     * merges with the client's defaults key by key, and which every
     * transport ignores unless it knows the key. It is deliberately not an
     * `extra.curl` option: a per-request `extra.curl` replaces the client's
     * default one outright, so adding one would drop curl options the
     * application configured. The retry layer re-issues these options, so
     * every attempt is claimed.
     *
     * Only when the hooks have said they read it. Otherwise the options are
     * exactly what they were, and nothing is added for a request this
     * decorator is not recording, so the hooks still see those.
     *
     * @param  array<string, mixed> $options
     * @return array<string, mixed>
     */
    private static function claim(array $options): array
    {
        if (!TransferClaim::isHonoured()) {
            return $options;
        }

        $extra = $options['extra'] ?? [];

        if (is_array($extra) && !array_key_exists(TransferClaim::KEY, $extra)) {
            $extra[TransferClaim::KEY] = true;
            $options['extra'] = $extra;
        }

        return $options;
    }

    /**
     * Whether the body can be read again after capture has read it.
     *
     * Only `true` and a stream resource guarantee that. A closure decides per
     * response, from the headers, and nothing reports what it decided —
     * reading it as "not false" let capture consume the only read of a body
     * the closure had chosen not to buffer, and the application's own
     * getContent(false) after a caught exception then threw. Not knowing
     * means not reading.
     */
    private static function isBuffered(mixed $buffer): bool
    {
        return $buffer === true || is_resource($buffer);
    }

    public function stream(iterable|ResponseInterface $responses, ?float $timeout = null): ResponseStreamInterface
    {
        // Unwrap: the inner client cannot stream a response it did not create.
        if ($responses instanceof ResponseInterface) {
            $responses = [$responses];
        }

        $unwrapped = [];
        $wrappers = new \SplObjectStorage();

        foreach ($responses as $response) {
            if ($response instanceof WiretapResponse) {
                $inner = $response->inner();
                $wrappers[$inner] = $response;
                $unwrapped[] = $inner;

                continue;
            }

            $unwrapped[] = $response;
        }

        // Keys are mapped back to the wrappers the caller was given. Yielding
        // the inner responses broke `$key === $response` comparisons and any
        // response-keyed map, which is the normal way to drive a multiplexed
        // stream. Completion also has to commit, or a fully consumed stream
        // recorded nothing at all.
        return new WiretapResponseStream(
            $this->inner->stream($unwrapped, $timeout),
            $wrappers,
        );
    }

    /**
     * @param array<string, mixed> $options
     */
    public function withOptions(array $options): static
    {
        return new self(
            $this->inner->withOptions($options),
            $this->resolveRecorder,
            $this->maxBodyBytes,
            // Accumulated, because withOptions() can be chained and Symfony
            // applies every layer.
            $this->effectiveOptions($options),
            $this->hashFullBody,
        );
    }

    /**
     * @param ?array{0: ?string, 1: int, 2: ?string} $observed
     */
    private function buildExchange(
        ResponseInterface $response,
        ?\Throwable $error,
        bool $mayReadBody,
        bool $mayInitialise,
        string $id,
        string $correlationId,
        int $sequence,
        string $method,
        string $url,
        Headers $requestHeaders,
        CapturedBody $requestBody,
        float $startedAt,
        ?array $observed = null,
    ): Exchange {
        /** @var array<string, mixed> $info */
        $info = $response->getInfo();

        $effectiveUrl = is_string($info['url'] ?? null) && $info['url'] !== '' ? $info['url'] : $url;
        $status = is_int($info['http_code'] ?? null) && $info['http_code'] > 0 ? $info['http_code'] : null;

        return new Exchange(
            id: $id,
            correlationId: $correlationId,
            transport: Exchange::TRANSPORT_PSR18,
            method: $method,
            uri: $effectiveUrl,
            requestHeaders: $requestHeaders,
            requestBody: $requestBody,
            status: $status,
            reason: null,
            responseHeaders: $this->responseHeaders($response, $mayInitialise),
            responseBody: $this->responseBody($response, $status, $mayReadBody, $observed),
            timings: $this->timings($info, $startedAt),
            // Not `$status === null && ...`: curl can deliver 200 headers and
            // then fail mid-body. Discarding the error because a status
            // existed recorded a failed transfer as a success, and
            // always-keep-failures sampling then dropped it.
            error: self::transferError($error, $status),
            startedAt: $startedAt,
            sequence: $sequence,
            pid: getmypid() ?: null,
        );
    }

    /**
     * The error to record, without anything taken from the response body.
     *
     * Symfony builds an HTTP exception's message from the body: a
     * problem+json `detail` or `title` goes into it verbatim. The body itself
     * is omitted or redacted by body_paths, but error.message is not a body,
     * so the value those rules exist to remove was stored in full a few
     * fields away. The status already says what happened; the class says how
     * the application saw it. A transport failure has no response body to
     * leak, so its message is kept.
     */
    private static function transferError(?\Throwable $error, ?int $status): ?TransferError
    {
        if ($error === null) {
            return null;
        }

        if ($error instanceof HttpExceptionInterface) {
            return new TransferError(
                errno: 0,
                message: $status !== null ? sprintf('HTTP %d response', $status) : 'HTTP error response',
                class: $error::class,
            );
        }

        return TransferError::fromThrowable($error);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function requestHeaders(array $options): Headers
    {
        $headers = $options['headers'] ?? [];

        if (!is_array($headers)) {
            return Headers::empty();
        }

        $pairs = [];

        foreach ($headers as $name => $value) {
            // Symfony accepts both ['Name' => 'value'] and ['Name: value'].
            if (is_int($name) && is_string($value) && str_contains($value, ':')) {
                [$headerName, $headerValue] = explode(':', $value, 2);
                $pairs[] = [trim($headerName), trim($headerValue)];

                continue;
            }

            foreach ((array) $value as $single) {
                if (is_scalar($single)) {
                    $pairs[] = [(string) $name, (string) $single];
                }
            }
        }

        return Headers::fromPairs($pairs);
    }

    /**
     * Whether a decoded payload holds an object at any depth, or is nested
     * too deeply to tell.
     *
     * Deliberately inspects nothing about the objects it finds. Anything that
     * reads from one — jsonSerialize(), __toString(), even a property — is
     * user code running a second time, which is the defect this guards
     * against rather than a way to detect it.
     */
    private function containsObject(mixed $value, int $depth = 0): bool
    {
        if (is_object($value)) {
            return true;
        }

        if (!is_array($value)) {
            return false;
        }

        // The recursion has to end somewhere, and where it ends nothing has
        // been proven. Answering "no objects" here sent a payload with an
        // object below the limit to json_encode, and Symfony then serialised
        // it again — jsonSerialize() side effects ran twice. Unknown is
        // treated as unsafe: the body is omitted, the request is untouched.
        if ($depth > 64) {
            return true;
        }

        foreach ($value as $item) {
            if ($this->containsObject($item, $depth + 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function requestBody(array $options): CapturedBody
    {
        $declaredType = $this->declaredContentType($options);

        if (isset($options['json'])) {
            $json = $options['json'];

            // Symfony serialises this itself. Serialising it here as well
            // invokes user code twice: a JsonSerializable that increments a
            // counter captured {"counter":1} and transmitted {"counter":2}, so
            // the record disagreed with the request, and any side effect in
            // jsonSerialize() happened twice. A serializer that throws could
            // stop the request outright.
            //
            // Checking only the top level was not enough — ['nested' => $obj]
            // is an array, so it went straight to json_encode and invoked the
            // object anyway. The search is for objects anywhere in the
            // payload, and it must not touch them: no jsonSerialize(), no
            // __toString(), no property reads.
            if ($this->containsObject($json)) {
                return CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE, null, 'application/json');
            }

            // Symfony's own flags (HttpClientTrait::jsonEncode), so the record
            // holds the bytes that went on the wire. Encoding with our own
            // turned 10.0 into 10, and `'`, `&`, `<`, `>`, `"`, `/` and
            // non-ASCII characters were stored unescaped while the request
            // carried ', &, \/ and ü: a record that could not
            // be replayed byte for byte, and whose sha256 matched nothing sent.
            $encoded = json_encode(
                $json,
                JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT | JSON_PRESERVE_ZERO_FRACTION,
            );

            return $encoded === false
                ? CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE)
                : $this->cap($encoded, 'application/json');
        }

        $body = $options['body'] ?? null;

        if ($body === null || $body === '') {
            return CapturedBody::none();
        }

        if (is_string($body)) {
            // Passing null here lost the declared content type, so the
            // redactor could not choose form parsing and body_paths did
            // nothing on a urlencoded body. It also defeated the binary gate.
            return $this->cap($body, $declaredType);
        }

        if (is_array($body)) {
            return $this->cap(http_build_query($body), $declaredType ?? 'application/x-www-form-urlencoded');
        }

        // A closure, a resource or an iterable. What was configured is not
        // what will be transmitted, and reading it here would consume it.
        return CapturedBody::omitted(CapturedBody::OMITTED_STREAMING);
    }


    /**
     * @param array<string, mixed> $options
     */
    private function declaredContentType(array $options): ?string
    {
        $headers = $options['headers'] ?? [];

        if (!is_array($headers)) {
            return null;
        }

        foreach ($headers as $name => $value) {
            if (is_int($name) && is_string($value) && stripos($value, 'content-type:') === 0) {
                return trim(substr($value, 13));
            }

            if (is_string($name) && strcasecmp($name, 'content-type') === 0) {
                $first = is_array($value) ? ($value[0] ?? null) : $value;

                if (is_scalar($first)) {
                    return (string) $first;
                }
            }
        }

        return null;
    }

    /**
     * Credentials Symfony generates from auth_bearer / auth_basic never appear
     * in the caller's headers, so the redactor never learned them and a
     * response echoing one recorded it verbatim.
     *
     * @param array<string, mixed> $options
     */
    private function rememberGeneratedCredentials(array $options, Headers $headers): Headers
    {
        $pairs = $headers->pairs();

        if (isset($options['auth_bearer']) && is_scalar($options['auth_bearer'])) {
            $pairs[] = ['Authorization', 'Bearer ' . $options['auth_bearer']];
        }

        if (isset($options['auth_basic'])) {
            $basic = $options['auth_basic'];
            $credential = is_array($basic) ? implode(':', array_map('strval', $basic)) : (string) $basic;
            $pairs[] = ['Authorization', 'Basic ' . base64_encode($credential)];
        }

        return Headers::fromPairs($pairs);
    }

    private function responseHeaders(ResponseInterface $response, bool $mayInitialise = true): Headers
    {
        // getHeaders() resolves the response. From the destructor that is not
        // ours to do: Symfony raises for an unread 4xx/5xx from the inner
        // response's own destructor, and only while that response has not been
        // initialised. Resolving it here made the inner destructor skip its
        // status check, so a dropped 500 threw on a plain client and nothing
        // at all on a wrapped one.
        //
        // getInfo() reads what is already known without resolving anything, so
        // it is what the destructor path uses. A response the application
        // never touched has no headers yet and records none, which is the
        // honest answer — it is also why this is not the default: a response
        // that was read has real headers worth recording.
        if (!$mayInitialise) {
            $raw = $response->getInfo('response_headers');

            if (!is_array($raw) || $raw === []) {
                return Headers::empty();
            }

            $lines = array_filter($raw, 'is_string');

            return Headers::fromRaw(implode("\r\n", $lines));
        }

        try {
            $pairs = [];

            foreach ($response->getHeaders(false) as $name => $values) {
                foreach ($values as $value) {
                    $pairs[] = [(string) $name, (string) $value];
                }
            }

            return Headers::fromPairs($pairs);
        } catch (\Throwable) {
            return Headers::empty();
        }
    }

    /**
     * @param ?array{0: ?string, 1: int, 2: ?string} $observed The body as it
     *     passed through stream(), null past the ceiling, its size, and its
     *     SHA-256 when that was taken
     */
    private function responseBody(
        ResponseInterface $response,
        ?int $status,
        bool $mayReadBody,
        ?array $observed = null,
    ): CapturedBody {
        if ($status === null) {
            return CapturedBody::none();
        }

        if ($observed !== null) {
            [$content, $size, $digest] = $observed;

            if ($size === 0) {
                return CapturedBody::none();
            }

            $contentType = self::contentType($response);

            return $content === null
                ? CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE, $size, $contentType)
                : $this->cap($content, $contentType, $digest, hashHere: false);
        }

        // Reading here when the caller asked for a stream, or only looked at
        // the status, has two effects the application feels: `buffer => false`
        // makes the body unreadable a second time, so their getContent()
        // throws; and a large or endless download is pulled into memory by
        // what was meant to be a headers-only operation.
        if (!$mayReadBody) {
            return CapturedBody::omitted(CapturedBody::OMITTED_STREAMING);
        }

        try {
            // false: a 4xx or 5xx body is exactly what someone is debugging,
            // so it must not throw its way out of the capture path.
            $content = $response->getContent(false);
        } catch (\Throwable) {
            return CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE);
        }

        if ($content === '') {
            return CapturedBody::none();
        }

        return $this->cap($content, self::contentType($response));
    }

    private static function contentType(ResponseInterface $response): ?string
    {
        try {
            $contentType = $response->getHeaders(false)['content-type'][0] ?? null;
        } catch (\Throwable) {
            // Headers unavailable; the body is still worth keeping.
            return null;
        }

        return is_string($contentType) ? $contentType : null;
    }

    /**
     * @param array<string, mixed> $info
     */
    private function timings(array $info, float $startedAt): Timings
    {
        // Symfony reports the same keys curl does, in seconds.
        if (isset($info['total_time'])) {
            return Timings::fromCurlInfo($info);
        }

        return Timings::fromElapsedSeconds(microtime(true) - $startedAt);
    }

    /**
     * @param ?string $digest   The body's SHA-256, taken as it passed through
     * @param bool    $hashHere Whether to take it now when none was supplied
     */
    private function cap(string $body, ?string $contentType, ?string $digest = null, bool $hashHere = true): CapturedBody
    {
        $size = strlen($body);

        // Over the ceiling the body is omitted, not truncated.
        //
        // Truncating produced a JSON prefix the redactor cannot decode, so
        // configured body_paths silently did nothing and a field the operator
        // had named was persisted in full inside the prefix. Raising the
        // ceiling only moves that: whatever the number, a body one byte over
        // it was redacted by nothing. Structured redaction needs the whole
        // document or none of it, which is the same conclusion core reaches
        // when it cannot inspect a body.
        //
        // The size and content type are still recorded, so the exchange shows
        // what was sent and why it is not here.
        if ($size > $this->maxBodyBytes) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_NOT_READABLE,
                $size,
                $contentType,
            );
        }

        // The body is whole and in hand, so its digest reads nothing. Core
        // keeps it only as an HMAC under the salt when it stores less than
        // all of it, and drops it without one.
        if ($digest === null && $hashHere && $this->hashFullBody) {
            $digest = hash('sha256', $body);
        }

        return CapturedBody::captured($body, $size, $contentType, sha256: $this->hashFullBody ? $digest : null);
    }
}
