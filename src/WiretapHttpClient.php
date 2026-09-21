<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Support\Ulid;
use Ssx\Wiretap\Timings;
use Ssx\Wiretap\TransferError;
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
    ) {
        $this->resolveRecorder = $recorder instanceof Recorder
            ? static fn (): Recorder => $recorder
            : \Closure::fromCallable($recorder);
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

        // Resolve against base_uri before gating. Passing the raw argument
        // showed the gate only `/private` for a base_uri pointing at a blocked
        // host, so the blocked body was read and only then rejected. Nothing
        // was stored, but the payload existed — which is what the gate exists
        // to prevent.
        if (!$recorder->shouldCapture($this->resolveUrl($url, $options))) {
            return $this->inner->request($method, $url, $options);
        }

        $startedAt = microtime(true);
        $id = Ulid::generate($startedAt);
        $sequence = Correlation::nextSequence();
        $correlationId = Correlation::id();

        $requestHeaders = $this->rememberGeneratedCredentials($options, $this->requestHeaders($options));
        $requestBody = $this->requestBody($options);

        $response = $this->inner->request($method, $url, $options);

        return new WiretapResponse(
            $response,
            function (
                ResponseInterface $resolved,
                ?\Throwable $error,
                bool $mayReadBody,
                bool $mayInitialise
            ) use (
                $recorder, $id, $correlationId, $sequence, $method, $url,
                $requestHeaders, $requestBody, $startedAt
            ): void {
                $recorder->record($this->buildExchange(
                    $resolved, $error, $mayReadBody, $mayInitialise, $id, $correlationId, $sequence,
                    $method, $url, $requestHeaders, $requestBody, $startedAt,
                ));
            },
            // `buffer => false` means the body can only be read once, so
            // capture must not be the one to read it.
            buffered: ($options['buffer'] ?? true) !== false,
        );
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
        return new self($this->inner->withOptions($options), $this->resolveRecorder, $this->maxBodyBytes);
    }

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
            responseBody: $this->responseBody($response, $status, $mayReadBody),
            timings: $this->timings($info, $startedAt),
            // Not `$status === null && ...`: curl can deliver 200 headers and
            // then fail mid-body. Discarding the error because a status
            // existed recorded a failed transfer as a success, and
            // always-keep-failures sampling then dropped it.
            error: $error !== null ? TransferError::fromThrowable($error) : null,
            startedAt: $startedAt,
            sequence: $sequence,
            pid: getmypid() ?: null,
        );
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
     * @param array<string, mixed> $options
     */
    private function requestBody(array $options): CapturedBody
    {
        $declaredType = $this->declaredContentType($options);

        if (isset($options['json'])) {
            $json = $options['json'];

            // Symfony serialises this itself. Serialising it here as well
            // invoked user code twice: a JsonSerializable that increments a
            // counter captured {"counter":1} and transmitted {"counter":2},
            // and any side effect in jsonSerialize() happened twice. Objects
            // are therefore described rather than encoded.
            if (is_object($json)) {
                return CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE, null, 'application/json');
            }

            $encoded = json_encode($json, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

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
     * The URL as Symfony will actually request it.
     *
     * @param array<string, mixed> $options
     */
    private function resolveUrl(string $url, array $options): string
    {
        $base = $options['base_uri'] ?? null;

        if (!is_string($base) || $base === '') {
            return $url;
        }

        // Already absolute.
        if (preg_match('~^[a-z][a-z0-9+.-]*://~i', $url) === 1) {
            return $url;
        }

        return rtrim($base, '/') . '/' . ltrim($url, '/');
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

    private function responseBody(ResponseInterface $response, ?int $status, bool $mayReadBody): CapturedBody
    {
        if ($status === null) {
            return CapturedBody::none();
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

        $contentType = null;

        try {
            $contentType = $response->getHeaders(false)['content-type'][0] ?? null;
        } catch (\Throwable) {
            // Headers unavailable; the body is still worth keeping.
        }

        return $this->cap($content, is_string($contentType) ? $contentType : null);
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

    private function cap(string $body, ?string $contentType): CapturedBody
    {
        $size = strlen($body);

        if ($size > $this->maxBodyBytes) {
            return CapturedBody::captured(
                bytes: substr($body, 0, $this->maxBodyBytes),
                size: $size,
                contentType: $contentType,
                truncated: true,
                sha256: hash('sha256', $body),
            );
        }

        return CapturedBody::captured($body, $size, $contentType);
    }
}
