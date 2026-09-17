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
     * @param Recorder|\Closure(): Recorder $recorder
     */
    public function __construct(
        private readonly HttpClientInterface $inner,
        Recorder|\Closure $recorder,
        private readonly int $maxBodyBytes = 65536,
    ) {
        $this->resolveRecorder = $recorder instanceof Recorder
            ? static fn (): Recorder => $recorder
            : $recorder;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        $recorder = ($this->resolveRecorder)();

        // Symfony resolves relative URLs against base_uri, so the URL here may
        // not be the one actually requested. getInfo('url') on the response is
        // authoritative, and the gate re-runs against it.
        if (!$recorder->shouldCapture($url)) {
            return $this->inner->request($method, $url, $options);
        }

        $startedAt = microtime(true);
        $id = Ulid::generate($startedAt);
        $sequence = Correlation::nextSequence();
        $correlationId = Correlation::id();

        $requestHeaders = $this->requestHeaders($options);
        $requestBody = $this->requestBody($options);

        $response = $this->inner->request($method, $url, $options);

        return new WiretapResponse(
            $response,
            function (ResponseInterface $resolved, ?\Throwable $error) use (
                $recorder, $id, $correlationId, $sequence, $method, $url,
                $requestHeaders, $requestBody, $startedAt
            ): void {
                $recorder->record($this->buildExchange(
                    $resolved, $error, $id, $correlationId, $sequence,
                    $method, $url, $requestHeaders, $requestBody, $startedAt,
                ));
            },
        );
    }

    public function stream(iterable|ResponseInterface $responses, ?float $timeout = null): ResponseStreamInterface
    {
        // Unwrap: the inner client cannot stream a response it did not create.
        if ($responses instanceof ResponseInterface) {
            $responses = [$responses];
        }

        $unwrapped = [];

        foreach ($responses as $response) {
            $unwrapped[] = $response instanceof WiretapResponse ? $response->inner() : $response;
        }

        return $this->inner->stream($unwrapped, $timeout);
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
            responseHeaders: $this->responseHeaders($response),
            responseBody: $this->responseBody($response, $status),
            timings: $this->timings($info, $startedAt),
            error: $status === null && $error !== null ? TransferError::fromThrowable($error) : null,
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
        if (isset($options['json'])) {
            $encoded = json_encode($options['json'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            return $encoded === false
                ? CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE)
                : $this->cap($encoded, 'application/json');
        }

        $body = $options['body'] ?? null;

        if ($body === null || $body === '') {
            return CapturedBody::none();
        }

        if (is_string($body)) {
            return $this->cap($body, null);
        }

        if (is_array($body)) {
            return $this->cap(http_build_query($body), 'application/x-www-form-urlencoded');
        }

        // A closure, a resource or an iterable. What was configured is not
        // what will be transmitted, and reading it here would consume it.
        return CapturedBody::omitted(CapturedBody::OMITTED_STREAMING);
    }

    private function responseHeaders(ResponseInterface $response): Headers
    {
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

    private function responseBody(ResponseInterface $response, ?int $status): CapturedBody
    {
        if ($status === null) {
            return CapturedBody::none();
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
