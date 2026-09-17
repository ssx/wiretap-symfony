<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Wraps a Symfony response and records the exchange once it resolves.
 *
 * Symfony's responses are lazy: `request()` returns immediately and the
 * transfer only completes when something asks for the status, the headers or
 * the content. So there is no single moment after `request()` at which the
 * exchange is known — recording there would capture a request with no
 * response attached.
 *
 * Instead every terminal method records on its way through, guarded so it
 * happens exactly once, with the destructor as a backstop for a response that
 * is created and dropped without being read.
 */
final class WiretapResponse implements ResponseInterface
{
    private bool $recorded = false;

    /**
     * @param \Closure(ResponseInterface, ?\Throwable): void $record
     */
    public function __construct(
        private readonly ResponseInterface $inner,
        private readonly \Closure $record,
    ) {
    }

    public function inner(): ResponseInterface
    {
        return $this->inner;
    }

    public function getStatusCode(): int
    {
        return $this->capturing(fn (): int => $this->inner->getStatusCode());
    }

    /**
     * @return array<string, list<string>>
     */
    public function getHeaders(bool $throw = true): array
    {
        return $this->capturing(fn (): array => $this->inner->getHeaders($throw));
    }

    public function getContent(bool $throw = true): string
    {
        return $this->capturing(fn (): string => $this->inner->getContent($throw));
    }

    /**
     * @return array<array-key, mixed>
     */
    public function toArray(bool $throw = true): array
    {
        return $this->capturing(fn (): array => $this->inner->toArray($throw));
    }

    public function cancel(): void
    {
        $this->inner->cancel();
        $this->commit(null);
    }

    /**
     * @return mixed
     */
    public function getInfo(?string $type = null): mixed
    {
        return $this->inner->getInfo($type);
    }

    public function __destruct()
    {
        // A response created and never read still happened. Record it rather
        // than lose it — though with no content, since reading it here could
        // block on a transfer the application deliberately abandoned.
        $this->commit(null);
    }

    /**
     * @template T
     *
     * @param \Closure(): T $operation
     *
     * @return T
     */
    private function capturing(\Closure $operation): mixed
    {
        try {
            $result = $operation();
        } catch (\Throwable $e) {
            // A 4xx/5xx with $throw = true lands here, and so does a transport
            // failure. Both are exchanges worth recording.
            $this->commit($e);

            throw $e;
        }

        $this->commit(null);

        return $result;
    }

    private function commit(?\Throwable $error): void
    {
        if ($this->recorded) {
            return;
        }

        $this->recorded = true;

        try {
            ($this->record)($this->inner, $error);
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        }
    }
}
