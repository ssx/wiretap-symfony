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
class WiretapResponse implements ResponseInterface
{
    private bool $recorded = false;

    /**
     * @param \Closure(ResponseInterface, ?\Throwable, bool, bool): void $record
     * @param bool $buffered Whether the body can be read again after capture
     */
    public function __construct(
        private readonly ResponseInterface $inner,
        private readonly \Closure $record,
        private readonly bool $buffered = true,
    ) {
    }

    public function inner(): ResponseInterface
    {
        return $this->inner;
    }

    public function getStatusCode(): int
    {
        // Resolves the transfer but does not commit. Committing here lost the
        // body for good: the record was written before the application had
        // asked for the content, and the once-only guard then skipped the
        // call that would have captured it.
        return $this->resolving(fn (): int => $this->inner->getStatusCode());
    }

    /**
     * @return array<string, list<string>>
     */
    public function getHeaders(bool $throw = true): array
    {
        return $this->resolving(fn (): array => $this->inner->getHeaders($throw));
    }

    public function getContent(bool $throw = true): string
    {
        // The application has asked for the body, so reading it for capture
        // costs nothing extra on a buffered response. On an unbuffered one it
        // cannot be read twice, so capture records it as streaming instead.
        return $this->capturing(fn (): string => $this->inner->getContent($throw), mayReadBody: $this->buffered);
    }

    /**
     * @return array<array-key, mixed>
     */
    public function toArray(bool $throw = true): array
    {
        return $this->capturing(fn (): array => $this->inner->toArray($throw), mayReadBody: $this->buffered);
    }

    /**
     * Called when a stream reaches its last chunk, or fails. The body was
     * consumed by the caller through the stream, so capture must not read it
     * again.
     */
    public function commitFromStream(?\Throwable $error = null): void
    {
        $this->commit($error, mayReadBody: false);
    }

    public function cancel(): void
    {
        $this->inner->cancel();
        $this->commit(null, mayReadBody: false);
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
        //
        // mayInitialise: false is what keeps this destructor from changing
        // what the application sees. Symfony throws for an unread 4xx/5xx from
        // the inner response's own destructor, but only if that response was
        // never initialised. Capture used to call getHeaders(false), which
        // initialises it without throwing — so the inner destructor then
        // skipped its status check and a dropped 500 raised nothing at all.
        // The plain client threw; the wrapped one silently succeeded.
        $this->commit(null, mayReadBody: false, mayInitialise: false);
    }

    /**
     * @template T
     *
     * @param \Closure(): T $operation
     *
     * @return T
     */
    /**
     * Run an operation that resolves the transfer without finishing the
     * record. Only a failure commits, since there will be nothing else to
     * commit if the transfer never completes.
     *
     * @template T
     *
     * @param \Closure(): T $operation
     *
     * @return T
     */
    protected function resolving(\Closure $operation): mixed
    {
        try {
            return $operation();
        } catch (\Throwable $e) {
            $this->commit($e, mayReadBody: false);

            throw $e;
        }
    }

    /**
     * @template T
     *
     * @param \Closure(): T $operation
     *
     * @return T
     */
    private function capturing(\Closure $operation, bool $mayReadBody = true): mixed
    {
        try {
            $result = $operation();
        } catch (\Throwable $e) {
            // A 4xx/5xx with $throw = true lands here, and so does a transport
            // failure. Both are exchanges worth recording.
            $this->commit($e, $mayReadBody);

            throw $e;
        }

        $this->commit(null, $mayReadBody);

        return $result;
    }

    /**
     * @param bool $mayInitialise Whether capture is allowed to force the inner
     *     response to resolve. False only from the destructor, where doing so
     *     suppresses the application's own exception.
     */
    private function commit(?\Throwable $error, bool $mayReadBody = true, bool $mayInitialise = true): void
    {
        if ($this->recorded) {
            return;
        }

        $this->recorded = true;

        try {
            ($this->record)($this->inner, $error, $mayReadBody, $mayInitialise);
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        }
    }
}
