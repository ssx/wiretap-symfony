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
     * The message of an idle timeout the stream yielded for this response,
     * cleared by anything that arrives after it.
     */
    private ?string $pendingTimeout = null;

    /**
     * The body as it passed through stream(), while it is a complete prefix
     * of the body and within the ceiling. Null once it is neither.
     */
    private ?string $observed = '';

    /** Bytes seen through stream(), counted past the ceiling. */
    private int $observedBytes = 0;

    /** Whether every byte seen so far arrived through stream(), in order. */
    private bool $observedContiguous = true;

    /**
     * The SHA-256 of the observed body, built chunk by chunk as the chunks
     * are handed to the application. Dropped with the observed body.
     */
    private ?\HashContext $observedHash = null;

    /**
     * @param \Closure(ResponseInterface, ?\Throwable, bool, bool, ?array{0: ?string, 1: int, 2: ?string}): void $record
     * @param bool $buffered Whether the body can be read again after capture
     * @param int $maxObservedBytes How much of a streamed body to keep
     * @param bool $hashObserved Whether to hash the streamed body as it passes
     */
    public function __construct(
        private readonly ResponseInterface $inner,
        private readonly \Closure $record,
        protected readonly bool $buffered = true,
        private readonly int $maxObservedBytes = 1_048_576,
        bool $hashObserved = false,
    ) {
        if ($hashObserved) {
            $this->observedHash = hash_init('sha256');
        }
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
    public function commitFromStream(
        ?\Throwable $error = null,
        bool $mayReadBody = false,
        bool $mayInitialise = true,
    ): void {
        $this->commit($error, $mayReadBody, $mayInitialise);
    }

    /**
     * Keep a chunk the application is being handed through stream().
     *
     * Those bytes are already in memory on their way to the caller, so
     * keeping them is not a read and cannot block or consume anything. It is
     * the only way to see the body under retry_failed: AsyncResponse makes
     * every attempt with `buffer => false` whatever the application asked
     * for, so the attempt's body can never be read a second time.
     *
     * Only a contiguous run from offset 0 counts. A chunk that does not start
     * where the last one ended means some of the body went elsewhere, and a
     * record of part of a body presented as all of it would be untrue.
     */
    public function observeChunk(string $content, int $offset): void
    {
        if ($content === '' || !$this->observedContiguous) {
            return;
        }

        if ($offset !== $this->observedBytes) {
            $this->observedContiguous = false;
            $this->observed = null;
            $this->observedHash = null;

            return;
        }

        $this->observedBytes += strlen($content);

        if ($this->observed === null) {
            return;
        }

        // Past the ceiling the body will be omitted, so stop holding it; the
        // count carries on so the record still says how large it was. The
        // digest stops with it: hashing a body without limit would cost the
        // application time in its own read loop for a record that keeps none
        // of the body.
        if ($this->observedBytes > $this->maxObservedBytes) {
            $this->observed = null;
            $this->observedHash = null;

            return;
        }

        $this->observed .= $content;

        if ($this->observedHash !== null) {
            hash_update($this->observedHash, $content);
        }
    }

    /**
     * The last chunk has been handed to the application: the transfer is
     * complete, so the body is complete too.
     *
     * The whole body passed through stream() in order: record that. Otherwise,
     * a buffered response still holds its complete content, and reading it
     * back now needs no network and cannot wait. Recording "streaming" for
     * either threw away a body that was sitting in memory — including for
     * Symfony's own documented pattern of streaming a response and then
     * calling toArray() on it, where the once-only guard then skipped the
     * toArray() that would have captured it.
     */
    public function commitStreamCompleted(): void
    {
        if ($this->observedContiguous) {
            // Only a body that passed through whole has a digest to give.
            $digest = $this->observed !== null && $this->observedHash !== null
                ? hash_final($this->observedHash)
                : null;
            $this->observedHash = null;

            $this->commit(null, mayReadBody: false, observed: [$this->observed, $this->observedBytes, $digest]);

            return;
        }

        $this->commit(null, mayReadBody: $this->buffered);
    }

    /**
     * An idle timeout does not end the transfer, so it is only remembered.
     * If the application gives up on the response after one — Symfony throws
     * TimeoutException from the chunk for exactly that — the timeout is the
     * outcome, and the destructor records it.
     */
    public function noteIdleTimeout(?string $message): void
    {
        $this->pendingTimeout = $message !== null && $message !== '' ? $message : 'Idle timeout reached';
    }

    public function noteProgress(): void
    {
        $this->pendingTimeout = null;
    }

    /**
     * Symfony's own exception where it is installed, so the record names the
     * class the application saw. The contracts alone do not ship one.
     */
    protected static function transportFailure(string $message, bool $timeout = false): \Throwable
    {
        $class = $timeout
            ? 'Symfony\\Component\\HttpClient\\Exception\\TimeoutException'
            : 'Symfony\\Component\\HttpClient\\Exception\\TransportException';

        if (class_exists($class)) {
            $failure = new $class($message);

            if ($failure instanceof \Throwable) {
                return $failure;
            }
        }

        return new \RuntimeException($message);
    }

    /**
     * @internal For WiretapResponseStream.
     */
    public static function streamFailure(string $message): \Throwable
    {
        return self::transportFailure($message);
    }

    public function cancel(): void
    {
        $this->inner->cancel();

        // RetryableHttpClient cancels an attempt that timed out before it
        // retries, so a pending timeout is what this attempt ended in.
        $this->commit($this->pendingTimeoutFailure(), mayReadBody: false);
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
        $this->commit($this->pendingTimeoutFailure(), mayReadBody: false, mayInitialise: false);
    }

    private function pendingTimeoutFailure(): ?\Throwable
    {
        return $this->pendingTimeout !== null
            ? self::transportFailure($this->pendingTimeout, timeout: true)
            : null;
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
    /**
     * @param ?array{0: ?string, 1: int, 2: ?string} $observed The body seen
     *     through stream(), its size and SHA-256, or null when capture has
     *     not seen it
     */
    private function commit(
        ?\Throwable $error,
        bool $mayReadBody = true,
        bool $mayInitialise = true,
        ?array $observed = null,
    ): void {
        if ($this->recorded) {
            return;
        }

        $this->recorded = true;

        // Nothing else needs these bytes now.
        $this->observed = null;
        $this->observedHash = null;

        try {
            ($this->record)($this->inner, $error, $mayReadBody, $mayInitialise, $observed);
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        }
    }
}
