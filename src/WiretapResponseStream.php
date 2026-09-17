<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Symfony\Contracts\HttpClient\ChunkInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * Maps streamed chunks back to the responses the caller was handed.
 *
 * The inner client only knows about the responses it created, so streaming
 * yields those — and the caller, holding WiretapResponse objects, found that
 * `$key === $response` was false. That breaks identity comparisons and
 * response-keyed maps, which is the normal way to drive a multiplexed stream.
 *
 * Consuming a stream to completion also has to finish the record, or a
 * response read entirely through stream() was never captured.
 *
 */
final class WiretapResponseStream implements ResponseStreamInterface
{
    /**
     * @param \SplObjectStorage<object, WiretapResponse> $wrappers
     */
    public function __construct(
        private readonly ResponseStreamInterface $inner,
        private readonly \SplObjectStorage $wrappers,
    ) {
    }

    public function key(): ResponseInterface
    {
        $key = $this->inner->key();

        return $this->wrappers[$key] ?? $key;
    }

    public function current(): ChunkInterface
    {
        $chunk = $this->inner->current();

        // getError() first, and never isLast() on an error chunk.
        //
        // ErrorChunk::isLast() *throws* — TimeoutException for an idle
        // timeout, TransportException otherwise. Calling it unconditionally
        // meant Symfony's own documented pattern
        //
        //     foreach ($client->stream($r, 1.0) as $chunk) {
        //         if ($chunk->isTimeout()) { continue; }
        //
        // threw from inside current(), before the caller's isTimeout() check
        // could run. It also silently disabled RetryableHttpClient, which
        // guards on getError() before isLast() and so never saw the failure it
        // was there to retry. Both happened even with capture disabled,
        // because the decorator is always installed.
        if ($chunk->getError() !== null) {
            // The transfer is over, and the error is the outcome. Record it
            // without touching anything that throws.
            $this->commitCurrent();

            return $chunk;
        }

        // ResponseStreamInterface extends Iterator, so foreach drives these
        // methods rather than getIterator(). commit() is guarded, so being
        // called for every chunk costs nothing.
        if ($chunk->isLast()) {
            $this->commitCurrent();
        }

        return $chunk;
    }

    public function next(): void
    {
        $this->inner->next();
    }

    public function valid(): bool
    {
        return $this->inner->valid();
    }

    public function rewind(): void
    {
        $this->inner->rewind();
    }

    /**
     * @return \Generator<ResponseInterface, ChunkInterface>
     */
    public function getIterator(): \Traversable
    {
        while ($this->valid()) {
            yield $this->key() => $this->current();

            $this->next();
        }
    }

    /**
     * The transfer finished through the stream, so nothing else will commit
     * this record.
     */
    private function commitCurrent(): void
    {
        try {
            $inner = $this->inner->key();
            $wrapper = $this->wrappers[$inner] ?? null;

            if ($wrapper instanceof WiretapResponse) {
                $wrapper->commitFromStream();
            }
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        }
    }
}
