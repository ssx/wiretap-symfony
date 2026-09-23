<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\Symfony\Internal\RecordingStream;
use Symfony\Component\HttpClient\Response\StreamableInterface;

/**
 * The wrapper for an inner response that can be cast to a PHP stream.
 *
 * A separate class rather than a method on WiretapResponse, because Symfony
 * decides behaviour on `instanceof StreamableInterface`: it is what makes
 * `body => ['file' => $response]` upload the download, and what offers
 * toStream() at all. The wrapper has to answer that question exactly as the
 * response it wraps would.
 *
 * The resource is the application reading the body, and all it keeps. The
 * wrapper is gone as soon as toStream() returns, so the record is finished
 * by the resource instead: when it reaches the end, fails, or is closed.
 */
final class StreamableWiretapResponse extends WiretapResponse implements StreamableInterface
{
    /**
     * @return resource
     */
    public function toStream(bool $throw = true)
    {
        $inner = $this->inner();
        assert($inner instanceof StreamableInterface);

        $stream = $this->resolving(static fn () => $inner->toStream($throw));

        return RecordingStream::wrap(
            $stream,
            $this,
            function (?string $error, bool $complete): void {
                $this->commitFromStream(
                    $error !== null ? self::transportFailure($error) : null,
                    // Read to the end of a buffered body, the content is
                    // still there, and capturing it costs no network.
                    // Short of the end nothing may be read or waited for.
                    mayReadBody: $complete && $this->buffered,
                    mayInitialise: $complete,
                );
            },
        );
    }
}
