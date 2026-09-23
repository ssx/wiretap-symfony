<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

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
 * The stream is the application reading the body, so capture does not read
 * it too. The record is finished by a failure here, or by the destructor
 * once the application is done with the response.
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

        return $this->resolving(static fn () => $inner->toStream($throw));
    }
}
