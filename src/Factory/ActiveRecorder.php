<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Factory;

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Wiretap;

/**
 * Resolves the recorder that is active right now.
 *
 * An invokable service rather than a closure because the container dumper
 * cannot serialise a closure — passing one produced an array at runtime.
 *
 * It exists at all so the HTTP client decorator never captures a concrete
 * recorder. The container builds that client once; a test calling
 * Wiretap::fake() afterwards must be able to redirect its traffic, or test
 * traffic keeps reaching the configured file sink.
 */
final class ActiveRecorder
{
    public function __invoke(): Recorder
    {
        return Wiretap::recorder();
    }
}
