<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Symfony\DependencyInjection\WiretapExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class WiretapBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        if ($this->extension === null) {
            $this->extension = new WiretapExtension();
        }

        return $this->extension === false ? null : $this->extension;
    }

    public function boot(): void
    {
        if ($this->container === null || $this->container->getParameter('wiretap.enabled') !== true) {
            return;
        }

        // Resolve the recorder eagerly.
        //
        // Symfony services are lazy, and the factory is what publishes the
        // recorder to the global holder that ssx/wiretap-auto's curl hooks
        // read from. Left lazy, a raw curl_exec() early in a request would be
        // recorded against a default recorder writing to a default sink —
        // capture would appear to work while the records went somewhere the
        // application never configured.
        try {
            $this->container->get(Recorder::class);
        } catch (\Throwable) {
            // A misconfigured recorder must not prevent the kernel booting.
        }
    }
}
