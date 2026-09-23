<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\NullSink;
use Ssx\Wiretap\Symfony\DependencyInjection\Compiler\SamplingSaltPass;
use Ssx\Wiretap\Symfony\DependencyInjection\Compiler\TransportDefaultsPass;
use Ssx\Wiretap\Symfony\DependencyInjection\WiretapExtension;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\DependencyInjection\ContainerBuilder;
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

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->addCompilerPass(new TransportDefaultsPass());
        $container->addCompilerPass(new SamplingSaltPass());
    }

    public function boot(): void
    {
        if ($this->container === null) {
            return;
        }

        // Resolve the recorder eagerly, and whether or not capture is on.
        //
        // Symfony services are lazy, and the factory is what publishes the
        // recorder to the global holder that ssx/wiretap-auto's curl hooks
        // and the HTTP client decorator read from. Left unpublished, the
        // holder builds core's default recorder from WIRETAP_ENABLED — so a
        // bundle configured `enabled: false` still recorded whenever that
        // variable was set, to a default sink and without the bundle's
        // redaction rules. The configured recorder is the one that decides,
        // including when what it decides is "off".
        try {
            $this->container->get(Recorder::class);
        } catch (\Throwable) {
            // A misconfigured recorder must not prevent the kernel booting,
            // and must not leave the environment to decide either. Capture is
            // off until the configuration is fixed.
            Wiretap::setRecorder(new Recorder(sink: new NullSink(), enabled: false));
        }
    }
}
