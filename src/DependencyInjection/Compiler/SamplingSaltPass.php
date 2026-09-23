<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Defaults the sampling salt to the kernel secret, and hands the same secret
 * to the recorder factory for deriving the redaction digest key.
 *
 * A compiler pass rather than a config default, because the bundle does not
 * require FrameworkBundle and `kernel.secret` only exists when something sets
 * it. Referenced as a parameter, not copied, so an env-backed secret resolves
 * at runtime like everything else.
 */
final class SamplingSaltPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if ($container->hasParameter('wiretap.redaction_secret')
            && $container->getParameter('wiretap.redaction_secret') === null
            && $container->hasParameter('kernel.secret')) {
            $container->setParameter('wiretap.redaction_secret', '%kernel.secret%');
        }

        if (!$container->hasParameter('wiretap.sampling_salt')
            || $container->getParameter('wiretap.sampling_salt') !== null
            || !$container->hasParameter('kernel.secret')) {
            return;
        }

        $container->setParameter('wiretap.sampling_salt', '%kernel.secret%');
    }
}
