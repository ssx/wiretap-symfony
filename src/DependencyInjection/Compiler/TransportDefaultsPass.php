<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\DependencyInjection\Compiler;

use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Hands the framework's http_client default_options to the capture decorator.
 *
 * FrameworkBundle passes default_options to the transport's constructor, so
 * they are applied inside the transport — below the decorator, where capture
 * cannot see them. A default `auth_bearer` or `X-Api-Key` was therefore never
 * learned as a secret, and a response echoing it was stored in plaintext.
 *
 * Read at compile time from the transport's own definition, so it is exactly
 * what the transport is built with, env placeholders included; the container
 * resolves them for both at the same moment.
 */
final class TransportDefaultsPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(WiretapHttpClient::class)
            || !$container->hasDefinition('http_client.transport')) {
            return;
        }

        $arguments = $container->getDefinition('http_client.transport')->getArguments();
        $defaults = $arguments[0] ?? [];

        if (!is_array($defaults)) {
            return;
        }

        $container->getDefinition(WiretapHttpClient::class)->replaceArgument(3, $defaults);
    }
}
