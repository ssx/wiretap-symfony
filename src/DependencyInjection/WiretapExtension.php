<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final class WiretapExtension extends Extension
{
    /**
     * @param array<array-key, mixed> $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.php');

        $container->setParameter('wiretap.enabled', $config['enabled']);
        $container->setParameter('wiretap.path', $config['path']);
        $container->setParameter('wiretap.retention_days', $config['retention_days']);
        $container->setParameter('wiretap.presets', $config['presets']);
        $container->setParameter('wiretap.blocklist', $config['blocklist']);
        $container->setParameter('wiretap.redaction', $config['redaction']);
        $container->setParameter('wiretap.sampling', $config['sampling']);
        $container->setParameter('wiretap.sampling_salt', $config['sampling_salt']);
    }

    public function getAlias(): string
    {
        return 'wiretap';
    }
}
