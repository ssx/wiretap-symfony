<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\DependencyInjection;

use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('wiretap');
        $root = $treeBuilder->getRootNode();

        $root
            ->children()
                // Off by default. A package that began recording personal data
                // the moment it was installed would be indefensible.
                ->booleanNode('enabled')->defaultFalse()->end()
                ->scalarNode('path')->defaultValue('%kernel.project_dir%/var/log/wiretap')->end()
                ->integerNode('retention_days')->defaultValue(7)->end()

                ->arrayNode('presets')
                    ->scalarPrototype()->end()
                    ->defaultValue([
                        PresetBlocklistProvider::PAYMENT_GATEWAYS,
                        PresetBlocklistProvider::CLOUD_METADATA,
                    ])
                ->end()

                // A URL matching any of these produces no record at all: the
                // body is never read. A gate, not a filter.
                ->arrayNode('blocklist')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()

                ->arrayNode('redaction')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
                        ->arrayNode('body_paths')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->integerNode('max_body_bytes')->defaultValue(65536)->end()
                    ->end()
                ->end()

                ->arrayNode('sampling')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('rate_basis_points')->defaultValue(10000)->end()
                        ->booleanNode('always_keep_failures')->defaultTrue()->end()
                        ->integerNode('slow_threshold_us')->defaultValue(2000000)->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
