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

                        // Everything below adds to what core already
                        // redacts rather than replacing it: naming one extra
                        // header must not stop Authorization and Cookie being
                        // removed.
                        ->arrayNode('headers')
                            ->info('Extra header names to remove (deny mode), or the only ones to keep (allow mode)')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('query')
                            ->info('Extra query parameter names to redact')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        // An enum, so a typo fails the container build rather
                        // than quietly meaning something else.
                        ->enumNode('header_mode')
                            ->values(['deny', 'allow'])
                            ->defaultValue('deny')
                        ->end()
                        ->arrayNode('patterns')
                            ->info('Built-in detectors to switch on or off, e.g. {email: true}')
                            ->useAttributeAsKey('name')
                            ->booleanPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('custom')
                            ->info('Extra regexes applied to header values and bodies')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->booleanNode('safety_net')->defaultTrue()->end()
                        ->booleanNode('omit_uninspectable_bodies')->defaultTrue()->end()
                        ->integerNode('max_header_value_bytes')->defaultValue(4096)->end()
                        ->integerNode('min_echoed_secret_length')->defaultValue(8)->end()
                    ->end()
                ->end()

                // Keys the sampling decision. Null means the kernel secret.
                ->scalarNode('sampling_salt')->defaultNull()->end()

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
