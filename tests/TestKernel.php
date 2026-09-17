<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Tests;

use Ssx\Wiretap\Symfony\WiretapBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class TestKernel extends Kernel
{
    /**
     * @param array<string, mixed> $wiretapConfig
     */
    public function __construct(
        private readonly array $wiretapConfig = [],
        private readonly string $uniqueId = '',
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        return [new FrameworkBundle(), new WiretapBundle()];
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'test' => true,
                'secret' => 'test',
                'http_method_override' => false,
                'php_errors' => ['log' => false],
                'router' => ['utf8' => true, 'resource' => 'kernel::loadRoutes', 'type' => 'service'],
                // Without this the http_client service is never registered,
                // and the decorator has nothing to decorate.
                'http_client' => ['default_options' => ['timeout' => 5]],
            ]);

            $container->loadFromExtension('wiretap', $this->wiretapConfig);

            // A consumer, so http_client is not inlined away, and so the test
            // can assert the thing that actually matters: that injecting
            // HttpClientInterface yields the recorded client.
            $container->register('test.consumer', HttpClientConsumer::class)
                ->setPublic(true)
                ->setAutowired(true);
        });
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/wiretap-symfony-cache/' . $this->uniqueId;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/wiretap-symfony-log/' . $this->uniqueId;
    }
}

/**
 * Exists so the container has a reason to keep http_client, and so the
 * decoration can be asserted through injection rather than by reaching into
 * the container for a private service.
 */
final class HttpClientConsumer
{
    public function __construct(public readonly HttpClientInterface $client)
    {
    }
}
