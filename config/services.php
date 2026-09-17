<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Symfony\Command\WiretapCommand;
use Ssx\Wiretap\Symfony\EventListener\CorrelationListener;
use Ssx\Wiretap\Symfony\Factory\ActiveRecorder;
use Ssx\Wiretap\Symfony\Factory\RecorderFactory;
use Ssx\Wiretap\Symfony\SymfonyContextEnricher;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services->set(ActiveRecorder::class);

    $services->set(SymfonyContextEnricher::class)
        ->args([service('request_stack')->nullOnInvalid()]);

    $services->set(RecorderFactory::class)
        ->args([
            '%wiretap.enabled%',
            '%wiretap.path%',
            '%wiretap.presets%',
            '%wiretap.blocklist%',
            '%wiretap.redaction%',
            '%wiretap.sampling%',
            service(SymfonyContextEnricher::class),
        ]);

    // The factory also registers this recorder on the global holder, so the
    // ssx/wiretap-auto curl hooks write to the same place.
    $services->set(Recorder::class)
        ->factory([service(RecorderFactory::class), 'create'])
        ->public();

    $services->set(NdjsonReader::class)
        ->args(['%wiretap.path%'])
        ->public();

    $services->set(CorrelationListener::class)
        ->tag('kernel.event_listener', ['event' => 'kernel.request', 'priority' => 1024]);

    // Decorate Symfony's HttpClient. It has no middleware concept, so a
    // decorator is the supported extension point — TraceableHttpClient and the
    // profiler panel work the same way.
    // `null` for the invalid behaviour: installing the bundle in an
    // application without symfony/http-client must not fail container
    // compilation. Decoration simply does not happen.
    //
    // The recorder is a closure resolved per request, not the concrete
    // service. The container builds this client once, and a test calling
    // Wiretap::fake() afterwards must be able to redirect its traffic —
    // otherwise test traffic keeps reaching the configured file sink.
    $services->set(WiretapHttpClient::class)
        ->decorate('http_client', null, 250, ContainerInterface::NULL_ON_INVALID_REFERENCE)
        ->args([
            service('.inner')->nullOnInvalid(),
            service(ActiveRecorder::class),
        ]);

    $services->set(WiretapCommand::class)
        ->args(['%wiretap.path%', '%wiretap.retention_days%'])
        ->tag('console.command');
};
