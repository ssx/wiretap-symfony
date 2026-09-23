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
use Ssx\Wiretap\Symfony\EventListener\LifecycleListener;
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
            '%wiretap.sampling_salt%',
            '%wiretap.redaction_secret%',
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

    // Commands, messenger messages and request termination: each command and
    // each handled message is its own unit of work, and each is flushed when
    // it ends. Starts early and ends late, so other listeners on the same
    // events are inside the unit of work. The messenger events are named by
    // string so the bundle still compiles without symfony/messenger.
    $services->set(LifecycleListener::class)
        ->args([service(RecorderFactory::class), service(Recorder::class)])
        ->tag('kernel.event_listener', ['event' => 'console.command', 'method' => 'onConsoleCommand', 'priority' => 2048])
        ->tag('kernel.event_listener', ['event' => 'console.terminate', 'method' => 'onConsoleTerminate', 'priority' => -2048])
        ->tag('kernel.event_listener', ['event' => 'kernel.terminate', 'method' => 'onKernelTerminate', 'priority' => -2048])
        ->tag('kernel.event_listener', ['event' => 'Symfony\\Component\\Messenger\\Event\\WorkerMessageReceivedEvent', 'method' => 'onMessageReceived', 'priority' => 2048])
        ->tag('kernel.event_listener', ['event' => 'Symfony\\Component\\Messenger\\Event\\WorkerMessageReceivedEvent', 'method' => 'onMessageReceivedLate', 'priority' => -2048])
        ->tag('kernel.event_listener', ['event' => 'Symfony\\Component\\Messenger\\Event\\WorkerMessageHandledEvent', 'method' => 'onMessageFinished', 'priority' => -2048])
        ->tag('kernel.event_listener', ['event' => 'Symfony\\Component\\Messenger\\Event\\WorkerMessageFailedEvent', 'method' => 'onMessageFinished', 'priority' => -2048]);

    // Decorate Symfony's HttpClient. It has no middleware concept, so a
    // decorator is the supported extension point — TraceableHttpClient and the
    // profiler panel work the same way.
    //
    // The transport, not `http_client`. Every framework client is built over
    // http_client.transport: `http_client` itself and each of
    // framework.http_client.scoped_clients. Decorating `http_client` left the
    // scoped clients uncaptured altogether. Down here capture also sees the
    // options each scope adds, and retries arrive as the separate attempts
    // they are.
    //
    // Priority -100 puts this outside the framework's mock_response_factory
    // client (-10), which never calls the transport it replaces — beneath it,
    // an application's tests would silently record nothing.
    //
    // `null` for the invalid behaviour: installing the bundle in an
    // application without symfony/http-client must not fail container
    // compilation. Decoration simply does not happen.
    //
    // The recorder is a closure resolved per request, not the concrete
    // service. The container builds this client once, and a test calling
    // Wiretap::fake() afterwards must be able to redirect its traffic —
    // otherwise test traffic keeps reaching the configured file sink.
    //
    // The last argument is the framework's default_options, filled in by
    // TransportDefaultsPass.
    $services->set(WiretapHttpClient::class)
        ->decorate('http_client.transport', null, -100, ContainerInterface::NULL_ON_INVALID_REFERENCE)
        ->args([
            service('.inner')->nullOnInvalid(),
            service(ActiveRecorder::class),
            1_048_576,
            [],
        ]);

    $services->set(WiretapCommand::class)
        ->args(['%wiretap.path%', '%wiretap.retention_days%'])
        ->tag('console.command');
};
