<?php

declare(strict_types=1);

use Psr\Log\NullLogger;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\EventListener\CorrelationListener;
use Ssx\Wiretap\Symfony\Internal\Lifecycle;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Wiretap;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Messenger\Event\WorkerMessageReceivedEvent;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * These go through a real console Application and a real messenger worker,
 * because the defects only exist there: commands and workers were never seen
 * at all, and a test that calls the listeners by hand would pass either way.
 */
final class LifecycleProbe
{
    public static ?InMemorySink $sink = null;

    /** @var list<string> */
    public static array $seen = [];

    public static function see(string $label): void
    {
        self::$seen[] = $label . ':' . count(self::$sink?->all() ?? []);
    }
}

final class LifecyclePing
{
    public function __construct(public readonly int $n, public readonly bool $fail = false)
    {
    }
}

final class LifecyclePingHandler
{
    public function __construct(private readonly HttpClientInterface $httpClient)
    {
    }

    public function __invoke(LifecyclePing $ping): void
    {
        $this->httpClient->request('GET', 'https://api.example.test/message/' . $ping->n)->getContent();
        LifecycleProbe::see('message' . $ping->n);

        if ($ping->fail) {
            throw new \RuntimeException('handler failed');
        }
    }
}

final class LifecycleCallCommand extends Command
{
    public function __construct(private readonly HttpClientInterface $httpClient)
    {
        parent::__construct('lifecycle:call');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->httpClient->request('GET', 'https://api.example.test/call/1')->getContent();
        LifecycleProbe::see('call');
        $this->httpClient->request('GET', 'https://api.example.test/call/2')->getContent();

        return Command::SUCCESS;
    }
}

final class LifecycleOuterCommand extends Command
{
    public function __construct(private readonly HttpClientInterface $httpClient)
    {
        parent::__construct('lifecycle:outer');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->httpClient->request('GET', 'https://api.example.test/outer/before')->getContent();

        // Through the application, so the console events fire for it.
        $this->getApplication()?->doRun(new ArrayInput(['command' => 'lifecycle:call']), $output);

        $this->httpClient->request('GET', 'https://api.example.test/outer/after')->getContent();

        return Command::SUCCESS;
    }
}

final class LifecycleMockFactory
{
    public function __invoke(): MockResponse
    {
        return new MockResponse('ok');
    }
}

function lifecycleKernel(): TestKernel
{
    $kernel = new TestKernel(
        ['enabled' => true, 'presets' => []],
        bin2hex(random_bytes(6)),
        [
            'http_client' => ['mock_response_factory' => 'lifecycle.mock'],
            'messenger' => [
                'transports' => ['mem' => ['dsn' => 'in-memory://', 'retry_strategy' => ['max_retries' => 0]]],
                'routing' => [LifecyclePing::class => 'mem'],
            ],
        ],
        static function (ContainerBuilder $container): void {
            $container->register('logger', NullLogger::class);
            $container->register('lifecycle.mock', LifecycleMockFactory::class)->setPublic(true);
            $container->register(LifecyclePingHandler::class, LifecyclePingHandler::class)->setAutowired(true)->addTag('messenger.message_handler');

            foreach ([LifecycleCallCommand::class, LifecycleOuterCommand::class] as $command) {
                $container->register($command, $command)->setAutowired(true)->addTag('console.command');
            }
        },
    );
    $kernel->boot();

    LifecycleProbe::$sink = new InMemorySink();
    LifecycleProbe::$seen = [];
    $kernel->getContainer()->get(Recorder::class)->setSink(LifecycleProbe::$sink);

    return $kernel;
}

function runCommand(TestKernel $kernel, array $input): int
{
    $application = new Application($kernel);
    $application->setAutoExit(false);
    $application->setCatchExceptions(false);

    return $application->run(new ArrayInput($input), new BufferedOutput());
}

/**
 * The bundle's kernel.request listener, called directly: this test kernel
 * has no routes, so dispatching the whole event fails in the router.
 */
function startRequest(TestKernel $kernel, Request $request): void
{
    (new CorrelationListener())(new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST));
}

/**
 * @return list<Exchange>
 */
function lifecycleRecords(): array
{
    Wiretap::recorder()->flush();

    return LifecycleProbe::$sink?->all() ?? [];
}

beforeEach(function (): void {
    Lifecycle::reset();
    Correlation::reset();
});

afterEach(function (): void {
    Lifecycle::reset();
    Correlation::reset();
    Wiretap::reset();
});

describe('a messenger worker', function (): void {
    beforeEach(function (): void {
        $this->kernel = lifecycleKernel();
        $this->bus = $this->kernel->getContainer()->get('test.service_container')->get('messenger.default_bus');
    });

    it('gives each message its own correlation, and writes each one when it is handled', function (): void {
        foreach ([1, 2, 3] as $n) {
            $this->bus->dispatch(new LifecyclePing($n));
        }

        runCommand($this->kernel, ['command' => 'messenger:consume', 'receivers' => ['mem'], '--limit' => 3]);
        $records = lifecycleRecords();

        // Each message sees the previous ones on disk already.
        expect(LifecycleProbe::$seen)->toBe(['message1:0', 'message2:1', 'message3:2'])
            ->and($records)->toHaveCount(3)
            ->and(array_unique(array_map(static fn (Exchange $e): string => $e->correlationId, $records)))->toHaveCount(3)
            ->and(array_map(static fn (Exchange $e): int => $e->sequence, $records))->toBe([0, 0, 0])
            ->and($records[0]->context)->toMatchArray([
                'command' => 'messenger:consume',
                'message' => LifecyclePing::class,
            ]);
    });

    it('ends a failed message too, so the next one still owns its own', function (): void {
        $this->bus->dispatch(new LifecyclePing(1, fail: true));
        $this->bus->dispatch(new LifecyclePing(2));

        runCommand($this->kernel, ['command' => 'messenger:consume', 'receivers' => ['mem'], '--limit' => 2]);
        $records = lifecycleRecords();

        expect(LifecycleProbe::$seen)->toBe(['message1:0', 'message2:1'])
            ->and($records)->toHaveCount(2)
            ->and($records[0]->correlationId)->not->toBe($records[1]->correlationId);
    });

    it('ends a message a listener declined to handle', function (): void {
        // Neither Handled nor Failed follows a declined message. Leaving it
        // open kept its correlation "owned", and every later message then
        // shared it.
        $dispatcher = $this->kernel->getContainer()->get('event_dispatcher');
        $declined = false;
        $dispatcher->addListener(WorkerMessageReceivedEvent::class, static function (WorkerMessageReceivedEvent $event) use (&$declined): void {
            if (!$declined) {
                $declined = true;
                $event->shouldHandle(false);
            }
        });

        foreach ([1, 2, 3] as $n) {
            $this->bus->dispatch(new LifecyclePing($n));
        }

        runCommand($this->kernel, ['command' => 'messenger:consume', 'receivers' => ['mem'], '--limit' => 3]);
        $records = lifecycleRecords();

        expect($records)->toHaveCount(2)
            ->and($records[0]->correlationId)->not->toBe($records[1]->correlationId);
    });
});

describe('a console command', function (): void {
    beforeEach(function (): void {
        $this->kernel = lifecycleKernel();
    });

    it('owns a correlation, names itself on its records, and writes each record as it is made', function (): void {
        // A long-running command stopped with SIGTERM runs no shutdown
        // functions, so anything still buffered was lost.
        runCommand($this->kernel, ['command' => 'lifecycle:call']);
        runCommand($this->kernel, ['command' => 'lifecycle:call']);
        $records = lifecycleRecords();

        expect(LifecycleProbe::$seen)->toBe(['call:1', 'call:3'])
            ->and($records)->toHaveCount(4)
            ->and($records[0]->correlationId)->toBe($records[1]->correlationId)
            ->and($records[1]->correlationId)->not->toBe($records[2]->correlationId)
            ->and(array_map(static fn (Exchange $e): int => $e->sequence, $records))->toBe([0, 1, 0, 1])
            ->and($records[0]->context)->toMatchArray(['command' => 'lifecycle:call']);
    });

    it('keeps the outer correlation through a nested command', function (): void {
        runCommand($this->kernel, ['command' => 'lifecycle:outer']);
        $records = lifecycleRecords();

        expect($records)->toHaveCount(4)
            ->and(array_unique(array_map(static fn (Exchange $e): string => $e->correlationId, $records)))->toHaveCount(1)
            ->and(array_map(static fn (Exchange $e): int => $e->sequence, $records))->toBe([0, 1, 2, 3])
            ->and($records[1]->context['command'] ?? null)->toBe('lifecycle:call')
            ->and($records[3]->context['command'] ?? null)->toBe('lifecycle:outer');
    });

    it('does not take over a correlation a request owns', function (): void {
        startRequest($this->kernel, Request::create('/checkout'));
        $requestId = Correlation::id();

        runCommand($this->kernel, ['command' => 'lifecycle:call']);

        // Neither reset nor flushed in the middle of the request.
        expect(Correlation::id())->toBe($requestId)
            ->and(LifecycleProbe::$sink?->all())->toBe([])
            ->and(array_map(static fn (Exchange $e): string => $e->correlationId, lifecycleRecords()))->toBe([$requestId, $requestId]);
    });

    it('installs no signal handler', function (): void {
        if (!function_exists('pcntl_signal_get_handler')) {
            $this->markTestSkipped('needs ext-pcntl');
        }

        runCommand($this->kernel, ['command' => 'lifecycle:call']);

        expect(pcntl_signal_get_handler(SIGTERM))->toBe(SIG_DFL)
            ->and(pcntl_signal_get_handler(SIGINT))->toBe(SIG_DFL);
    });
});

describe('a request in a long-running process', function (): void {
    it('is written and its correlation ended when the kernel terminates', function (): void {
        // FrankenPHP worker mode, RoadRunner and Swoole do not end the process
        // after a request, so the shutdown flush never came.
        $kernel = lifecycleKernel();
        $dispatcher = $kernel->getContainer()->get('event_dispatcher');
        $request = Request::create('/checkout');
        startRequest($kernel, $request);

        $kernel->getContainer()->get('test.consumer')->client->request('GET', 'https://api.example.test/in-request')->getContent();

        expect(LifecycleProbe::$sink?->all())->toBe([]);

        $dispatcher->dispatch(new TerminateEvent($kernel, $request, new Response()), KernelEvents::TERMINATE);

        expect(LifecycleProbe::$sink?->all())->toHaveCount(1)
            ->and(Correlation::hasStarted())->toBeFalse();
    });
});
