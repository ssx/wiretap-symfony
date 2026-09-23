<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\EventListener;

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Symfony\Factory\RecorderFactory;
use Ssx\Wiretap\Symfony\Internal\Lifecycle;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\Messenger\Command\ConsumeMessagesCommand;
use Symfony\Component\Messenger\Command\FailedMessagesRetryCommand;
use Symfony\Component\Messenger\Event\WorkerMessageReceivedEvent;

/**
 * Starts and ends a correlation for each console command and each message a
 * messenger worker handles, and flushes when a request, command or message
 * ends.
 *
 * Events are received as plain objects: symfony/console and
 * symfony/messenger are optional, and a listener for a component that is not
 * installed is simply never called.
 *
 * Starts are registered early and ends late, so other listeners on the same
 * events, which can make HTTP calls of their own, are inside the unit of work
 * rather than on either side of it. No signal handler is installed: every one
 * tried in the Laravel bridge changed how applications shut down. An ordinary
 * command writes each record as it is made instead (see writeThrough()).
 */
final class LifecycleListener
{
    /**
     * Commands that handle messages, each of which is its own unit of work.
     */
    private const WORKER_COMMANDS = ['messenger:consume', 'messenger:failed:retry'];

    /**
     * Per command running, outermost first: the recorder it displaced to
     * write each record as it is made, or null when it did not.
     *
     * @var list<array{own: Recorder, writeThrough: Recorder}|null>
     */
    private array $displaced = [];

    public function __construct(
        private readonly RecorderFactory $factory,
        private readonly Recorder $recorder,
    ) {
    }

    public function onConsoleCommand(object $event): void
    {
        if (!$event instanceof ConsoleCommandEvent) {
            return;
        }

        $command = $event->getCommand();

        $ownsWork = Lifecycle::commandStarted($command?->getName(), self::isWorker($command));

        $this->displaced[] = $ownsWork ? $this->writeThrough() : null;
    }

    public function onConsoleTerminate(object $event): void
    {
        Lifecycle::commandFinished();

        $frame = array_pop($this->displaced);

        // Back to batching, for anything the process does next: a request
        // served after an in-process command must not write on the request
        // path. Only if nothing replaced the recorder meanwhile — a test
        // calling Wiretap::fake() inside the command keeps its fake.
        if ($frame !== null && Wiretap::recorder() === $frame['writeThrough']) {
            Wiretap::setRecorder($frame['own']);
        }
    }

    /**
     * Make an ordinary command write each record as it is made.
     *
     * A command that is not a worker — an import, a migration, a daemon, a
     * scheduler loop — has no per-message flush and ran until it ended with
     * everything buffered. Stopped with SIGTERM (a deploy, a timeout, a
     * container stop) PHP runs no shutdown functions, so it lost every call it
     * had made, which is exactly the run someone wants to see. Installing a
     * signal handler to flush changes how applications shut down, so instead
     * nothing is left buffered to lose. A command makes its calls with nobody
     * waiting on a response, so a write per record costs it nothing that
     * matters; requests and workers keep batching.
     *
     * Done by swapping in a recorder that buffers a single record, since core
     * fixes the buffer size at construction. The swap is on the global holder,
     * which both the HTTP client decorator and ssx/wiretap-auto's curl hooks
     * resolve per call, so raw curl in vendor code is covered too. Only when
     * the recorder in use is this application's own and is recording: a fake,
     * or one the application set itself, is left alone.
     *
     * @return array{own: Recorder, writeThrough: Recorder}|null
     */
    private function writeThrough(): ?array
    {
        try {
            if (Wiretap::isFaked()
                || Wiretap::recorder() !== $this->recorder
                || !$this->recorder->isEnabled()) {
                return null;
            }

            // Anything buffered before the command started is written now,
            // not stranded in a recorder that will receive nothing more.
            $this->recorder->flush();

            $writeThrough = $this->factory->writeThrough($this->recorder);
            Wiretap::setRecorder($writeThrough);

            return ['own' => $this->recorder, 'writeThrough' => $writeThrough];
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
            return null;
        }
    }

    public function onMessageReceived(object $event): void
    {
        if (!$event instanceof WorkerMessageReceivedEvent) {
            return;
        }

        Lifecycle::messageStarted($event->getEnvelope()->getMessage()::class);
    }

    /**
     * A listener can tell the worker not to handle a message it has received.
     * Neither Handled nor Failed follows, so the message ends here instead —
     * otherwise its correlation outlived it and every later message in the
     * worker declined to own one.
     */
    public function onMessageReceivedLate(object $event): void
    {
        if ($event instanceof WorkerMessageReceivedEvent && !$event->shouldHandle()) {
            Lifecycle::messageFinished();
        }
    }

    /**
     * Handled or failed. Failed is dispatched before a retry is scheduled,
     * so a retried message's attempts are separate units of work, as their
     * records should be.
     */
    public function onMessageFinished(object $event): void
    {
        Lifecycle::messageFinished();
    }

    public function onKernelTerminate(object $event): void
    {
        Lifecycle::requestTerminated();
    }

    private static function isWorker(?object $command): bool
    {
        if ($command === null) {
            return false;
        }

        // By class, so a renamed or aliased worker is still one; by name for
        // a command wrapped by something else.
        if ($command instanceof ConsumeMessagesCommand || $command instanceof FailedMessagesRetryCommand) {
            return true;
        }

        return method_exists($command, 'getName')
            && in_array($command->getName(), self::WORKER_COMMANDS, true);
    }
}
