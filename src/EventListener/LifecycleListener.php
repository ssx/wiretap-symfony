<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\EventListener;

use Ssx\Wiretap\Symfony\Internal\Lifecycle;
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
 * tried in the Laravel bridge changed how applications shut down.
 */
final class LifecycleListener
{
    /**
     * Commands that handle messages, each of which is its own unit of work.
     */
    private const WORKER_COMMANDS = ['messenger:consume', 'messenger:failed:retry'];

    public function onConsoleCommand(object $event): void
    {
        if (!$event instanceof ConsoleCommandEvent) {
            return;
        }

        $command = $event->getCommand();

        Lifecycle::commandStarted($command?->getName(), self::isWorker($command));
    }

    public function onConsoleTerminate(object $event): void
    {
        Lifecycle::commandFinished();
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
