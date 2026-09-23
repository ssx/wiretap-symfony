<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Internal;

use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Wiretap;

/**
 * Which unit of work the process is doing, and who owns its correlation.
 *
 * An HTTP request is not the only unit of work. A console command is one, and
 * so is each message a messenger worker handles, and none of those reach the
 * kernel.request listener. Without this, every command and every message in a
 * process shared one correlation id, one ever-growing sequence and one
 * sampling decision, and nothing was flushed until the process exited — so a
 * worker being debugged showed nothing at all.
 *
 * Ownership is decided once, when a unit starts, and only the owner resets
 * and flushes when it ends. A command run from inside a request, a message or
 * another command is part of that unit of work: resetting for it would split
 * the outer trace in two and flush in the middle of it.
 *
 * Static because there is one of these per process, and the capture layers
 * and the enricher that read it are not containers' to inject into.
 */
final class Lifecycle
{
    /**
     * Commands running, outermost first.
     *
     * @var list<array{name: ?string, owns: bool, worker: bool}>
     */
    private static array $commands = [];

    /**
     * Messages being handled, outermost first.
     *
     * @var list<array{class: string, owns: bool}>
     */
    private static array $messages = [];

    private static bool $handlingRequest = false;

    public static function requestStarted(): void
    {
        self::$handlingRequest = true;
    }

    /**
     * The main request has been terminated: flush what it recorded and end
     * its correlation.
     *
     * Under php-fpm the process ends here anyway. Under FrankenPHP worker
     * mode, RoadRunner or Swoole it does not, and the next flush was 200
     * records or a restart away. Ending the correlation matters too: the
     * explicit start made for the request otherwise stayed "owned" after it,
     * and a message handled later in the same process would decline to own
     * its own.
     */
    public static function requestTerminated(): void
    {
        self::$handlingRequest = false;

        self::flush();
        Correlation::reset();
    }

    public static function commandStarted(?string $name, bool $worker): void
    {
        $owns = self::$commands === []
            && self::$messages === []
            && !self::$handlingRequest;

        self::$commands[] = ['name' => $name, 'owns' => $owns, 'worker' => $worker];

        if (!$owns) {
            return;
        }

        Correlation::reset();

        // A worker is not one unit of work, and must not own a correlation.
        // Starting one explicitly would make every message it handles see an
        // enclosing owner and decline its own: one id and one sampling
        // decision for the worker's whole life.
        if (!$worker) {
            Correlation::start();
        }
    }

    public static function commandFinished(): void
    {
        $frame = array_pop(self::$commands);

        if ($frame === null || !$frame['owns']) {
            return;
        }

        self::flush();
        Correlation::reset();
    }

    public static function messageStarted(string $class): void
    {
        // An enclosing owner: an outer message, a request, or a command that
        // deliberately started a correlation. A worker command does not start
        // one, so its messages each own theirs.
        $owns = self::$messages === []
            && !self::$handlingRequest
            && !Correlation::startedExplicitly();

        self::$messages[] = ['class' => $class, 'owns' => $owns];

        if ($owns) {
            Correlation::start();
        }
    }

    public static function messageFinished(): void
    {
        $frame = array_pop(self::$messages);

        if ($frame === null || !$frame['owns']) {
            return;
        }

        // Per message, or a worker holds its captures until the buffer fills
        // or the process exits.
        self::flush();
        Correlation::reset();
    }

    /**
     * The command the current work belongs to, innermost first.
     */
    public static function command(): ?string
    {
        $frame = self::$commands === [] ? null : self::$commands[array_key_last(self::$commands)];

        return $frame['name'] ?? null;
    }

    public static function message(): ?string
    {
        $frame = self::$messages === [] ? null : self::$messages[array_key_last(self::$messages)];

        return $frame['class'] ?? null;
    }

    /**
     * Whether each record should be written as soon as it is made.
     *
     * True inside a console command that owns its correlation and is not a
     * worker. Such a command can run for hours — a daemon, an import, a
     * scheduler loop — and a process manager stops it with SIGTERM, on which
     * PHP runs no shutdown functions, so everything buffered was lost on every
     * deploy. Installing a signal handler to flush changes how applications
     * shut down, so instead nothing is left buffered to lose. A worker flushes
     * per message instead, and a request once it is terminated.
     */
    public static function flushesEachRecord(): bool
    {
        $outer = self::$commands[0] ?? null;

        return $outer !== null && $outer['owns'] && !$outer['worker'];
    }

    /**
     * @internal For tests.
     */
    public static function reset(): void
    {
        self::$commands = [];
        self::$messages = [];
        self::$handlingRequest = false;
    }

    private static function flush(): void
    {
        try {
            Wiretap::recorder()->flush();
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        }
    }
}
