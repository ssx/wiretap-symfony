<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Internal;

use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * A stream wrapper that passes every operation through to the resource the
 * inner response's toStream() returned, and says when the transfer ended.
 *
 * toStream() hands the application a resource and nothing else, so the
 * response wrapper is dropped the moment it returns. Recording from the
 * wrapper's destructor therefore described a transfer that had not happened
 * yet — no status, no headers, no body, and a body that later ended early
 * recorded as a success. Psr18Client and HttplugClient read every streamable
 * response this way, so that was every PSR-18 exchange.
 *
 * Delegating rather than reimplementing is what keeps this from changing
 * behaviour: reads, EOF, seeking back over a buffered body, blocking and
 * select() casting all come from the resource Symfony built, exactly as
 * they would without capture.
 *
 * @internal
 */
final class RecordingStream
{
    private const PROTOCOL = 'wiretap-recording';

    /** @var resource|null Set by PHP for a stream wrapper */
    public $context;

    /** @var resource */
    private $inner;

    private ResponseInterface $response;

    /** @var \Closure(?string, bool): void */
    private \Closure $onEnd;

    private bool $ended = false;

    /**
     * @param resource                      $inner What the inner response's toStream() returned
     * @param \Closure(?string, bool): void $onEnd Called once, with the transfer's error or
     *                                             null, and whether the body was read to the end
     *
     * @return resource
     */
    public static function wrap($inner, ResponseInterface $response, \Closure $onEnd)
    {
        if (!in_array(self::PROTOCOL, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::PROTOCOL, self::class);
        }

        $stream = fopen(self::PROTOCOL . '://response', 'r', false, stream_context_create([
            self::PROTOCOL => ['inner' => $inner, 'response' => $response, 'onEnd' => $onEnd],
        ]));

        if ($stream === false) {
            // Unreachable in practice. Either way the application gets the
            // stream it would have had; only the recording is lost.
            $onEnd(null, false);

            return $inner;
        }

        return $stream;
    }

    /**
     * The response the application holds, which is what Symfony's own
     * stream wrapper answers here.
     */
    public function getResponse(): ResponseInterface
    {
        return $this->response;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $context = $this->context !== null ? stream_context_get_options($this->context)[self::PROTOCOL] ?? null : null;
        $this->context = null;

        if (!is_array($context) || !is_resource($context['inner'] ?? null)) {
            return false;
        }

        $this->inner = $context['inner'];
        $this->response = $context['response'];
        $this->onEnd = $context['onEnd'];

        return true;
    }

    public function stream_read(int $count): string|false
    {
        $data = fread($this->inner, max(1, $count));

        if ($data === false) {
            $this->end($this->failure(), false);

            return false;
        }

        if (feof($this->inner)) {
            // Symfony's wrapper can report a failure it met while reading as
            // a warning and EOF rather than as false, so the response is
            // asked either way.
            $error = $this->failure();
            $this->end($error, $error === null);
        }

        return $data;
    }

    public function stream_eof(): bool
    {
        return feof($this->inner);
    }

    public function stream_seek(int $offset, int $whence): bool
    {
        return fseek($this->inner, $offset, $whence) === 0;
    }

    public function stream_tell(): int
    {
        return (int) ftell($this->inner);
    }

    /**
     * @return array<int|string, int>|false
     */
    public function stream_stat(): array|false
    {
        return fstat($this->inner);
    }

    public function stream_set_option(int $option, int $arg1, ?int $arg2): bool
    {
        return match ($option) {
            \STREAM_OPTION_BLOCKING => stream_set_blocking($this->inner, (bool) $arg1),
            \STREAM_OPTION_READ_TIMEOUT => stream_set_timeout($this->inner, $arg1, (int) $arg2),
            default => false,
        };
    }

    /**
     * @return resource|false
     */
    public function stream_cast(int $castAs)
    {
        $wrapper = stream_get_meta_data($this->inner)['wrapper_data'] ?? null;

        return is_object($wrapper) && method_exists($wrapper, 'stream_cast')
            ? $wrapper->stream_cast($castAs)
            : $this->inner;
    }

    public function stream_close(): void
    {
        $complete = feof($this->inner);
        fclose($this->inner);

        // Usually closed before the end: the application stopped reading,
        // and the response knows whether the transfer had failed.
        $error = $this->failure();
        $this->end($error, $complete && $error === null);
    }

    private function failure(): ?string
    {
        try {
            $error = $this->response->getInfo('error');

            return is_string($error) && $error !== '' ? $error : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function end(?string $error, bool $complete): void
    {
        if ($this->ended) {
            return;
        }

        $this->ended = true;

        try {
            ($this->onEnd)($error, $complete);
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        }
    }
}
