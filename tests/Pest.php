<?php

declare(strict_types=1);

/**
 * A server that answers, sends part of a body, then stalls.
 *
 * Needed because an ErrorChunk only appears on an *idle timeout*.
 * MockHttpClient raises its 'error' at request time and never streams one, and
 * a closed port makes NativeHttpClient throw before streaming begins — so
 * neither can exercise the chunk-inspection path.
 */
const STALLING_SERVER_PORT = 8793;

/**
 * A second server that stalls briefly and then finishes the body, so an idle
 * timeout can be followed by a transfer that completes.
 */
const RESUMING_SERVER_PORT = 8794;

function startStallingServer(int $port = STALLING_SERVER_PORT, bool $resumes = false): array
{
    $script = sys_get_temp_dir() . '/wiretap-stalling-server-' . $port . '.php';

    file_put_contents($script, <<<'SRV'
        <?php
        [, $port, $resumes] = $argv;
        $s = stream_socket_server('tcp://127.0.0.1:' . $port, $e, $m);
        while ($c = @stream_socket_accept($s, 30)) {
            // The readiness probe connects and closes without a request.
            // Answering it would hold this single-threaded server for the
            // whole stall, and the first real request would queue behind it.
            if (in_array(fread($c, 2048), ['', false], true)) {
                @fclose($c);
                continue;
            }
            $length = $resumes ? 14 : 100;
            fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: {$length}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n");
            fwrite($c, 'partial');
            fflush($c);
            sleep($resumes ? 1 : 3);
            if ($resumes) {
                fwrite($c, '-rest!!');
            }
            @fclose($c);
        }
        SRV);

    $process = proc_open(
        sprintf('exec %s %s %d %d', PHP_BINARY, escapeshellarg($script), $port, $resumes ? 1 : 0),
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
    );

    // A controlled handler rather than @: PHPUnit installs one that fires
    // regardless of suppression, so probing a port that is not up yet
    // reported a warning on a passing test.
    set_error_handler(static fn (): bool => true);

    try {
        for ($i = 0; $i < 50; ++$i) {
            $socket = fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1);

            if ($socket !== false) {
                fclose($socket);

                break;
            }

            usleep(100_000);
        }
    } finally {
        restore_error_handler();
    }

    return [$process, $script];
}

function stopStallingServer(array $handles): void
{
    [$process, $script] = $handles;

    if (is_resource($process)) {
        proc_terminate($process);
        proc_close($process);
    }

    @unlink($script);
}
