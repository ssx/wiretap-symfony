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

function startStallingServer(): array
{
    $script = sys_get_temp_dir() . '/wiretap-stalling-server.php';

    file_put_contents($script, <<<'SRV'
        <?php
        $s = stream_socket_server('tcp://127.0.0.1:' . $argv[1], $e, $m);
        while ($c = @stream_socket_accept($s, 30)) {
            fread($c, 2048);
            fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: text/plain\r\n\r\n");
            fwrite($c, 'partial');
            sleep(3);
            @fclose($c);
        }
        SRV);

    $process = proc_open(
        sprintf('exec %s %s %d', PHP_BINARY, escapeshellarg($script), STALLING_SERVER_PORT),
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
    );

    // A controlled handler rather than @: PHPUnit installs one that fires
    // regardless of suppression, so probing a port that is not up yet
    // reported a warning on a passing test.
    set_error_handler(static fn (): bool => true);

    try {
        for ($i = 0; $i < 50; ++$i) {
            $socket = fsockopen('127.0.0.1', STALLING_SERVER_PORT, $errno, $errstr, 0.1);

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
