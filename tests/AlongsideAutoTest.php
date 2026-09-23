<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Symfony\Tests\TestKernel;
use Ssx\Wiretap\Symfony\WiretapHttpClient;
use Ssx\Wiretap\Wiretap as Core;
use Symfony\Component\HttpClient\CurlHttpClient;
use Symfony\Component\HttpClient\Retry\GenericRetryStrategy;
use Symfony\Component\HttpClient\RetryableHttpClient;

/**
 * The decorator and ssx/wiretap-auto's curl hooks in one process, both
 * writing to the same recorder: each transfer must be recorded once, by the
 * decorator, including redirects and retry attempts.
 */
const ALONGSIDE_PORT = 18794;

beforeAll(function (): void {
    if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
        return;
    }

    $docroot = sys_get_temp_dir() . '/wiretap-symfony-alongside';
    @mkdir($docroot, 0o755, true);
    file_put_contents($docroot . '/index.php', <<<'ROUTER'
<?php
$uri = $_SERVER['REQUEST_URI'];
if (str_starts_with($uri, '/redirect')) {
    header('Location: /echo?from=redirect', true, 302);
    exit;
}
if (preg_match('~^/flaky/([a-z0-9]+)~', $uri, $m)) {
    $counter = sys_get_temp_dir() . '/wiretap-symfony-flaky-' . $m[1];
    $seen = (int) @file_get_contents($counter);
    file_put_contents($counter, (string) ($seen + 1));
    if ($seen % 2 === 0) {
        http_response_code(503);
    }
}
header('Content-Type: application/json');
echo json_encode(['path' => $uri]);
ROUTER);

    $server = proc_open(
        sprintf('exec %s -S 127.0.0.1:%d -t %s', PHP_BINARY, ALONGSIDE_PORT, escapeshellarg($docroot)),
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
    );

    for ($i = 0; $i < 50; ++$i) {
        $socket = @fsockopen('127.0.0.1', ALONGSIDE_PORT, $errno, $errstr, 0.1);

        if ($socket !== false) {
            fclose($socket);

            break;
        }

        usleep(100_000);
    }

    register_shutdown_function(static function () use ($server): void {
        proc_terminate($server);
        proc_close($server);
    });
});

beforeEach(function (): void {
    if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
        $this->markTestSkipped('needs ext-opentelemetry and ssx/wiretap-auto');
    }

    // The package boots itself from its autoload file; this only makes sure.
    \Ssx\Wiretap\Auto\Wiretap::boot();
    $this->base = 'http://127.0.0.1:' . ALONGSIDE_PORT;
});

afterEach(fn () => Core::reset());

it('records each transfer once, as the decorator: plain, redirect and both retry attempts', function (): void {
    $sink = new InMemorySink();
    $recorder = Core::setRecorder(new Recorder(sink: $sink, blocklist: new Blocklist()));
    $client = new WiretapHttpClient(new CurlHttpClient(), static fn (): Recorder => Core::recorder());
    $retrying = new RetryableHttpClient($client, new GenericRetryStrategy(delayMs: 0), 1);

    $statuses = [
        $client->request('GET', $this->base . '/echo?plain=1')->getStatusCode(),
        $client->request('GET', $this->base . '/redirect')->getStatusCode(),
        $retrying->request('GET', $this->base . '/flaky/' . bin2hex(random_bytes(4)))->getStatusCode(),
    ];
    $recorder->flush();

    // Before the claim this was 8: the decorator's four and four more from
    // the curl hooks, with nothing linking them.
    expect($statuses)->toBe([200, 200, 200])
        ->and($sink->all())->toHaveCount(4)
        ->and(array_values(array_unique(array_map(static fn ($e): string => $e->transport, $sink->all()))))
        ->not->toContain('curl');
});

it('records each attempt once through the framework-wired client with retry_failed', function (): void {
    $kernel = new TestKernel(
        ['enabled' => true, 'path' => sys_get_temp_dir() . '/wiretap-symfony-alongside-log'],
        bin2hex(random_bytes(6)),
        ['http_client' => ['default_options' => [
            'extra' => ['curl' => [CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4]],
            'retry_failed' => ['max_retries' => 1, 'delay' => 0],
        ]]],
    );
    $kernel->boot();

    /** @var Recorder $recorder */
    $recorder = $kernel->getContainer()->get('test.service_container')->get(Recorder::class);
    $recorder->setSink($sink = new InMemorySink());
    $client = $kernel->getContainer()->get('test.consumer')->client;

    $response = $client->request('GET', $this->base . '/flaky/' . bin2hex(random_bytes(4)));
    $status = $response->getStatusCode();
    $response->getContent();
    $recorder->flush();
    $kernel->shutdown();

    // retry_failed records each attempt; the hooks add nothing. Before the
    // claim this was 4.
    expect($status)->toBe(200)
        ->and($sink->all())->toHaveCount(2)
        ->and(array_map(static fn ($e): string => $e->transport, $sink->all()))->not->toContain('curl');
});
