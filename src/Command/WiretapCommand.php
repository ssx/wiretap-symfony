<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Command;

use Ssx\Wiretap\Cli\Application;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Ssx\Wiretap\Cli\Output;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Bridges the core CLI into `bin/console`.
 *
 * One passthrough command rather than six wrappers. Reimplementing the
 * rendering against Symfony's console helpers would mean two implementations
 * of every command drifting apart, and the core CLI already knows how to print
 * an exchange. This exists so `bin/console wiretap list` works against the
 * application's configured path without anyone having to remember where it is.
 */
#[AsCommand(
    name: 'wiretap',
    description: 'Inspect captured outbound HTTP calls (list, show, trace, export, prune, doctor)',
)]
final class WiretapCommand extends Command
{
    /** @var list<string> */
    private const FORWARDED = [
        'host', 'method', 'status', 'failed', 'since', 'limit', 'offset',
        'curl', 'har', 'json', 'raw', 'out', 'older-than', 'dry-run',
    ];

    public function __construct(
        private readonly string $path,
        private readonly int $retentionDays,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('subcommand', InputArgument::OPTIONAL, 'list, show, trace, export, prune or doctor', 'list')
            ->addArgument('args', InputArgument::IS_ARRAY, 'Positional arguments for the subcommand')
            // Declared explicitly. An IS_ARRAY argument does not accept unknown
            // options, so `wiretap list --failed` threw "The --failed option
            // does not exist" — every documented flag was rejected before it
            // could be forwarded.
            ->addOption('host', null, InputOption::VALUE_REQUIRED, 'Only this host')
            ->addOption('method', null, InputOption::VALUE_REQUIRED, 'Only this HTTP method')
            ->addOption('status', null, InputOption::VALUE_REQUIRED, 'Exact status, or a class such as 5xx')
            ->addOption('failed', null, InputOption::VALUE_NONE, 'Transport errors and 4xx/5xx only')
            ->addOption('since', null, InputOption::VALUE_REQUIRED, 'Relative window, e.g. 30m, 2h, 7d')
            ->addOption('limit', null, InputOption::VALUE_REQUIRED, 'Maximum results')
            ->addOption('offset', null, InputOption::VALUE_REQUIRED, 'Skip this many results')
            ->addOption('curl', null, InputOption::VALUE_NONE, 'Print an equivalent curl command')
            ->addOption('har', null, InputOption::VALUE_NONE, 'Print HAR 1.2')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the raw record')
            ->addOption('raw', null, InputOption::VALUE_NONE, 'Do not pretty-print bodies')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Write to this file instead of stdout')
            ->addOption('older-than', null, InputOption::VALUE_REQUIRED, 'Retention window, e.g. 7d')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report without deleting')
            ->setHelp(<<<'HELP'
                <info>bin/console wiretap list --failed</info>
                <info>bin/console wiretap show 1 --curl</info>
                <info>bin/console wiretap trace <correlation-id></info>
                <info>bin/console wiretap export --out=calls.har</info>
                <info>bin/console wiretap prune --older-than=7d</info>
                <info>bin/console wiretap doctor</info>
                HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $subcommand = (string) $input->getArgument('subcommand');

        /** @var list<string> $args */
        $args = (array) $input->getArgument('args');

        foreach (self::FORWARDED as $name) {
            $value = $input->getOption($name);

            if ($value === null || $value === false || $value === []) {
                continue;
            }

            $args[] = $value === true
                ? "--{$name}"
                : sprintf('--%s=%s', $name, is_array($value) ? implode(',', $value) : (string) $value);
        }

        // Retention defaults to the bundle's configured window rather than the
        // core CLI's, so a project that set one gets it.
        if ($subcommand === 'prune' && !$this->hasOption($args, 'older-than')) {
            $args[] = sprintf('--older-than=%dd', $this->retentionDays);
        }

        $argv = array_merge(['wiretap', $subcommand], $args, ['--path=' . $this->path]);

        // Capture and replay through Symfony's output, so `bin/console` can
        // buffer it and tests can assert on it.
        $stream = fopen('php://memory', 'w+');

        if ($stream === false) {
            return (new Application())->run($argv);
        }

        try {
            $exitCode = (new Application(new Output($stream, decorated: $output->isDecorated())))->run($argv);

            rewind($stream);
            $captured = stream_get_contents($stream);

            if (is_string($captured) && $captured !== '') {
                $output->write($captured);
            }

            return $exitCode;
        } finally {
            fclose($stream);
        }
    }

    /**
     * @param list<string> $args
     */
    private function hasOption(array $args, string $name): bool
    {
        foreach ($args as $arg) {
            if ($arg === '--' . $name || str_starts_with($arg, '--' . $name . '=')) {
                return true;
            }
        }

        return false;
    }
}
