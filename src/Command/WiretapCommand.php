<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Command;

use Ssx\Wiretap\Cli\Application;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
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
            ->addArgument('args', InputArgument::IS_ARRAY, 'Arguments and options for the subcommand')
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

        // Retention defaults to the bundle's configured window rather than the
        // core CLI's, so a project that set one gets it.
        if ($subcommand === 'prune' && !$this->hasOption($args, 'older-than')) {
            $args[] = sprintf('--older-than=%dd', $this->retentionDays);
        }

        $argv = array_merge(['wiretap', $subcommand], $args, ['--path=' . $this->path]);

        return (new Application())->run($argv);
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
