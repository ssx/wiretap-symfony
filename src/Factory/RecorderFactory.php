<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Factory;

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Contract\ContextEnricher;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Sink\NullSink;
use Ssx\Wiretap\Wiretap;

/**
 * Builds the recorder from bundle configuration.
 *
 * A factory rather than inline service definitions because the wiring is
 * conditional — the sink depends on whether capture is enabled — and because
 * the recorder also has to be published to the global holder, which a plain
 * service definition cannot express.
 */
final readonly class RecorderFactory
{
    /**
     * @param list<string>         $presets
     * @param list<string>         $blocklist
     * @param array<string, mixed> $redaction
     * @param array<string, mixed> $sampling
     */
    public function __construct(
        private bool $enabled,
        private string $path,
        private array $presets,
        private array $blocklist,
        private array $redaction,
        private array $sampling,
        private ContextEnricher $enricher,
    ) {
    }

    public function create(): Recorder
    {
        $recorder = new Recorder(
            sink: $this->enabled ? new NdjsonFileSink($this->path) : new NullSink(),
            blocklist: new Blocklist([
                new PresetBlocklistProvider($this->presets),
                new ArrayBlocklistProvider($this->blocklist, 'config:wiretap.blocklist'),
                new EnvBlocklistProvider(),
            ]),
            redactor: new Redactor(new RedactionConfig(
                enabled: (bool) ($this->redaction['enabled'] ?? true),
                bodyPaths: array_values((array) ($this->redaction['body_paths'] ?? [])),
                maxBodyBytes: (int) ($this->redaction['max_body_bytes'] ?? 65536),
            )),
            sampler: new Sampler(
                rateBasisPoints: (int) ($this->sampling['rate_basis_points'] ?? 10000),
                alwaysKeepFailures: (bool) ($this->sampling['always_keep_failures'] ?? true),
                slowThresholdUs: (int) ($this->sampling['slow_threshold_us'] ?? 2_000_000),
            ),
            enabled: $this->enabled,
        );

        $recorder->addEnricher($this->enricher);

        // Publish to the global holder, so the ssx/wiretap-auto curl hooks —
        // which run below the container and cannot be injected into — write to
        // this application's configured sink rather than a default one.
        Wiretap::setRecorder($recorder);

        return $recorder;
    }
}
