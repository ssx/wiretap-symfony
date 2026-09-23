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
        private ?string $samplingSalt = null,
    ) {
    }

    public function create(): Recorder
    {
        $recorder = $this->build();

        // Publish to the global holder, so the ssx/wiretap-auto curl hooks —
        // which run below the container and cannot be injected into — write to
        // this application's configured sink rather than a default one.
        Wiretap::setRecorder($recorder);

        return $recorder;
    }

    /**
     * The same recorder, writing each record as it is made.
     *
     * For a console command that is not a worker: see LifecycleListener.
     * Core fixes the buffer size at construction, so this is a second
     * recorder over the first one's sink rather than a setting on it — which
     * also keeps a sink the application set on the recorder. Not published;
     * the caller decides when it is in use.
     */
    public function writeThrough(Recorder $current): Recorder
    {
        return $this->build(maxBufferedRecords: 1)->setSink($current->sink());
    }

    private function build(int $maxBufferedRecords = 200): Recorder
    {
        $recorder = new Recorder(
            sink: $this->enabled ? new NdjsonFileSink($this->path) : new NullSink(),
            blocklist: new Blocklist([
                new PresetBlocklistProvider($this->presets),
                new ArrayBlocklistProvider($this->blocklist, 'config:wiretap.blocklist'),
                new EnvBlocklistProvider(),
            ]),
            redactor: new Redactor($this->redactionConfig()),
            sampler: new Sampler(
                rateBasisPoints: (int) ($this->sampling['rate_basis_points'] ?? 10000),
                alwaysKeepFailures: (bool) ($this->sampling['always_keep_failures'] ?? true),
                slowThresholdUs: (int) ($this->sampling['slow_threshold_us'] ?? 2_000_000),
                // Without a key the decision is a pure function of the
                // correlation id, which is adopted from an inbound
                // X-Request-Id or traceparent, so a caller could compute an
                // id offline that keeps their traffic out of the capture.
                samplingSalt: is_string($this->samplingSalt) && trim($this->samplingSalt) !== ''
                    ? $this->samplingSalt
                    : null,
            ),
            maxBufferedRecords: $maxBufferedRecords,
            enabled: $this->enabled,
        );

        return $recorder->addEnricher($this->enricher);
    }

    /**
     * The redaction rules, with every option core exposes that the Laravel
     * bridge exposes too.
     *
     * Only enabled, body_paths and max_body_bytes used to be passed through,
     * so a leak through a header core does not know — an API authenticating
     * with Ocp-Apim-Subscription-Key, say — could not be fixed from config.
     *
     * In deny mode configured names are added to core's defaults, so naming
     * one extra header does not stop Authorization and Cookie being removed.
     * In allow mode the configured names are the whole list: merging the
     * default denylist into an allowlist would keep exactly the headers it
     * names, X-Api-Key among them.
     */
    private function redactionConfig(): RedactionConfig
    {
        $defaults = new RedactionConfig();
        $mode = ($this->redaction['header_mode'] ?? RedactionConfig::MODE_DENY) === RedactionConfig::MODE_ALLOW
            ? RedactionConfig::MODE_ALLOW
            : RedactionConfig::MODE_DENY;
        $headers = self::names($this->redaction['headers'] ?? [], lower: true);

        /** @var array<string, bool> $patterns */
        $patterns = array_filter(
            (array) ($this->redaction['patterns'] ?? []),
            static fn (mixed $v): bool => is_bool($v),
        );

        return new RedactionConfig(
            enabled: (bool) ($this->redaction['enabled'] ?? true),
            headerMode: $mode,
            headers: $mode === RedactionConfig::MODE_ALLOW
                ? $headers
                : array_values(array_unique(array_merge($defaults->headers, $headers))),
            query: array_values(array_unique(array_merge(
                $defaults->query,
                self::names($this->redaction['query'] ?? [], lower: true),
            ))),
            bodyPaths: array_values((array) ($this->redaction['body_paths'] ?? [])),
            patterns: array_merge($defaults->patterns, $patterns),
            custom: self::names($this->redaction['custom'] ?? []),
            safetyNet: (bool) ($this->redaction['safety_net'] ?? true),
            maxBodyBytes: (int) ($this->redaction['max_body_bytes'] ?? $defaults->maxBodyBytes),
            maxHeaderValueBytes: (int) ($this->redaction['max_header_value_bytes'] ?? $defaults->maxHeaderValueBytes),
            minEchoedSecretLength: (int) ($this->redaction['min_echoed_secret_length'] ?? $defaults->minEchoedSecretLength),
            omitUninspectableBodies: (bool) ($this->redaction['omit_uninspectable_bodies'] ?? true),
        );
    }

    /**
     * @return list<string>
     */
    private static function names(mixed $configured, bool $lower = false): array
    {
        $names = [];

        foreach ((array) $configured as $name) {
            if (is_string($name) && trim($name) !== '') {
                $names[] = $lower ? strtolower(trim($name)) : $name;
            }
        }

        return array_values(array_unique($names));
    }
}
