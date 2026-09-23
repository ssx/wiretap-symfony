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
        private ?string $redactionSecret = null,
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
            // hashHint is left at core's default (off), so an absent salt can
            // never trip core's "hash hints need a hashSalt" check at boot.
            hashSalt: $this->hashSalt(),
        );
    }

    /**
     * The key for the digest core keeps of a body it did not store.
     *
     * An omitted or truncated body keeps a digest only as an HMAC under
     * RedactionConfig::$hashSalt, and none without one: a plain SHA-256 of a
     * short payload beside its own redaction can be brute-forced back to the
     * payload. With no salt set, every such body lost the "did this body
     * change between calls" comparison.
     *
     * The default is derived from the kernel secret rather than being the
     * secret itself, because the sampler is already keyed with it. A labelled
     * HMAC keeps the two keys independent while needing no new configuration.
     *
     * `redaction.hash_salt` overrides it and is used as it is; an empty value
     * keeps no digest. Without a kernel secret there is no digest either.
     */
    private function hashSalt(): ?string
    {
        $configured = $this->redaction['hash_salt'] ?? null;

        if (is_string($configured) || is_int($configured) || is_float($configured)) {
            $configured = (string) $configured;

            return trim($configured) === '' ? null : $configured;
        }

        return is_string($this->redactionSecret) && trim($this->redactionSecret) !== ''
            ? hash_hmac('sha256', 'wiretap-redaction', $this->redactionSecret)
            : null;
    }

    /**
     * Whether the HTTP client decorator hashes the whole body it sees.
     *
     * Core keeps a digest of a body it did not store in full — truncated, or
     * omitted as binary — only as an HMAC under the redaction salt, and it
     * can only do that when the capture layer supplies the SHA-256 of the
     * whole body. Supplying one is safe only while core will key it, so this
     * is on by default only while redaction runs and a salt is in effect,
     * and off without either whatever `redaction.hash_full_body` says.
     *
     * Unset, it follows WIRETAP_HASH_FULL_BODY. Only a recognised false
     * value turns it off.
     */
    public function hashFullBody(): bool
    {
        if (!(bool) ($this->redaction['enabled'] ?? true) || $this->hashSalt() === null) {
            return false;
        }

        $configured = $this->redaction['hash_full_body'] ?? null;

        if ($configured === null) {
            $configured = $_SERVER['WIRETAP_HASH_FULL_BODY'] ?? $_ENV['WIRETAP_HASH_FULL_BODY'] ?? getenv('WIRETAP_HASH_FULL_BODY');

            if ($configured === false) {
                return true;
            }
        }

        if ($configured === false || $configured === 0) {
            return false;
        }

        return !(is_string($configured)
            && in_array(strtolower(trim($configured)), ['false', '0', 'off', 'no'], true));
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
