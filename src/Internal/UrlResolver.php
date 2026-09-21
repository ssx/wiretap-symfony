<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\Internal;

use Symfony\Component\HttpClient\HttpClientTrait;

/**
 * Resolves a request URL against `base_uri` exactly as Symfony does.
 *
 * The pre-capture gate has to be asked about the URL Symfony will actually
 * request, not an approximation of it. Concatenating base and path was that
 * approximation, and it disagreed with Symfony in two ways that matter:
 *
 *     base_uri https://example.test/public/ + /private
 *       Symfony  https://example.test/private
 *       concat   https://example.test/public/private
 *
 *     base_uri https://example.test/public/ + ../other
 *       Symfony  https://example.test/other
 *       concat   https://example.test/public/../other
 *
 * A rooted path replaces the base path under RFC 3986; it does not extend it.
 * So a blocklist rule naming the host-and-path the request really goes to
 * could be evaluated against a different path entirely — the gate would admit
 * a request it was configured to block, and the body was read into memory
 * before the recorder's final check discarded the exchange. Nothing was
 * stored, but the payload existed, which is the whole thing the pre-capture
 * gate exists to prevent.
 *
 * Symfony's own trait is used rather than a reimplementation of RFC 3986, so
 * this cannot drift away from the client it is standing in front of.
 */
final class UrlResolver
{
    use HttpClientTrait;

    /**
     * @param array<string, mixed> $options
     */
    public static function resolve(string $url, array $options): string
    {
        $base = $options['base_uri'] ?? null;

        try {
            $parsedBase = is_string($base) && $base !== ''
                ? self::parseUrl($base)
                : null;

            return implode('', self::resolveUrl(self::parseUrl($url), $parsedBase));
        } catch (\Throwable) {
            // An unparseable URL is Symfony's problem to report, not ours to
            // crash on. Handing back what we were given means the gate sees
            // something rather than nothing, and the request proceeds.
            return $url;
        }
    }
}
