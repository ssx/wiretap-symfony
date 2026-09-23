<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\Contract\ContextEnricher;
use Ssx\Wiretap\Exchange;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Tags each exchange with the route that caused it.
 *
 * The capture layers sit below the framework — the curl hooks below the
 * container entirely — so they cannot know this. It is usually what turns
 * "a slow call to some API" into "the checkout route is slow".
 */
final readonly class SymfonyContextEnricher implements ContextEnricher
{
    public function __construct(private ?RequestStack $requestStack = null)
    {
    }

    public function enrich(Exchange $exchange): Exchange
    {
        try {
            $request = $this->requestStack?->getCurrentRequest();

            if ($request === null) {
                // No request in flight: a console command, a messenger worker,
                // a warm-up. Nothing useful to add, and claiming a route here
                // would be worse than claiming nothing.
                return $exchange;
            }

            $route = $request->attributes->get('_route');
            $controller = $request->attributes->get('_controller');

            return $exchange->withContext(array_filter([
                'route' => is_string($route) ? $route : null,
                'controller' => is_string($controller) ? $controller : null,
                'method' => $request->getMethod(),
                'uri' => self::safePath($request, $route),
            ], static fn (mixed $v): bool => $v !== null && $v !== ''));
        } catch (\Throwable) {
            // Enrichment is a nicety. Never let it cost a record.
            return $exchange;
        }
    }

    /**
     * The inbound path, only where it cannot carry a value.
     *
     * The concrete path of `/reset-password/{token}` holds the token, and
     * context is not something redaction looks at, so storing it put a
     * credential into every record the request made. Symfony keeps no route
     * template on the request, and rebuilding one by matching parameter
     * values back into the path would be a guess — which the record must not
     * contain. So the path is kept for a matched route with no parameters,
     * where it is the template, and otherwise left out: the route name still
     * says which endpoint it was. Unmatched paths are left out too, since
     * nothing says what is in them.
     */
    private static function safePath(Request $request, mixed $route): ?string
    {
        if (!is_string($route) || $route === '') {
            return null;
        }

        $parameters = $request->attributes->get('_route_params');

        if (!is_array($parameters)) {
            return null;
        }

        foreach (array_keys($parameters) as $name) {
            // Underscore-prefixed entries (_locale, _format) are routing
            // defaults Symfony adds; the rest are path variables.
            if (!str_starts_with((string) $name, '_')) {
                return null;
            }
        }

        return $request->getPathInfo();
    }
}
