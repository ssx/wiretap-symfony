<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony;

use Ssx\Wiretap\Contract\ContextEnricher;
use Ssx\Wiretap\Exchange;
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
                'uri' => $request->getPathInfo(),
            ], static fn (mixed $v): bool => $v !== null && $v !== ''));
        } catch (\Throwable) {
            // Enrichment is a nicety. Never let it cost a record.
            return $exchange;
        }
    }
}
