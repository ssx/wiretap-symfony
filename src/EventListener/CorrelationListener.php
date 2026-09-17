<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Symfony\EventListener;

use Ssx\Wiretap\Correlation;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Seeds the correlation id from the inbound request.
 *
 * Every outbound call made while handling it then shares one id, so a trace
 * shows the whole story rather than one call out of context. Adopting an
 * inbound traceparent joins the trace up with whatever called us.
 *
 * Registered at a high priority so the id exists before anything else has a
 * chance to make an outbound call.
 */
final class CorrelationListener
{
    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            // A sub-request is part of the same logical operation and must not
            // start a new correlation.
            return;
        }

        $request = $event->getRequest();

        foreach (['traceparent', 'X-Request-Id', 'X-Correlation-Id'] as $header) {
            $value = $request->headers->get($header);

            if (is_string($value) && trim($value) !== '') {
                Correlation::start($value);

                return;
            }
        }

        Correlation::start();
    }
}
