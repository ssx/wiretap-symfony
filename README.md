# wiretap-symfony

Symfony bundle for [wiretap](https://github.com/ssx/wiretap). Captures
outbound HTTP requests and responses, tags each with the route that caused it,
and groups every call from one inbound request under a single correlation id.

```bash
composer require ssx/wiretap-symfony
```

```yaml
# config/packages/wiretap.yaml
wiretap:
    enabled: '%env(bool:WIRETAP_ENABLED)%'
    blocklist:
        - '*.myacquirer.test'
    redaction:
        body_paths:
            - 'card.cvv'
            - 'customer.email'
```

Nothing is recorded until `enabled` is true. A package that began recording
personal data the moment it was installed would be indefensible.

## How it captures

Symfony's HttpClient is not Guzzle and has no middleware concept, so the bundle
**decorates** `http_client.transport`, the client every framework client is
built on. A decorator is the same extension point `TraceableHttpClient` and the
profiler panel use. Anything injecting `HttpClientInterface` is recorded, and
so is every client under `framework.http_client.scoped_clients`. Credentials
from `default_options` and from a scope's options are learned as secrets, so an
echo of one is redacted. With `retry_failed` on, each attempt is its own record.

Symfony's responses are lazy: `request()` returns immediately and the transfer
only completes when something asks for the status, headers or content. So the
exchange is recorded when the response resolves, not when it is created — with
a destructor backstop for a response that is created and dropped unread.

| Surface | Covered |
| --- | --- |
| `HttpClientInterface` from the container | yes |
| scoped clients (`framework.http_client.scoped_clients`) | yes |
| Guzzle clients built in your own code | via [`ssx/wiretap-guzzle`](https://github.com/ssx/wiretap-guzzle) |
| `new GuzzleHttp\Client()` in vendor code | needs [`ssx/wiretap-auto`](https://github.com/ssx/wiretap-auto) |
| raw `curl_exec()` | needs `ssx/wiretap-auto` |

## Commands

```bash
bin/console wiretap list --failed
bin/console wiretap show 1 --curl
bin/console wiretap trace <correlation-id>
bin/console wiretap export --out=calls.har
bin/console wiretap prune --older-than=7d
bin/console wiretap doctor
```

One passthrough command rather than six wrappers — the core CLI already knows
how to render an exchange, and two implementations would drift.

`wiretap export` writes HAR 1.2, which Chrome DevTools, Proxyman, Charles,
Insomnia and Postman all import.

Schedule the prune. Captured payloads are personal data and Article 5(1)(e)
storage limitation applies to them, so retention is an obligation rather than
housekeeping.

## Correlation and context

A `kernel.request` listener at priority 1024 seeds the correlation id from an
inbound `traceparent`, `X-Request-Id` or `X-Correlation-Id`, before anything
else has a chance to make an outbound call. Sub-requests deliberately do not
start a new correlation — they are part of the same logical operation.

Each exchange is tagged with the route name, controller, method and path.

## Configuration reference

```yaml
wiretap:
    enabled: false
    path: '%kernel.project_dir%/var/log/wiretap'
    retention_days: 7

    presets: ['payment-gateways', 'cloud-metadata']
    blocklist: []

    redaction:
        enabled: true
        body_paths: []
        max_body_bytes: 65536

    sampling:
        rate_basis_points: 10000   # 10000 keeps everything
        always_keep_failures: true
        slow_threshold_us: 2000000
```

`blocklist` and `redaction.body_paths` are the two worth setting for your
project. Wiretap cannot know which of your endpoints carry cardholder data, or
which keys in your payloads are sensitive. You do.

A blocklisted URL produces **no record at all** — the body is never read. It is
a gate, not a filter, which is what makes it the right control for cardholder
data rather than redaction.

## Requirements

PHP 8.2+, Symfony 6.4 or 7.

## ⚠️ Do not leave it running

Wiretap records complete request and response bodies. It is not PCI-DSS
compliant and not GDPR compliant on its own. See the
[main README](https://github.com/ssx/wiretap).

## Licence

MIT.
