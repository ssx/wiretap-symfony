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

Running `ssx/wiretap-auto` (v0.0.8 or later) as well records each transfer
once. The decorator claims the requests it records, in `extra` (a key
Symfony merges with your defaults one by one, so `default_options.extra.curl`
is untouched), the retry layer carries it to every attempt, and auto records
nothing for a claimed transfer. You get the decorator's record, with bodies.
The claim is only added while auto's hooks are running; otherwise request
options are exactly what they would be without it.

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

Each exchange is tagged with the route name, controller and method. The path
is added only for a matched route without parameters: `/reset-password/{token}`
would otherwise put the token into every record, and context is not redacted.

Console commands and messenger messages are units of work too. Each command
gets its own correlation, and each message a `messenger:consume` worker
handles gets its own — the worker itself owns none, so one message never
shares an id or a sampling decision with the next. A command run from inside
a request, a message or another command stays part of that one. Records are
tagged with `command` and, in a worker, `message` (the message class).

Records are written when a request is terminated (so FrankenPHP worker mode,
RoadRunner and Swoole do not wait for process exit), when each message is
handled or fails, and when a command ends. Inside a command that is not a
worker, each record is written as it is made, including those made by
`ssx/wiretap-auto`'s curl hooks: a daemon stopped with SIGTERM runs no
shutdown functions, and wiretap installs no signal handler, so nothing is left
buffered to lose.

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
        # Added to core's defaults (Authorization, Cookie, X-Api-Key, ...),
        # never replacing them. In allow mode `headers` is the only list kept.
        headers: []                # e.g. ['Ocp-Apim-Subscription-Key']
        query: []                  # e.g. ['subscription-key']
        header_mode: deny          # deny | allow
        patterns: {}               # e.g. {email: true}
        custom: []                 # extra regexes
        safety_net: true
        omit_uninspectable_bodies: true
        max_header_value_bytes: 4096
        min_echoed_secret_length: 8

    sampling:
        rate_basis_points: 10000   # 10000 keeps everything
        always_keep_failures: true
        slow_threshold_us: 2000000

    # Keys the sampling decision. Defaults to kernel.secret. Without a key the
    # decision is a function of the correlation id, which a caller controls
    # through X-Request-Id or traceparent.
    sampling_salt: ~
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
