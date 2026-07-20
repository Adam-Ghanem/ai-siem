# Security Policy

AI-SIEM is a defensive engineering project. Run it only with telemetry,
systems, and networks you are authorized to monitor.

## Reporting a vulnerability

Do not include credentials, webhook URLs, production logs, or customer data in
a public issue. Prefer GitHub private vulnerability reporting when it is
available for this repository. Otherwise, contact the repository owner with a
minimal, redacted reproduction.

## Security posture

- All API routes except the health check require a configured Bearer key.
- Admin, Operator, and Viewer keys are compared in constant time and must be
  unique across roles.
- Request sizes, ingestion batches, list responses, and in-memory state are
  bounded.
- Proxy headers are ignored unless the deployment explicitly trusts its reverse
  proxy.
- Audit records are sanitized and never include authorization headers.
- The dashboard stores its key only in the current browser tab and permits
  plaintext HTTP only for localhost development.

## Notifications

Outbound notifications are disabled by default and activate only when
`AI_SIEM_WEBHOOK_URL` or `AI_SIEM_SLACK_WEBHOOK_URL` is explicitly configured.

- Destinations must be absolute HTTPS URLs without embedded credentials,
  queries, or fragments.
- Redirects are never followed.
- Requests use a five-second timeout, bounded payloads and responses, three
  exponential-backoff retries, and a circuit breaker.
- A bounded background queue keeps webhook latency and failures out of the
  detection and alert-persistence path.
- Alert targets, IP addresses, hostnames, users, and raw evidence are excluded
  by default. Raw target inclusion requires the explicit
  `AI_SIEM_NOTIFY_INCLUDE_RAW_TARGETS=true` opt-in.
- Destination URLs are treated as secrets. They are never logged or returned
  by the API; status responses expose only channel kind and enabled state.
- Duplicate alert notifications are debounced, and an SLA breach transition is
  recorded once in operational history.

Rotate a webhook immediately if it is exposed. Use a secrets manager or
deployment secret rather than committing it to the repository.
