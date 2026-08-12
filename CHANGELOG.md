# Changelog

## Unreleased — Enterprise SOC Upgrade

This release is maintained on branch `enterprise-identity-rbac` and is intended to be reviewed as a stacked Pull Request over `enterprise-hardening`.

### Security and platform foundation

The unused `backend/engine/` duplicate modules were confirmed to have no codebase references and removed. The anomaly engine now uses `ip.is_global` semantics while treating RFC5737 documentation ranges as external only under the explicit lab/demo flag `AI_SIEM_TREAT_DOCUMENTATION_IPS_AS_EXTERNAL=true`. FastAPI is pinned to `0.141.1`, and the dependency audit reports no known vulnerabilities.

### Detection and ingestion

The ingestion route now uses an asynchronous pipeline that moves parsing and persistence work off the event loop. Windows Event Log and Sysmon parsing covers the requested IDs `4624`, `4625`, `4688`, `4104`, `4720`, `4732`, plus selected Sysmon event types, with bounded normalized fields. Sigma import/export is available through safe YAML parsing, bounded schema validation, deterministic rule IDs, and preserved ATT&CK metadata.

### Intelligence and identity

Threat-intelligence enrichment supports opt-in AbuseIPDB and OTX lookups for globally routable IPs only, with fixed provider URLs, timeout, bounded cache, secret-free normalized responses, and graceful provider failure. JWT migration mode validates HS256, issuer, audience, expiry, not-before, issued-at, subject, tenant, and roles; legacy token mode remains explicit for controlled migration.

### Durable analyst operations

Alert acknowledgements and analyst notes are durable, tenant-scoped, role-protected, bounded, and recorded with principal/request metadata. The storage layer now provides SQLite default behavior, a memory backend for tests, and optional PostgreSQL/OpenSearch adapters with fail-closed configuration.

### Operations

The Dockerfile runs as a non-root user and exposes a health check. Render and Fly.io deployment templates plus a deployment runbook were added. The GitHub Actions workflow has a local hardening diff that adds frontend syntax checks, whitespace checks, Docker build, and container health smoke testing; the current GitHub token cannot update workflow files because it lacks the `workflows` permission, so that workflow change remains local until an authorized maintainer applies it.

### Verification

The latest handoffs passed **89 unit tests**, Python compilation, frontend syntax checking, Bandit, `pip-audit` with no known vulnerabilities, `git diff --check`, fresh-clone installation, and fresh-clone health checks for SQLite and memory modes. Docker build execution was not claimed locally because the sandbox does not provide a Docker daemon; CI contains the intended container checks once the workflow patch is applied.

### Remaining risks

The project is not yet a hyperscale enterprise SIEM. OIDC/OAuth2, asymmetric key rotation and revocation, distributed queues, dead-letter/replay, measured PostgreSQL/OpenSearch production operation, retention and backup drills, centralized audit search, approval-gated response, and evaluated AI analyst workflows remain roadmap work.
