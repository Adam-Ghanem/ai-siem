# Enterprise AI-SIEM Architecture and Delivery Roadmap

## Executive Position

The current repository is a useful lightweight SOC demonstrator: it normalizes a small set of Linux, Windows, firewall, and web events; evaluates deterministic detections; produces explainable anomalies; correlates alerts into incidents; and exposes a static dashboard. It is **not yet a production enterprise SIEM** because ingestion, identity, tenancy, persistence, query scalability, response orchestration, and operational controls are still intentionally minimal.

The modernization strategy is therefore incremental. The first release in this branch hardens the existing service without pretending that a single-process SQLite deployment is equivalent to a hyperscale SIEM. The next releases should preserve the same API contracts while allowing the storage and ingestion layers to be replaced behind explicit interfaces.

## Design Principles

| Principle | Target behavior |
|---|---|
| Security by default | Protected endpoints fail closed, request identity is explicit, secrets are never written to audit logs, and unsafe proxy headers are not trusted by default. |
| Explainable detection | Every alert and anomaly carries rule metadata, evidence, confidence, and a recommended analyst action. AI must assist analysts rather than silently make irreversible decisions. |
| Bounded work | Query endpoints paginate, ingestion is bounded, and expensive detection/correlation work is cached or scoped so one request cannot consume the whole process. |
| Durable analyst state | Triage and incident state must survive process restarts and be auditable. |
| Schema-first interoperability | Events should move toward a stable normalized contract compatible with common security event schemas, while retaining source-specific raw evidence. |
| Replaceable infrastructure | The current SQLite/memory implementation remains useful for development, but repository interfaces should make PostgreSQL, OpenSearch, or a streaming backend a deploy-time choice. |
| Safe automation | Response workflows are suggestions or approval-gated actions by default. Automatic containment must have explicit policy, idempotency, and an audit trail. |

NIST describes enterprise log management as both infrastructure and process, not just a parser or search screen [1]. NIST's current incident-response guidance similarly emphasizes preparing for, detecting, responding to, and recovering from incidents as part of cybersecurity risk management [2]. MITRE ATT&CK is retained as the threat-modeling vocabulary for rule metadata and coverage reporting [3].

## Target Architecture

```text
                 +--------------------------+
                 |  Collectors / Connectors |
                 |  syslog, agents, cloud   |
                 +------------+-------------+
                              |
                              v
                 +--------------------------+
                 |  Ingestion Gateway       |
                 |  auth, quotas, validation |
                 |  idempotency, DLQ         |
                 +------------+-------------+
                              |
                              v
                 +--------------------------+
                 |  Normalization Pipeline  |
                 |  parser registry +       |
                 |  normalized event schema |
                 +------------+-------------+
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
+--------------------------+       +--------------------------+
| Durable Event Store      |       | Derived Index / Search    |
| PostgreSQL or lakehouse  |       | OpenSearch or equivalent |
+------------+-------------+       +------------+-------------+
             |                                 |
             +----------------+----------------+
                              v
                 +--------------------------+
                 | Detection + Analytics     |
                 | rules, baselines, AI      |
                 +------------+-------------+
                              v
                 +--------------------------+
                 | Alert / Incident Service  |
                 | dedup, correlation, SLA   |
                 +------+-----------+---------+
                        |           |
                        v           v
              +----------------+  +----------------+
              | Analyst UI/API |  | Response       |
              | RBAC, search,  |  | approval gates |
              | cases, reports |  | connectors     |
              +----------------+  +----------------+
```

The repository's current single-process flow maps onto the middle of this design. The immediate work should improve the gateway, event contract, durable analyst state, and API query boundaries before adding distributed infrastructure.

## Prioritized Delivery Plan

| Release | Scope | Exit criteria |
|---|---|---|
| R1: Enterprise hardening | Request IDs, bounded pagination, secure audit logging, thread-safe rate limits, durable triage, SQLite WAL/busy timeout, stable event validation, regression tests, and operational documentation. | All tests pass; security scanners pass; API responses expose pagination metadata; analyst triage survives restart; no secret or newline injection in audit logs. |
| R2: Multi-tenant and identity | **Implemented foundation:** configurable principals/RBAC, tenant-aware event/triage/ingest/ack/note storage, tenant-scoped reads, authenticated `/api/me`, authorization audit records, and optional HS256 JWT migration mode. **Next:** OIDC/OAuth2, asymmetric signing, per-tenant quotas, key rotation, revocation, and audit search. | Every protected operation has a tenant and principal; tenant isolation, JWT negative cases, and role authorization tests pass. OIDC and centralized secret rotation remain follow-on work. |
| R3: Streaming ingestion | **Partial foundation implemented:** bounded `asyncio.to_thread` parsing/persistence, batch lifecycle, event-size limits, and parser statistics. **Next:** collector registration, durable queue, retry policy, dead-letter queue, backpressure across workers, and replay. | The current single-process pipeline avoids blocking the event loop and records batch state. Distributed resume/no-loss guarantees require the next queue-based release. |
| R4: Enterprise analytics | **Partial foundation implemented:** Windows/Sysmon parser coverage, safe Sigma import/export, opt-in AbuseIPDB/OTX enrichment, SQLite default, and optional PostgreSQL/OpenSearch adapters. **Next:** search index validation, time-range queries, detection scheduling, retention, measured load, and provider governance. | The current adapters are contract-tested and fail closed when optional dependencies/configuration are absent. Production throughput and failover are not yet claimed. |
| R5: AI analyst layer | Retrieval-grounded investigation summaries, alert clustering, entity risk scoring, natural-language search translated to reviewed queries, and evaluation datasets. | AI outputs cite evidence, are reproducible enough for audit, have confidence/abstention behavior, and cannot trigger irreversible response without policy approval. This remains future work; current anomaly logic is deterministic/statistical. |
| R6: Response and governance | Approval-gated playbooks, connector isolation, case management, evidence export, tenant isolation testing, backups, disaster recovery, and compliance controls. | Restore drills, access reviews, response approvals, and audit export are tested and documented. |

## Immediate Risks Found in the Baseline

| Area | Current limitation | Priority |
|---|---|---:|
| Query scalability | List APIs are bounded, but derived detections/correlation still execute in-process and are not benchmarked for enterprise volume. | P1 |
| Analyst state | Triage, acknowledgements, and notes are durable for configured adapters; case management, retention, evidence export, and restore drills remain. | P1 |
| Audit integrity | Audit values are control-character escaped and secrets are excluded, but centralized audit search, tamper evidence, and export remain. | P1 |
| Rate limiting | In-memory buckets are bounded and synchronized; distributed quotas and per-tenant rate budgets remain. | P1 |
| Persistence | SQLite uses WAL/busy timeout and adapters exist for PostgreSQL/OpenSearch, but remote backend production validation, backups, migrations, and failover remain. | P1 |
| Authentication | Legacy tokens remain a controlled migration path; JWT HS256 mode validates key claims, but OIDC/OAuth2, asymmetric keys, revocation, rotation, and centralized secret management are still pending. | P1 |
| Event contract | Tenant and event metadata are present and parser fields are bounded, but full ECS/OCSF alignment, strict timestamp policy, integrity metadata, and schema versioning remain. | P1 |
| Detection architecture | The repository has deterministic rules and statistical heuristics, but no real model lifecycle, feature store, evaluation set, or AI evidence contract. | P1 |
| Response safety | Workflow YAML exists, but there is no approval gate, idempotency key, connector isolation, or durable execution record. | P1 |
| Deployment | Docker, Render, and Fly.io templates plus health checks are present, but no external live deployment is claimed; the local sandbox has no Docker daemon. SQLite remains single-process. | P2 |

## Release 2 Identity Contract

The current identity layer supports legacy `AI_SIEM_API_KEY`, JSON principal mapping through `AI_SIEM_PRINCIPALS`, and an optional JWT mode selected with `AI_SIEM_AUTH_MODE=jwt` or `hybrid`. JWT mode validates HS256 signatures plus issuer, audience, expiry, not-before, issued-at, subject, tenant, and role claims. The API derives tenant scope from the authenticated context and does not accept a client-supplied tenant selector. This is a migration foundation for a lab or controlled deployment; a large enterprise should replace shared static bearer secrets with OIDC/OAuth2, short-lived credentials, asymmetric key rotation, revocation, and a centralized policy decision point.

| Role | Read SOC data | Ingest events | Write triage |
|---|---:|---:|---:|
| `admin` | Yes | Yes | Yes |
| `reader` | Yes | No | No |
| `analyst` | Yes | No | Yes |
| `responder` | Yes | No | Yes |
| `ingestor` | Yes | Yes | No |

## AI-Specific Guardrails

AI components should begin as **decision support**. They may summarize evidence, rank alerts, propose a query, or identify a likely related entity. They should not invent telemetry, suppress alerts without a deterministic policy, or execute containment without explicit authorization. Each AI output should store the input event/alert identifiers, model/version, prompt or feature version, confidence, and analyst disposition. Evaluation should include false-positive rate, false-negative review, calibration, latency, and prompt-injection resistance.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/92/final "NIST SP 800-92: Guide to Computer Security Log Management"

[2]: https://csrc.nist.gov/pubs/sp/800/61/r3/final "NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations"

[3]: https://attack.mitre.org/ "MITRE ATT&CK"
