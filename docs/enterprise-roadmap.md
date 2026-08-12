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
| R2: Multi-tenant and identity | OIDC/OAuth2 integration, tenant-aware storage, RBAC roles, per-tenant quotas, key rotation, and audit search. | Every protected operation has a tenant and principal; authorization tests cover analyst, responder, and admin roles. |
| R3: Streaming ingestion | Collector registration, syslog/HTTP connectors, durable queue, retry policy, dead-letter queue, backpressure, and replay. | Ingestion can resume after worker restart without losing acknowledged events; poison messages are isolated. |
| R4: Enterprise analytics | Search index, time-range queries, detection scheduling, deduplication, suppression policies, threat-intelligence enrichment, and data retention. | Query latency and ingestion throughput are measured against an agreed workload; rules are versioned and explainable. |
| R5: AI analyst layer | Retrieval-grounded investigation summaries, alert clustering, entity risk scoring, natural-language search translated to reviewed queries, and evaluation datasets. | AI outputs cite evidence, are reproducible enough for audit, have confidence/abstention behavior, and cannot trigger irreversible response without policy approval. |
| R6: Response and governance | Approval-gated playbooks, connector isolation, case management, evidence export, tenant isolation testing, backups, disaster recovery, and compliance controls. | Restore drills, access reviews, response approvals, and audit export are tested and documented. |

## Immediate Risks Found in the Baseline

| Area | Current limitation | Priority |
|---|---|---:|
| Query scalability | `/api/events` and related endpoints return unbounded lists and recompute derived data on every request. | P0 |
| Analyst state | Triage records are process-local and disappear on restart. | P0 |
| Audit integrity | Audit detail is concatenated into a line without sanitization; attacker-controlled values can forge log lines. | P0 |
| Rate limiting | In-memory buckets are not bounded, are not synchronized, and trust `X-Forwarded-For` from any caller. | P0 |
| Persistence | SQLite does not enable WAL/busy timeout; per-request initialization and writes are not prepared for concurrent workers. | P1 |
| Authentication | A single static bearer token provides no principal, role, tenant, rotation, or revocation model. | P1 |
| Event contract | Validation is permissive, invalid timestamps silently become `now`, and the schema lacks tenant, ingestion, trace, and integrity metadata. | P1 |
| Detection architecture | The repository has deterministic rules and statistical heuristics, but no real model lifecycle, feature store, evaluation set, or AI evidence contract. | P1 |
| Response safety | Workflow YAML exists, but there is no approval gate, idempotency key, connector isolation, or durable execution record. | P1 |
| Deployment | A single process and SQLite are appropriate for a demo or small lab, not for a large enterprise's volume or availability objectives. | P2 |

## AI-Specific Guardrails

AI components should begin as **decision support**. They may summarize evidence, rank alerts, propose a query, or identify a likely related entity. They should not invent telemetry, suppress alerts without a deterministic policy, or execute containment without explicit authorization. Each AI output should store the input event/alert identifiers, model/version, prompt or feature version, confidence, and analyst disposition. Evaluation should include false-positive rate, false-negative review, calibration, latency, and prompt-injection resistance.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/92/final "NIST SP 800-92: Guide to Computer Security Log Management"

[2]: https://csrc.nist.gov/pubs/sp/800/61/r3/final "NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations"

[3]: https://attack.mitre.org/ "MITRE ATT&CK"
