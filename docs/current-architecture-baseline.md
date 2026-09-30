# Current Architecture Baseline

**Baseline commit:** `445c2447f3d9b771f66ec4a00ca81543a756ff6c`  
**Audit scope:** current `main` as inspected for Task 001.  
**Status:** factual implementation baseline, not a target-state design.

This document records what the repository actually implements at the baseline commit. Target-state ideas belong in [enterprise-roadmap.md](enterprise-roadmap.md); they are not capabilities until code and tests implement them.

## Runtime map

```text
Linux log agent / JSON API / bundled first-run sample
                  |
                  v
        FastAPI ingestion boundary
 auth + role checks + rate limits + body/event limits
                  |
                  v
        parser.py -> Event.from_dict
                  |
                  v
     SQLite durable event/alert storage
                  |
          +-------+--------+
          |                |
          v                v
 detection.py          anomaly.py
 deterministic        statistical /
 rule evaluation      heuristic analysis
          |
          v
     correlation.py
          |
          v
 durable incident snapshots + incident case state
          |
          v
 FastAPI query/investigation/triage endpoints
          |
          v
 static HTML/CSS/JavaScript SOC dashboard
```

The default durable implementation is SQLite. The process also keeps bounded event state in memory for some read/analytics paths. This is a single-service architecture; it does not currently provide a durable distributed ingestion queue, horizontally coordinated workers, a search cluster, or a general-purpose AI model lifecycle.

## Component inventory and responsibility boundaries

| Area | Current implementation | Boundary / coupling observed |
|---|---|---|
| Collection | `agents/linux_log_agent.py`; JSON ingestion API; bundled sample data for first run | Collector surface is intentionally narrow. |
| HTTP/API | `backend/main.py`, FastAPI | Main currently owns routing plus substantial orchestration and global runtime state. |
| Authentication/authorization | `backend/security.py` | Static bearer/API-key identities with viewer/analyst/ingestor/admin roles; no OIDC or tenant model. |
| Rate limiting | `backend/security.py` | In-process, lock-protected bounded buckets; state is not shared across processes. |
| Audit | `backend/security.py`, `backend/audit_search.py` | SHA-256 chain; optional HMAC-SHA256; filesystem-backed audit log. |
| Parsing/normalization | `backend/parser.py`, `backend/models.py` | Source-specific parsing produces a common Event dataclass. Parser statistics are process-local. |
| Persistence | `backend/storage.py` plus focused storage modules | SQLite is the operational store; storage functions are imported directly by service/orchestration code rather than hidden behind repository interfaces. |
| Detection | `backend/detection.py`, `backend/rules.py`, rule validation | Deterministic rules, including state/window-style logic; no general Sigma compiler or versioned detection runtime. |
| Anomaly analysis | `backend/anomaly.py` | Explainable heuristics/statistics over in-memory event collections; not an ML lifecycle or calibrated probability model. |
| Correlation | `backend/correlation.py`, `backend/incident_storage.py` | Alerts are deterministically correlated into incidents; durable incident snapshots avoid recomputing every read when clean. |
| Investigation | `backend/investigation.py`, evidence/alert storage helpers | Builds evidence-oriented investigation output and hydrates durable evidence. |
| Cases/triage | `backend/main.py`, `backend/storage.py` | SQLite-backed analyst state exists; non-SQLite mode falls back to process-local state. |
| Threat intelligence | `backend/threat_intel.py` | Local/file-oriented enrichment; not a general provider/feed orchestration service. |
| Frontend | `frontend/index.html` | Static dashboard polling backend endpoints; no separate frontend application framework. |
| Deployment | `Dockerfile`, Compose configuration, GitHub Actions | Containerized single-service development/portfolio deployment; not an HA topology. |
| Verification | `tests/`, `.github/workflows/ci.yml` | Broad unittest regression coverage plus compile/security/dependency checks described in README. |

## Data and evidence contracts

The normalized `Event` model carries an ID, timestamp, source, event type, optional asset/user/network/process/status/message fields, ports/protocol, and raw evidence. Explicit malformed timestamps are rejected rather than silently rewritten. Event identity and ingest paths have dedicated validation/idempotency regression tests.

`Alert` records preserve rule ID, title, severity, confidence, ATT&CK tactic/technique, timestamp, entity context, contributing event IDs/evidence, and recommended action. `Incident` records preserve related alerts/entities, evidence summary, timeline, and recommended actions. These are useful evidence contracts, but they are not yet a versioned canonical enterprise event schema.

## Security properties confirmed in code

- Protected routes require bearer identity; `/api/health` is intentionally public.
- API-key identities can carry role and principal; authorization is route/method aware.
- Rate-limit buckets are lock protected, expired, and capped; trusted proxy headers are honored only when explicitly enabled and the peer is in configured trusted proxy CIDRs.
- Audit values are sanitized/encoded. Audit records are hash chained and can be HMAC authenticated, including retained previous verification keys for rotation.
- Ingestion has event-count, raw-log, request-body, and in-memory bounds.
- README documents non-root container execution and CI security checks.

These controls are process-local/file-local where noted. They must not be described as distributed enforcement.

## Reliability and state observations

SQLite is initialized for durable events, alerts, triage/cases, and incident snapshots. Incident snapshots have dirty-state handling so the read path can avoid repeated correlation. The architecture still mixes durable state with module globals such as `EVENTS`, `TRIAGE`, `INCIDENT_CASES`, parser counters, threat-intelligence index state, and in-process rate-limit buckets. That is acceptable for the current single-process scope but is a hard boundary for multi-worker correctness.

The service has liveness/readiness endpoints and verifies storage/audit prerequisites on readiness. Current configuration is read from environment variables at module import in several modules, so invalid configuration can fail early but configuration ownership is distributed.

## Detection and analytics observations

The detector sorts events by timestamp and emits deterministic alerts from repository rules. Dedicated regression tests exist for multiple Windows execution techniques, SSH/network behavior, external-IP handling, scalability, alert durability, and atomic ingest/alert behavior. Correlation has dedicated correctness, scalability, durability, and snapshot-read-path tests.

Anomaly analysis is explicitly heuristic/statistical. It must not be described as trained AI/ML, UEBA with a model lifecycle, or a calibrated probability system.

## Documentation drift corrected by this baseline

The older roadmap's "Immediate Risks Found in the Baseline" describes an earlier repository state. Several items have since been materially addressed in current code/tests: bounded pagination/search paths, durable triage, sanitized/tamper-evident audit logging, bounded/thread-safe rate limiting with trusted-proxy controls, SQLite durability improvements, richer API-key identity/roles, strict event-time/identity validation, durable alerts/incidents, and case state.

Remaining target-state gaps still include:
- no tenant isolation model;
- no OIDC/OAuth2 identity provider integration;
- no durable distributed queue/backpressure/replay architecture;
- no replaceable storage/search repository boundary across the service;
- no HA/multi-worker coordination for process-local state;
- no general Sigma/detection-as-code compiler and lifecycle;
- no production response executor with approval/idempotency/connector isolation;
- no AI evidence contract/model lifecycle/evaluation pipeline;
- limited collector/telemetry breadth compared with enterprise SIEM deployments.

## Technical-debt and coupling register

| Priority | Finding | Evidence / consequence | Direction |
|---|---|---|---|
| P0 | Durable and process-local state are mixed | Module globals coexist with SQLite-backed state | Define explicit state/repository interfaces before multi-worker deployment. |
| P0 | Storage calls are concrete imports | `main.py` imports SQLite-oriented functions directly | Introduce narrow storage contracts before alternate backends. |
| P0 | No tenant boundary | Identity has role/principal but no tenant propagated through data | Add tenant semantics before claiming multi-tenancy. |
| P1 | Configuration ownership is distributed | Environment variables are parsed in multiple modules at import time | Move toward one typed, validated settings boundary. |
| P1 | API/orchestration concentration in `main.py` | Routing, startup state, incident refresh, auth middleware and service orchestration meet there | Extract services incrementally while preserving API contracts. |
| P1 | Parser metrics and rate-limit state are process-local | Multiple workers would disagree | Introduce shared/aggregated state only when multi-worker mode is supported. |
| P1 | Analytics read from bounded in-memory events in places | Results can represent a bounded working set rather than all durable history | Make query/time-window semantics explicit before enterprise analytics. |
| P2 | Static frontend is tightly coupled to current API shapes | Large workflow growth will increase UI complexity | Stabilize API contracts before a frontend rewrite. |

## Architectural invariants for follow-on work

1. Raw evidence and source event IDs remain traceable through alert, incident, and investigation outputs.
2. Unknown or missing evidence is never converted into a confident fact.
3. Detection and correlation remain deterministic for the same ordered evidence and rule/version inputs.
4. Authorization and integrity checks fail closed.
5. Ingestion, queries, regex/rule evaluation, and in-memory state remain bounded.
6. Historical evidence is not silently reinterpreted when rules or schemas change.
7. New infrastructure is introduced behind explicit interfaces rather than parallel duplicate pipelines.
8. Local single-process development remains supported while production boundaries evolve.

## Verification map

The repository contains focused tests for backend/API behavior, parsing, event normalization/time/identity, storage, detection, detection scalability, correlation/scalability, incident durability/snapshots/cases, alert durability/atomicity, ingest idempotency/atomicity/body limits, auth identity, proxy trust, audit integrity/search, health privacy/readiness, search validation, threat intelligence, anomaly analysis, metrics, and triage pagination.

The CI workflow and README are the authority for executable verification commands. This audit does not substitute documentation claims for passing CI.

## Target-state separation

The target architecture remains documented in [enterprise-roadmap.md](enterprise-roadmap.md). Future tasks should update this baseline when they materially change runtime boundaries. A capability belongs in this document only after implementation and regression evidence exist.
