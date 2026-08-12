# AI-SIEM Architecture

AI-SIEM is designed as a lightweight full-stack SOC/SIEM platform.

## Components

- **Frontend**: static HTML/CSS/JavaScript dashboard.
- **Backend**: FastAPI service with protected API endpoints, request IDs, bounded pagination, and health checks.
- **Data Layer**: SQLite persistence with WAL mode for normalized events and durable analyst triage; bundled JSON logs are only first-run demo input.
- **Detection Content**: Rule metadata mapped to MITRE ATT&CK tactics and techniques, plus explainable statistical anomaly heuristics.
- **Parsers**: source-specific parser metadata.
- **Dashboards**: dashboard metadata definitions.
- **Workflows**: response playbook definitions, currently approval-free metadata that must be wrapped by a future approval-gated executor before production automation.

## Data Flow

```text
collectors / JSON API
  -> bounded ingestion gateway
  -> parser and normalized event model
  -> SQLite event store
  -> detection and anomaly engines
  -> alerts and incident correlation
  -> durable triage API
  -> frontend dashboard
```

## API Flow

The frontend fetches backend endpoints every 15 seconds and updates the SOC dashboard.

## Design Goal

The current goal is to provide a secure, testable foundation for enterprise evolution without pretending that a single-process SQLite deployment meets hyperscale availability or ingestion objectives. See [`enterprise-roadmap.md`](enterprise-roadmap.md) for the target architecture, release gates, and AI safety guardrails.
