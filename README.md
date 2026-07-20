# AI-SIEM — SOC Engineering Portfolio Lab

AI-SIEM is a defensive cybersecurity engineering project that ingests logs, normalizes events, runs detection logic, correlates alerts into incidents, calculates metrics, and exposes the result through a FastAPI API and lightweight SOC dashboard.

The project now supports **real local log ingestion** through a Linux log agent and **SQLite persistence**. It can still bootstrap with bundled sample logs for first-run demo purposes, but new ingested events are stored in `data/ai_siem.db` and survive backend restarts.

This is not an enterprise SIEM replacement. It is a realistic portfolio lab that demonstrates SOC platform architecture, backend engineering, parser design, detection engineering, API security, and operational thinking.

## Architecture

```mermaid
flowchart LR
    A[Linux/Auth/Web log files] --> B[Linux log agent]
    C[JSON events / API clients] --> D[/api/ingest]
    B --> D
    D --> E[Parser / normalization]
    E --> F[SQLite event store]
    F --> G[Detection engine]
    G --> H[Alerts]
    H --> I[Correlation engine]
    I --> J[Incidents]
    F --> K[Explainable anomalies]
    F --> L[Metrics]
    L --> M[FastAPI API]
    M --> N[SOC Dashboard]
```

## Main features

- FastAPI backend with SOC-focused endpoints.
- Constant-time Bearer-token authentication with `AI_SIEM_API_KEY`.
- CORS support for the dashboard, including browser preflight requests.
- SQLite event persistence in `data/ai_siem.db` by default.
- Persistent analyst triage records with validated actions and alert references.
- Real log tailing agent for Linux auth logs and web access logs.
- Ingest limits for total request size, event size, batch size, and loaded events.
- Duplicate event-ID suppression across memory and SQLite.
- Thread-safe per-client rate limiting with proxy headers disabled by default.
- Sanitized audit logging to `logs/audit.log` without logging secrets.
- Parser statistics for unknown/unsupported formats.
- Rule-based detections mapped to MITRE ATT&CK tactics and techniques.
- Linear-time sliding detection windows and cached SOC analysis snapshots.
- MITRE ATT&CK coverage summary for implemented rule metadata.
- Alert suppression and duplicate-noise reduction for rare-source-IP events.
- Correlated incidents with related alert IDs, evidence summaries, and timelines.
- Lightweight statistical anomaly scoring with clear reasons and contributing features.
- Tab-scoped dashboard authentication, output escaping, and real activity charts.
- Hardened Docker Compose deployment and security CI.

## Security model

All endpoints except `GET /api/health` require:

```http
Authorization: Bearer <token>
```

Set the key before running the backend:

```bash
export AI_SIEM_API_KEY='dev-token'
```

Fish shell:

```fish
set -x AI_SIEM_API_KEY dev-token
```

Example:

```bash
curl -H "Authorization: Bearer dev-token" http://localhost:8000/api/events
```

The dashboard has a connection screen for the API URL and key. The key is kept
in `sessionStorage`, so it is scoped to the current browser tab and cleared when
that tab closes. Remote API URLs must use HTTPS; HTTP is accepted only for
localhost development.

`X-Forwarded-For` is ignored unless `AI_SIEM_TRUST_PROXY_HEADERS=true`. Enable
that setting only when the backend is reachable exclusively through a trusted
reverse proxy.

### Security-related configuration

| Variable | Default | Purpose |
|---|---:|---|
| `AI_SIEM_API_KEY` | empty | Required API secret |
| `AI_SIEM_RATE_LIMIT_PER_MINUTE` | `60` | Per-client global request limit |
| `AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE` | `10` | Per-client ingest request limit |
| `AI_SIEM_MAX_REQUEST_BYTES` | `1048576` | Maximum JSON request body |
| `AI_SIEM_MAX_EVENTS_PER_INGEST` | `100` | Maximum batch count |
| `AI_SIEM_MAX_RAW_LOG_BYTES` | `10240` | Maximum individual raw event |
| `AI_SIEM_MAX_IN_MEMORY_EVENTS` | `10000` | Analysis working-set limit |
| `AI_SIEM_TRUST_PROXY_HEADERS` | `false` | Trust validated proxy client IPs |

## Run backend locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export AI_SIEM_API_KEY='dev-token'
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Fish shell:

```fish
source .venv/bin/activate.fish
set -x AI_SIEM_API_KEY dev-token
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://localhost:8000/api/health
```

Storage stats:

```bash
curl -H "Authorization: Bearer dev-token" http://localhost:8000/api/storage/stats
```

ATT&CK coverage summary:

```bash
curl -H "Authorization: Bearer dev-token" http://localhost:8000/api/coverage/attack
```

## Run frontend

```bash
cd frontend
python -m http.server 5173
```

Open:

```text
http://localhost:5173
```

Enter `http://localhost:8000` and the configured API key in the connection
screen. No browser DevTools setup is required.

Alternatively, start both services with the checked startup script:

```bash
export AI_SIEM_API_KEY='replace-with-a-strong-random-key'
./start.sh
```

## Real log ingestion

Start the backend first, then run the agent.

Keep the token out of the process list by setting it in the environment:

```bash
export AI_SIEM_API_KEY='dev-token'
```

Linux auth logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/auth.log \
  --api http://localhost:8000
```

Kali/RHEL/Fedora-style auth logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/secure \
  --api http://localhost:8000
```

Web access logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/nginx/access.log \
  --file /var/log/apache2/access.log \
  --api http://localhost:8000
```

To ingest an existing lab log file from the beginning:

```bash
python agents/linux_log_agent.py \
  --file ./lab/auth.log \
  --from-start \
  --api http://localhost:8000
```

The agent stores offsets atomically in `.agent_state/linux_offsets.json`. An
offset advances only after the backend accepts the batch, so a temporary
network/backend failure does not silently drop log lines. Redirects are not
followed, response reads are capped, and non-local remote APIs require HTTPS.

## Manual real-event test

You can also send one real-looking log line directly:

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"logs":["Jun 12 14:40:00 kali sshd[1234]: Failed password for invalid user root from 203.0.113.10 port 45678 ssh2"]}'
```

Then refresh the dashboard and check Events, Alerts, Metrics, and Storage stats.

## API endpoints

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | public | Backend status |
| `GET` | `/api/events` | required | Normalized events |
| `GET` | `/api/alerts` | required | Detection alerts |
| `GET` | `/api/incidents` | required | Correlated incidents |
| `GET` | `/api/incidents/{incident_id}` | required | One incident by ID |
| `GET` | `/api/rules` | required | Rule definitions |
| `GET` | `/api/coverage/attack` | required | MITRE ATT&CK coverage by rule metadata |
| `GET` | `/api/metrics` | required | SOC metrics and parser failure count |
| `GET` | `/api/anomalies` | required | Explainable anomalies |
| `GET` | `/api/parser/stats` | required | Parser visibility stats |
| `GET` | `/api/storage/stats` | required | SQLite storage statistics |
| `GET` | `/api/triage` | required | Recent persisted triage records |
| `POST` | `/api/ingest` | required | Ingest events/logs |
| `POST` | `/api/triage` | required | Record validated analyst triage |

List endpoints accept bounded `offset` and `limit` query parameters.

## Detection coverage

| Rule ID | Detection | Severity | MITRE tactic | MITRE technique |
|---|---|---:|---|---|
| `DET-SSH-001` | SSH brute force from one source IP | High | Credential Access | `T1110` |
| `DET-SSH-002` | Successful login after multiple failures | High | Initial Access | `T1078` |
| `DET-SSH-003` | SSH password spraying across multiple users from one source IP | High | Credential Access | `T1110.003` |
| `DET-PS-001` | Encoded or suspicious PowerShell execution | Critical | Execution | `T1059.001` |
| `DET-NET-001` | Internal port scan across multiple destinations | Medium | Discovery | `T1046` |
| `DET-WIN-001` | Admin account creation or group change | Critical | Persistence | `T1136` |
| `DET-WAF-001` | SQL injection indicators in WAF/web requests | High | Initial Access | `T1190` |
| `DET-BEH-001` | Rare external source IP for user | Medium | Initial Access | `T1078` |
| `DET-BEH-002` | Off-hours privileged access | Medium | Privilege Escalation | `T1078` |

## MITRE ATT&CK coverage report

`GET /api/coverage/attack` summarizes implemented detection-rule metadata by ATT&CK tactic and technique. It is useful for SOC roadmap work because it shows where the current rule set is concentrated and where coverage is still thin.

The report is intentionally honest: it reflects implemented rule metadata only. It does not prove that every required telemetry source is connected, that every ATT&CK procedure is detected, or that rules are tuned for a production environment.

Example fields:

```json
{
  "total_rules": 7,
  "tactics": [{"tactic": "Initial Access", "rule_count": 2}],
  "techniques": [{"technique": "T1078", "tactic": "Initial Access", "rule_count": 1, "rules": ["DET-SSH-002"]}],
  "unmapped_rules": []
}
```

## Run tests and security checks

```bash
python -m compileall backend tests agents
AI_SIEM_API_KEY=test-token AI_SIEM_RATE_LIMIT_PER_MINUTE=1000 AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE=1000 python -m unittest discover tests -v
python -m pip install -r requirements-dev.txt
flake8 --select=F backend agents tests healthcheck.py
mypy --ignore-missing-imports backend/main.py backend/security.py backend/storage.py backend/detection.py backend/parser.py backend/anomaly.py agents/linux_log_agent.py
node --check frontend/app.js
bash -n start.sh
bandit -q -r backend agents healthcheck.py -lll
pip-audit -r requirements.txt
```

## Docker

```bash
export AI_SIEM_API_KEY='dev-token'
docker compose up --build
```

Docker hardening notes:

- Requires an explicit API key; there is no default deployment secret.
- Runs the backend as a non-root `appuser` with all Linux capabilities dropped.
- Uses read-only container filesystems with dedicated writable data/log volumes.
- Serves the static frontend through Nginx with a same-origin API proxy and
  browser security headers; no nonexistent Node/Vite build is required.
- Binds host ports to `127.0.0.1` by default.
- Adds a backend `HEALTHCHECK` and waits for it before starting the frontend.
- Uses `.dockerignore` to keep secrets, Git metadata, logs, venvs, and node modules out of the build context.

## Current limitations

- SQLite is good for the lab but not for distributed production SIEM scale.
- No RBAC or multi-user authorization model yet.
- Docker is localhost-only by default; production still needs managed TLS and a
  secrets manager at the deployment edge.
- Parsers cover practical common formats but are not full ECS/OCSF coverage.
- No Sigma import/export yet.
- Anomaly detection is explainable/statistical, not enterprise ML.

## Roadmap

- Add Windows Event Log collector.
- Add Sysmon parser and Windows Event IDs 4624/4625/4688/4104/4720/4732.
- Add Sigma rule import/export.
- Add RBAC-backed analyst identities and case ownership.
- Add dashboard filters and full incident-state transitions.
- Add PostgreSQL or OpenSearch backend option.
