# AI-SIEM — Real SOC / AI-SIEM Portfolio Lab

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
- Bearer-token API authentication with `AI_SIEM_API_KEY`.
- CORS support for the dashboard, including browser preflight requests.
- SQLite event persistence in `data/ai_siem.db` by default.
- Real log tailing agent for Linux auth logs and web access logs.
- Ingest limits for request size, log size, and total loaded events.
- Simple in-memory per-IP rate limiting.
- Audit logging to `logs/audit.log` without logging secrets.
- Parser statistics for unknown/unsupported formats.
- Rule-based detections mapped to MITRE ATT&CK tactics and techniques.
- Alert suppression and AI-noise reduction for internal rare-source-IP events.
- Correlated incidents with related alert IDs, evidence summaries, and timelines.
- Lightweight statistical anomaly scoring with clear reasons and contributing features.
- Docker Compose support and security CI.

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

The frontend reads the token from browser localStorage:

```js
localStorage.setItem('AI_SIEM_API', 'http://localhost:8000')
localStorage.setItem('AI_SIEM_API_KEY', 'dev-token')
```

For WSL-to-Windows browser access, set `AI_SIEM_API` to your WSL IP, for example:

```js
localStorage.setItem('AI_SIEM_API', 'http://172.30.9.161:8000')
```

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

## Run frontend

```bash
cd frontend
python -m http.server 5173
```

Open:

```text
http://localhost:5173
```

Then configure localStorage from browser DevTools Console:

```js
localStorage.setItem('AI_SIEM_API', 'http://localhost:8000')
localStorage.setItem('AI_SIEM_API_KEY', 'dev-token')
location.reload()
```

## Real log ingestion

Start the backend first, then run the agent.

Linux auth logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/auth.log \
  --api http://localhost:8000 \
  --token dev-token
```

Kali/RHEL/Fedora-style auth logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/secure \
  --api http://localhost:8000 \
  --token dev-token
```

Web access logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/nginx/access.log \
  --file /var/log/apache2/access.log \
  --api http://localhost:8000 \
  --token dev-token
```

To ingest an existing lab log file from the beginning:

```bash
python agents/linux_log_agent.py \
  --file ./lab/auth.log \
  --from-start \
  --api http://localhost:8000 \
  --token dev-token
```

The agent stores offsets in `.agent_state/linux_offsets.json` so it does not resend the same lines every run.

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
| `GET` | `/api/metrics` | required | SOC metrics and parser failure count |
| `GET` | `/api/anomalies` | required | Explainable anomalies |
| `GET` | `/api/parser/stats` | required | Parser visibility stats |
| `GET` | `/api/storage/stats` | required | SQLite storage statistics |
| `POST` | `/api/ingest` | required | Ingest events/logs |
| `POST` | `/api/triage` | required | Record analyst triage |

## Detection coverage

| Rule ID | Detection | Severity | MITRE tactic | MITRE technique |
|---|---|---:|---|---|
| `DET-SSH-001` | SSH brute force from one source IP | High | Credential Access | `T1110` |
| `DET-SSH-002` | Successful login after multiple failures | High | Initial Access | `T1078` |
| `DET-PS-001` | Encoded or suspicious PowerShell execution | Critical | Execution | `T1059.001` |
| `DET-NET-001` | Internal port scan across multiple destinations | Medium | Discovery | `T1046` |
| `DET-WIN-001` | Admin account creation or group change | Critical | Persistence | `T1136` |
| `DET-WAF-001` | SQL injection indicators in WAF/web requests | High | Initial Access | `T1190` |
| `DET-AI-001` | Rare external source IP for user | Medium | Initial Access | `T1078` |
| `DET-AI-002` | Off-hours privileged access | Medium | Privilege Escalation | `T1078` |

## Run tests and security checks

```bash
python -m compileall backend tests agents
AI_SIEM_API_KEY=test-token AI_SIEM_RATE_LIMIT_PER_MINUTE=1000 AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE=1000 python -m unittest discover tests -v
bandit -q -r backend agents -lll
pip-audit -r requirements.txt
```

## Docker

```bash
export AI_SIEM_API_KEY='dev-token'
docker compose up --build
```

Docker hardening notes:

- Uses `python:3.11-slim`.
- Runs as a non-root `appuser`.
- Adds `HEALTHCHECK` for `/api/health`.
- Uses `.dockerignore` to keep secrets, Git metadata, logs, venvs, and node modules out of the build context.

## Current limitations

- SQLite is good for the lab but not for distributed production SIEM scale.
- No RBAC or multi-user authorization model yet.
- No TLS termination or secrets manager integration yet.
- Parsers cover practical common formats but are not full ECS/OCSF coverage.
- No Sigma import/export yet.
- Anomaly detection is explainable/statistical, not enterprise ML.

## Roadmap

- Add Windows Event Log collector.
- Add Sysmon parser and Windows Event IDs 4624/4625/4688/4104/4720/4732.
- Add Sigma rule import/export.
- Add analyst notes persisted in SQLite.
- Add dashboard filters and alert acknowledgement workflow.
- Add PostgreSQL or OpenSearch backend option.
