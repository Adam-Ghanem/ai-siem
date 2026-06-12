# AI-SIEM — Live SOC Command Center

AI-SIEM is a cybersecurity portfolio project for SOC analyst and junior detection engineering practice. It is not an enterprise SIEM replacement and does not claim production readiness. The project demonstrates a realistic mini-pipeline: log ingestion, parsing, normalized events, rule-based detections, alert correlation, explainable anomaly scoring, calculated metrics, Docker, and unit tests.

## What it does

- Parses mixed Linux auth, Windows/PowerShell, firewall, WAF/web, and normalized JSON events.
- Normalizes events into a consistent schema.
- Runs detections using field matching, contains, regex, thresholds, time windows, and group-by fields.
- Maps detections to MITRE ATT&CK tactic and technique.
- Correlates alerts into incidents using real relationships: same asset, user, source IP, tactic, and time proximity.
- Calculates metrics from current in-memory events instead of hardcoded formulas.
- Generates explainable statistical anomalies.
- Exposes FastAPI endpoints and a Vite frontend.

## Event schema

`id`, `timestamp`, `source`, `event_type`, `asset`, `user`, `src_ip`, `dst_ip`, `process_name`, `command_line`, `status`, `message`, `raw_log`.

## API endpoints

- `GET /api/health`
- `GET /api/events`
- `GET /api/alerts`
- `GET /api/incidents`
- `GET /api/incidents/{incident_id}`
- `GET /api/rules`
- `GET /api/metrics`
- `GET /api/anomalies`
- `GET /api/triage`
- `POST /api/ingest`
- `POST /api/triage`

## Detection examples

| Rule | Logic | MITRE |
|---|---|---|
| SSH brute force | 5 failed SSH logins from same `src_ip` in 5 minutes | T1110 |
| Success after failures | successful SSH login after multiple failures | T1078 |
| Encoded PowerShell | command line contains encoded/bypass indicators | T1059.001 |
| Internal port scan | same source reaches many destinations quickly | T1046 |
| Admin account creation | Windows account/admin group change | T1136 |
| SQL injection | WAF/web request matches SQLi regex | T1190 |
| Rare source IP | user logs in from a new source | T1078 |
| Off-hours privileged access | root/admin success outside business hours | T1078 |

## Run locally

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## Run tests

```bash
python -m unittest discover tests
```

## Run with Docker

```bash
docker compose up --build
```

Backend: `http://localhost:8000`
Frontend: `http://localhost:5173`

## Configuration

- `AI_SIEM_HOST` default: `0.0.0.0`
- `AI_SIEM_PORT` default: `8000`
- `AI_SIEM_ALLOWED_ORIGIN` default: `http://localhost:5173`

CORS is environment-configured and is not wildcard by default.

## Limitations

- In-memory storage only.
- Parsers are practical examples, not full ECS/OCSF coverage.
- No authentication or API keys yet.
- No database persistence yet.
- No Sigma rule import/export yet.
- Anomaly detection is explainable/statistical, not enterprise ML.

## Roadmap

- Add SQLite/PostgreSQL persistence.
- Add authentication and API keys.
- Add ECS/OCSF mapping.
- Add Sigma import/export.
- Add analyst notes and audit trail.
- Add rule suppression/tuning workflow.
