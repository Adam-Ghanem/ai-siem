# AI-SIEM

> **A defensive, explainable SIEM platform for turning security telemetry into actionable SOC intelligence.**

<p align="center">
  <img src="https://img.shields.io/github/license/Adam-Ghanem/ai-siem" alt="License">
  <img src="https://img.shields.io/github/stars/Adam-Ghanem/ai-siem" alt="GitHub stars">
  <img src="https://img.shields.io/github/commit-activity/m/Adam-Ghanem/ai-siem" alt="Commit activity">
</p>

AI-SIEM is a defensive security platform that ingests logs, normalizes events, detects threats, correlates alerts into incidents, calculates SOC metrics, and exposes the results through a **FastAPI backend and lightweight SOC dashboard**.

It combines deterministic detection engineering with explainable anomaly analysis, MITRE ATT&CK context, durable event storage, analyst triage, and real local Linux log ingestion.

## ⚡ Highlights

- 🛡️ Rule-based threat detection with severity and confidence
- 🧩 Event normalization across security log sources
- 🔗 Alert correlation into incidents and timelines
- 🧠 Explainable statistical anomaly detection
- 🎯 MITRE ATT&CK tactic and technique mapping
- 📥 Real Linux auth and web log ingestion
- 💾 Durable SQLite event and analyst-triage persistence
- 📊 SOC metrics, parser statistics, and coverage reporting
- 🔐 Bearer authentication, rate limiting, audit logging, and bounded inputs
- 🌐 FastAPI API + lightweight SOC dashboard
- 🐳 Docker Compose support
- 🧪 Automated testing and security checks

## 🏗️ Architecture

```text
                    ┌──────────────────────────┐
                    │     Log Sources / API    │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │     Linux Log Agent      │
                    └────────────┬─────────────┘
                                 │
                         ┌───────▼────────┐
                         │ Ingestion API  │
                         └───────┬────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Parse & Normalize       │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Event Store         │
                    │        SQLite           │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
       ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
       │  Detection  │    │  Anomalies  │    │   Metrics   │
       │    Rules    │    │  Explainable│    │ & Coverage  │
       └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Correlation / Triage    │
                    │ Alerts → Incidents      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ FastAPI + SOC Dashboard │
                    └─────────────────────────┘
```

The architecture separates **collection, ingestion, normalization, persistence, detection, correlation, analytics, and analyst workflows** so each layer can be tested and evolved independently.

## 🧠 How It Works

```text
Telemetry
   ↓
Normalize
   ↓
Detect ───────→ MITRE ATT&CK context
   ↓
Correlate
   ↓
Prioritize
   ↓
Incident
   ↓
Analyst Triage
```

AI-SIEM is intentionally evidence-driven. Detection rules and anomaly scores explain **why** an event or incident was surfaced instead of hiding the decision behind an opaque score.

## 🎯 Detection Coverage

| Rule | Detection | Severity | ATT&CK |
|---|---|---:|---|
| `DET-SSH-001` | SSH brute force | High | `T1110` |
| `DET-SSH-002` | Login after repeated failures | High | `T1078` |
| `DET-SSH-003` | SSH password spraying | High | `T1110.003` |
| `DET-PS-001` | Suspicious PowerShell execution | Critical | `T1059.001` |
| `DET-NET-001` | Internal port scanning | Medium | `T1046` |
| `DET-WIN-001` | Admin account/group changes | Critical | `T1136` |
| `DET-WAF-001` | SQL injection indicators | High | `T1190` |
| `DET-AI-001` | Rare external source IP | Medium | `T1078` |
| `DET-AI-002` | Off-hours privileged access | Medium | `T1078` |

MITRE coverage is generated from implemented rule metadata; it does not claim complete enterprise ATT&CK coverage.

## 🔐 Security Model

Sensitive API operations require bearer authentication:

```http
Authorization: Bearer <token>
```

The platform also includes:

- Bounded request and ingestion limits
- Per-IP rate limiting
- Request IDs and audit records
- Secret-safe logging
- Input validation and pagination limits
- Proxy-header trust controls
- Non-root Docker execution
- Dependency and security scanning

> **Defensive use only:** deploy and test AI-SIEM against systems and telemetry you are authorized to monitor.

## 🚀 Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export AI_SIEM_API_KEY='dev-token'
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://localhost:8000/api/health
```

Start the dashboard:

```bash
cd frontend
python -m http.server 5173
```

Then open `http://localhost:5173`.

## 📥 Real Log Ingestion

Linux authentication logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/auth.log \
  --api http://localhost:8000 \
  --token dev-token
```

Existing lab logs can be replayed from the beginning with `--from-start`.

## 🔌 API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service health |
| `GET` | `/api/events` | Normalized events |
| `GET` | `/api/alerts` | Detection alerts |
| `GET` | `/api/incidents` | Correlated incidents |
| `GET` | `/api/metrics` | SOC metrics |
| `GET` | `/api/anomalies` | Explainable anomalies |
| `GET` | `/api/rules` | Detection rules |
| `GET` | `/api/coverage/attack` | ATT&CK coverage |
| `POST` | `/api/ingest` | Ingest telemetry |
| `POST` | `/api/triage` | Record analyst triage |

## 🧱 Built With

- **Python**
- **FastAPI**
- **SQLite**
- Lightweight JavaScript dashboard
- MITRE ATT&CK metadata
- Docker Compose
- Automated tests and security tooling

## 🏅 Engineering Quality

The project includes automated testing, Python source validation, dependency auditing, Bandit security analysis, secret scanning, bounded input handling, and Docker hardening checks.

Run the local test suite:

```bash
python -m compileall backend tests agents
python -m unittest discover tests -v
bandit -q -r backend agents -lll
pip-audit -r requirements.txt
```

## 📄 License

AI-SIEM is released under the **MIT License**. See [`LICENSE`](LICENSE) for the full license text.

## 🔭 Vision

AI-SIEM is designed as a practical foundation for a modern SOC: **collect telemetry, explain detections, correlate incidents, help analysts prioritize, and keep security decisions grounded in evidence.**

The long-term direction is to evolve from a portfolio-scale defensive platform toward richer telemetry, investigation workflows, detection-as-code, scalable storage, and analyst-focused automation.

## 🤝 Contributing

Contributions, detection ideas, parser improvements, security fixes, and SOC workflow experiments are welcome.

---

<p align="center">
  <strong>AI-SIEM</strong><br>
  <em>From telemetry to actionable security intelligence.</em>
</p>
