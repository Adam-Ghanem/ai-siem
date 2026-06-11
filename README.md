# AI-SIEM — Live SOC Command Center

<p align="center">
  <img src="frontend/assets/logo.svg" alt="AI-SIEM Logo" width="180" />
</p>

<p align="center">
  <strong>Professional zero-dependency AI-SIEM/SOC platform for security monitoring, detection engineering, incident triage, MITRE ATT&CK mapping, and response workflows.</strong>
</p>

---

## Overview

**AI-SIEM** is a full-stack cybersecurity engineering project that simulates a real Security Operations Center platform. It provides a live SOC dashboard, backend API, detection engine, parser layer, incident correlation, triage logic, MITRE ATT&CK mapping, and response workflows.

The project is intentionally simple to run and professional to present. It uses **only Python standard library + HTML/CSS/JavaScript**.

No npm. No pip. No venv. No React. No external services.

---

## Features

- Live SOC dashboard as the first screen
- Backend API using Python standard library only
- Pure HTML/CSS/JavaScript frontend
- Alert queue with severity, confidence, asset, source, and MITRE tactic
- Live Analysis button for analyst-style triage
- Incident lifecycle view
- MITRE ATT&CK coverage panel
- Detection rules inventory
- Parser catalog
- Dashboards catalog
- Response workflows
- Professional dark enterprise design
- One-command startup script

---

## Project Structure

```text
ai-siem/
├── README.md
├── start.sh
├── start.bat
├── backend/
│   ├── main.py
│   └── engine/
│       ├── __init__.py
│       ├── parser.py
│       ├── detections.py
│       ├── correlation.py
│       └── triage.py
├── frontend/
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   └── assets/
│       └── logo.svg
├── data/
│   └── sample_logs.json
├── dashboards/
│   ├── soc_overview.json
│   ├── mitre_coverage.json
│   └── incident_response.json
├── detections/
│   ├── ssh_bruteforce.yml
│   ├── suspicious_powershell.yml
│   ├── port_scan.yml
│   ├── admin_account_created.yml
│   └── sql_injection.yml
├── parsers/
│   ├── linux_auth.conf
│   ├── windows_event.conf
│   ├── firewall_syslog.conf
│   └── cloudtrail.conf
├── workflows/
│   ├── block_ip.yml
│   ├── isolate_host.yml
│   └── reset_user_password.yml
└── docs/
    ├── architecture.md
    ├── detection-engine.md
    └── runbook.md
```

---

## Run the Project

### Linux / Kali / Git Bash

```bash
bash start.sh
```

### Windows CMD

```bat
start.bat
```

Then open:

```text
http://localhost:5173
```

Backend API:

```text
http://localhost:8000/api
```

---

## Manual Run

Terminal 1:

```bash
cd backend
python main.py
```

Terminal 2:

```bash
cd frontend
python -m http.server 5173
```

Open:

```text
http://localhost:5173
```

---

## API Endpoints

```text
GET  /api/health
GET  /api/metrics
GET  /api/logs
GET  /api/alerts
GET  /api/incidents
GET  /api/detections
GET  /api/parsers
GET  /api/dashboards
GET  /api/workflows
GET  /api/reports/summary
POST /api/triage
```

---

## SOC Workflow

```text
Raw Logs
   ↓
Parser Layer
   ↓
Detection Engine
   ↓
Alert Generation
   ↓
Correlation Engine
   ↓
Incident Creation
   ↓
Live Analysis + Response Workflow
```

---

## Detection Coverage

Current detections include:

- SSH brute force
- Suspicious PowerShell execution
- Internal port scan
- Admin account creation
- SQL injection attempt

---

## Portfolio Positioning

This project demonstrates:

- SOC analyst workflow understanding
- SIEM architecture fundamentals
- Detection engineering concepts
- API design
- Frontend dashboard design
- MITRE ATT&CK mapping
- Incident response runbooks
- Clean repository organization

---

## Author

**Adam Ghanem**  
Cybersecurity & Networks Student
