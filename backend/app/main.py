from __future__ import annotations
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .parsers import parse_log
from .detection import detect
from .correlation import correlate
from .anomaly import detect_anomalies
from .rules import RULES
from .sample_data import sample_logs
from .models import NormalizedEvent

class IngestRequest(BaseModel):
    logs: list[str] = []
    events: list[NormalizedEvent] = []

class TriageRequest(BaseModel):
    incident_id: str | None = None
    alert_id: str | None = None
    action: str
    analyst: str = 'analyst'
    notes: str = ''

app = FastAPI(title='AI-SIEM SOC Command Center', version='2.0.0')
origins = [x.strip() for x in os.getenv('ALLOWED_ORIGINS','http://localhost:5173,http://localhost:3000').split(',')]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=['GET','POST'], allow_headers=['*'])

EVENTS: list[NormalizedEvent] = [parse_log(x) for x in sample_logs()]
TRIAGE: list[dict] = []

def current_state():
    alerts = detect(EVENTS)
    incidents = correlate(alerts)
    anomalies = detect_anomalies(EVENTS)
    return alerts, incidents, anomalies

@app.get('/api/health')
def health():
    return {'status':'ok','service':'AI-SIEM','events_loaded':len(EVENTS),'cors_origins':origins}

@app.get('/api/events')
def get_events(source: str | None = None, asset: str | None = None, user: str | None = None):
    data = EVENTS
    if source: data = [e for e in data if e.source == source]
    if asset: data = [e for e in data if e.asset == asset]
    if user: data = [e for e in data if e.user == user]
    return data

@app.get('/api/alerts')
def get_alerts(severity: str | None = None, asset: str | None = None, user: str | None = None, tactic: str | None = None):
    data = current_state()[0]
    if severity: data = [a for a in data if a.severity == severity]
    if asset: data = [a for a in data if a.asset == asset]
    if user: data = [a for a in data if a.user == user]
    if tactic: data = [a for a in data if a.tactic == tactic]
    return data

@app.get('/api/incidents')
def get_incidents():
    return current_state()[1]

@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id: str):
    for inc in current_state()[1]:
        if inc.incident_id == incident_id:
            return inc
    raise HTTPException(status_code=404, detail='Incident not found')

@app.get('/api/rules')
def get_rules():
    return RULES

@app.get('/api/anomalies')
def get_anomalies():
    return current_state()[2]

@app.get('/api/metrics')
def get_metrics():
    alerts, incidents, anomalies = current_state()
    return {'total_events':len(EVENTS),'total_alerts':len(alerts),'total_incidents':len(incidents),'total_anomalies':len(anomalies),'critical_alerts':sum(1 for a in alerts if a.severity=='critical'),'high_alerts':sum(1 for a in alerts if a.severity=='high')}

@app.post('/api/ingest')
def ingest(payload: IngestRequest):
    if not payload.logs and not payload.events:
        raise HTTPException(status_code=400, detail='Provide logs or events')
    parsed = [parse_log(x) for x in payload.logs] + payload.events
    EVENTS.extend(parsed)
    return {'ingested':len(parsed),'total_events':len(EVENTS)}

@app.post('/api/triage')
def triage(payload: TriageRequest):
    if not payload.incident_id and not payload.alert_id:
        raise HTTPException(status_code=400, detail='incident_id or alert_id is required')
    TRIAGE.append(payload.model_dump())
    return {'status':'recorded','triage':payload.model_dump()}
