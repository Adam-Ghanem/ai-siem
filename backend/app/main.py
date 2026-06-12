from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.engine.rules import RULES
from backend.engine.store import SIEMStore

HOST = os.getenv('AI_SIEM_HOST', '0.0.0.0')
PORT = int(os.getenv('AI_SIEM_PORT', '8000'))
ALLOWED_ORIGIN = os.getenv('AI_SIEM_ALLOWED_ORIGIN', 'http://localhost:5173')

app = FastAPI(title='AI-SIEM Live SOC Command Center', version='3.1.0')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGIN.split(',') if origin.strip()],
    allow_credentials=False,
    allow_methods=['GET', 'POST'],
    allow_headers=['content-type', 'authorization'],
)
store = SIEMStore()

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={'detail': 'Invalid request format', 'errors': exc.errors()})

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={'detail': str(exc)})

@app.get('/api/health')
def health():
    return {'status': 'ok', 'service': 'AI-SIEM', 'version': '3.1.0', 'events_loaded': len(store.events), 'allowed_origin': ALLOWED_ORIGIN}

@app.get('/api/events')
def get_events(source: str | None = None, event_type: str | None = None, asset: str | None = None, user: str | None = None, src_ip: str | None = None):
    data = store.events
    if source: data = [e for e in data if e.source == source]
    if event_type: data = [e for e in data if e.event_type == event_type]
    if asset: data = [e for e in data if e.asset == asset]
    if user: data = [e for e in data if e.user == user]
    if src_ip: data = [e for e in data if e.src_ip == src_ip]
    return [e.to_dict() for e in data]

@app.get('/api/alerts')
def get_alerts(severity: str | None = None, tactic: str | None = None, asset: str | None = None, user: str | None = None, src_ip: str | None = None):
    data = store.alerts()
    if severity: data = [a for a in data if a.severity == severity]
    if tactic: data = [a for a in data if a.tactic == tactic]
    if asset: data = [a for a in data if a.asset == asset]
    if user: data = [a for a in data if a.user == user]
    if src_ip: data = [a for a in data if a.src_ip == src_ip]
    return [a.to_dict() for a in data]

@app.get('/api/incidents')
def get_incidents():
    return [i.to_dict() for i in store.incidents()]

@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id: str):
    for incident in store.incidents():
        if incident.incident_id == incident_id:
            return incident.to_dict()
    raise HTTPException(status_code=404, detail='Incident not found')

@app.get('/api/rules')
def get_rules():
    return RULES

@app.get('/api/rules/{rule_id}')
def get_rule(rule_id: str):
    for rule in RULES:
        if rule['rule_id'] == rule_id:
            return rule
    raise HTTPException(status_code=404, detail='Rule not found')

@app.get('/api/metrics')
def get_metrics():
    return store.metrics()

@app.get('/api/anomalies')
def get_anomalies():
    return [a.to_dict() for a in store.anomalies()]

@app.get('/api/mitre')
def get_mitre_coverage():
    return store.coverage()

@app.get('/api/triage')
def get_triage_records():
    return store.triage_records

@app.get('/api/export')
def export_snapshot():
    return store.snapshot()

@app.post('/api/ingest')
async def ingest(request: Request):
    try:
        payload: Any = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail='Invalid JSON body') from exc
    count = store.ingest(payload)
    return {'ingested': count, 'total_events': len(store.events)}

@app.post('/api/triage')
async def triage(request: Request):
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail='Invalid JSON body') from exc
    record = store.triage(payload)
    return record
