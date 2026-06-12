from __future__ import annotations
import json, os
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .anomaly import detect_anomalies
from .correlation import correlate
from .detection import run_detections
from .metrics import calculate_metrics
from .parser import parse_events
from .rules import RULES

AI_SIEM_HOST=os.getenv('AI_SIEM_HOST','0.0.0.0')
AI_SIEM_PORT=int(os.getenv('AI_SIEM_PORT','8000'))
AI_SIEM_ALLOWED_ORIGIN=os.getenv('AI_SIEM_ALLOWED_ORIGIN','http://localhost:5173')
DATA_FILE=Path(__file__).resolve().parents[1]/'data'/'sample_logs.json'

app=FastAPI(title='AI-SIEM Live SOC Command Center',version='3.0.0')
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in AI_SIEM_ALLOWED_ORIGIN.split(',') if x.strip()],allow_credentials=False,allow_methods=['GET','POST'],allow_headers=['content-type','authorization'])
TRIAGE=[]

def load_events():
    if DATA_FILE.exists(): return parse_events(json.loads(DATA_FILE.read_text(encoding='utf-8')))
    return []
EVENTS=load_events()
def alerts(): return run_detections(EVENTS)
def incidents(): return correlate(alerts())
def anomalies(): return detect_anomalies(EVENTS)

@app.exception_handler(RequestValidationError)
async def validation_error(request:Request, exc:RequestValidationError): return JSONResponse(status_code=400,content={'detail':'Invalid request format','errors':exc.errors()})
@app.exception_handler(ValueError)
async def value_error(request:Request, exc:ValueError): return JSONResponse(status_code=400,content={'detail':str(exc)})

@app.get('/api/health')
def health(): return {'status':'ok','service':'AI-SIEM','events_loaded':len(EVENTS),'allowed_origin':AI_SIEM_ALLOWED_ORIGIN}
@app.get('/api/events')
def get_events(source:str|None=None,event_type:str|None=None,asset:str|None=None,user:str|None=None,src_ip:str|None=None):
    data=EVENTS
    if source: data=[e for e in data if e.source==source]
    if event_type: data=[e for e in data if e.event_type==event_type]
    if asset: data=[e for e in data if e.asset==asset]
    if user: data=[e for e in data if e.user==user]
    if src_ip: data=[e for e in data if e.src_ip==src_ip]
    return [e.to_dict() for e in data]
@app.get('/api/alerts')
def get_alerts(severity:str|None=None,tactic:str|None=None,asset:str|None=None,user:str|None=None,src_ip:str|None=None):
    data=alerts()
    if severity: data=[a for a in data if a.severity==severity]
    if tactic: data=[a for a in data if a.tactic==tactic]
    if asset: data=[a for a in data if a.asset==asset]
    if user: data=[a for a in data if a.user==user]
    if src_ip: data=[a for a in data if a.src_ip==src_ip]
    return [a.to_dict() for a in data]
@app.get('/api/incidents')
def get_incidents(): return [i.to_dict() for i in incidents()]
@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id:str):
    for i in incidents():
        if i.incident_id==incident_id: return i.to_dict()
    raise HTTPException(status_code=404,detail='Incident not found')
@app.get('/api/rules')
def get_rules(): return RULES
@app.get('/api/metrics')
def get_metrics(): return calculate_metrics(EVENTS,alerts(),incidents())
@app.get('/api/anomalies')
def get_anomalies(): return [a.to_dict() for a in anomalies()]
@app.get('/api/triage')
def triage_history(): return TRIAGE
@app.post('/api/ingest')
async def ingest(request:Request):
    try: payload=await request.json()
    except Exception as exc: raise HTTPException(status_code=400,detail='Invalid JSON body') from exc
    if isinstance(payload,dict) and 'events' in payload: items=payload['events']
    elif isinstance(payload,dict) and 'logs' in payload: items=payload['logs']
    elif isinstance(payload,list): items=payload
    elif isinstance(payload,(str,dict)): items=[payload]
    else: raise ValueError('POST /api/ingest expects one event/log or a list under events/logs')
    parsed=parse_events(items); EVENTS.extend(parsed); return {'ingested':len(parsed),'total_events':len(EVENTS)}
@app.post('/api/triage')
async def triage(request:Request):
    try: payload=await request.json()
    except Exception as exc: raise HTTPException(status_code=400,detail='Invalid JSON body') from exc
    if not isinstance(payload,dict): raise ValueError('triage body must be a JSON object')
    if not payload.get('incident_id') and not payload.get('alert_id'): raise ValueError('triage requires incident_id or alert_id')
    if not payload.get('action'): raise ValueError('triage requires action')
    payload['status']='recorded'; TRIAGE.append(payload); return payload
