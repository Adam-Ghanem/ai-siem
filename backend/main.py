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
from .coverage import generate_attack_coverage
from .detection import run_detections
from .metrics import calculate_metrics
from .parser import parse_events, parser_stats
from .rules import RULES
from .security import MAX_EVENTS_PER_INGEST, MAX_IN_MEMORY_EVENTS, MAX_RAW_LOG_BYTES, audit_log, enforce_auth, enforce_rate_limit
from .storage import init_db, load_events as load_stored_events, save_events, stats as storage_stats

AI_SIEM_HOST=os.getenv('AI_SIEM_HOST','0.0.0.0')
AI_SIEM_PORT=int(os.getenv('AI_SIEM_PORT','8000'))
AI_SIEM_ALLOWED_ORIGIN=os.getenv('AI_SIEM_ALLOWED_ORIGIN','http://localhost:5173')
AI_SIEM_STORAGE=os.getenv('AI_SIEM_STORAGE','sqlite').lower()
DATA_FILE=Path(__file__).resolve().parents[1]/'data'/'sample_logs.json'

app=FastAPI(title='AI-SIEM Live SOC Command Center',version='3.3.0')
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in AI_SIEM_ALLOWED_ORIGIN.split(',') if x.strip()],allow_credentials=False,allow_methods=['GET','POST','OPTIONS'],allow_headers=['content-type','authorization'])
TRIAGE=[]

def _load_sample_events():
    if DATA_FILE.exists(): return parse_events(json.loads(DATA_FILE.read_text(encoding='utf-8')))
    return []

def load_events():
    if AI_SIEM_STORAGE=='sqlite':
        init_db()
        stored=load_stored_events(limit=MAX_IN_MEMORY_EVENTS)
        if stored: return stored
        sample=_load_sample_events()
        save_events(sample)
        return sample
    return _load_sample_events()
EVENTS=load_events()
def alerts(): return run_detections(EVENTS)
def incidents(): return correlate(alerts())
def anomalies(): return detect_anomalies(EVENTS)

@app.middleware('http')
async def security_middleware(request:Request, call_next):
    if request.method == 'OPTIONS':
        return await call_next(request)
    try:
        enforce_rate_limit(request)
        enforce_auth(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code,content={'detail':exc.detail})
    return await call_next(request)

@app.exception_handler(RequestValidationError)
async def validation_error(request:Request, exc:RequestValidationError):
    audit_log(request,'validation','failed')
    return JSONResponse(status_code=400,content={'detail':'Invalid request format','errors':exc.errors()})
@app.exception_handler(ValueError)
async def value_error(request:Request, exc:ValueError):
    audit_log(request,'validation','failed')
    return JSONResponse(status_code=400,content={'detail':str(exc)})

@app.get('/api/health')
def health(): return {'status':'ok','service':'AI-SIEM','events_loaded':len(EVENTS),'allowed_origin':AI_SIEM_ALLOWED_ORIGIN,'storage':AI_SIEM_STORAGE}
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
def get_incidents(status:str|None=None,priority:str|None=None):
    data=incidents()
    if status: data=[i for i in data if i.status==status]
    if priority: data=[i for i in data if i.priority==priority]
    return [i.to_dict() for i in data]
@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id:str):
    for i in incidents():
        if i.incident_id==incident_id: return i.to_dict()
    raise HTTPException(status_code=404,detail='Incident not found')
@app.get('/api/anomalies')
def get_anomalies(): return [a.to_dict() for a in anomalies()]
@app.get('/api/rules')
def get_rules(): return [r if isinstance(r,dict) else r.__dict__ for r in RULES]
@app.get('/api/coverage/attack')
def get_attack_coverage(): return generate_attack_coverage(get_rules())
@app.get('/api/metrics')
def get_metrics():
    m=calculate_metrics(EVENTS,alerts(),incidents())
    m['parsing_failed_events']=parser_stats()['unknown_events']
    return m
@app.get('/api/parser/stats')
def get_parser_stats(): return parser_stats()
@app.get('/api/storage/stats')
def get_storage_stats(): return storage_stats() if AI_SIEM_STORAGE=='sqlite' else {'backend':'memory','stored_events':len(EVENTS)}

def _extract_items(payload:Any):
    if isinstance(payload,dict):
        if 'logs' in payload: items=payload['logs']
        elif 'events' in payload: items=payload['events']
        else: items=[payload]
    elif isinstance(payload,list): items=payload
    else: raise ValueError('Request body must be JSON object or list')
    if len(items)>MAX_EVENTS_PER_INGEST: raise HTTPException(status_code=413,detail=f'Maximum {MAX_EVENTS_PER_INGEST} events per ingest request')
    if len(EVENTS)+len(items)>MAX_IN_MEMORY_EVENTS: raise HTTPException(status_code=413,detail=f'Maximum in-memory event capacity {MAX_IN_MEMORY_EVENTS} reached')
    for item in items:
        raw=item if isinstance(item,str) else json.dumps(item,separators=(',',':'))
        if len(raw.encode('utf-8'))>MAX_RAW_LOG_BYTES: raise HTTPException(status_code=413,detail=f'Maximum raw event size is {MAX_RAW_LOG_BYTES} bytes')
    return items
@app.post('/api/ingest')
async def ingest(request:Request):
    try: payload=await request.json()
    except Exception:
        audit_log(request,'ingest','invalid_json')
        raise HTTPException(status_code=400,detail='Invalid JSON body')
    items=_extract_items(payload)
    parsed=parse_events(items); EVENTS.extend(parsed)
    if AI_SIEM_STORAGE=='sqlite': save_events(parsed)
    audit_log(request,'ingest','success',f'count={len(parsed)}')
    return {'ingested':len(parsed),'total_events':len(EVENTS),'storage':AI_SIEM_STORAGE}
@app.post('/api/triage')
async def triage(request:Request):
    try: payload=await request.json()
    except Exception:
        audit_log(request,'triage','invalid_json')
        raise HTTPException(status_code=400,detail='Invalid JSON body')
    if not isinstance(payload,dict) or not payload.get('alert_id') or not payload.get('action'): raise HTTPException(status_code=400,detail='alert_id and action are required')
    record={'alert_id':payload['alert_id'],'action':payload['action'],'analyst':payload.get('analyst','frontend'),'status':'recorded'}; TRIAGE.append(record)
    audit_log(request,'triage','success',f"alert_id={payload['alert_id']}")
    return record
