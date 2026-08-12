from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from .anomaly import detect_anomalies
from .correlation import correlate
from .coverage import generate_attack_coverage
from .ingestion import AsyncIngestionPipeline
from .detection import run_detections
from .metrics import calculate_metrics
from .parser import parse_events, parser_stats
from .rules import RULES
from .sigma import SigmaRuleError, export_sigma, import_sigma
from .threat_intel import CACHE_TTL_SECONDS, MAX_INDICATORS_PER_REQUEST, THREAT_INTEL, normalize_indicators
from .security import (
    MAX_EVENTS_PER_INGEST,
    MAX_IN_MEMORY_EVENTS,
    MAX_RAW_LOG_BYTES,
    audit_log,
    enforce_auth,
    enforce_permission,
    enforce_rate_limit,
)
from .storage_backends import build_storage_backend

AI_SIEM_HOST = os.getenv('AI_SIEM_HOST', '0.0.0.0')
AI_SIEM_PORT = int(os.getenv('AI_SIEM_PORT', '8000'))
AI_SIEM_ALLOWED_ORIGIN = os.getenv(
    'AI_SIEM_ALLOWED_ORIGIN',
    'http://localhost:5173',
)
AI_SIEM_STORAGE = os.getenv('AI_SIEM_STORAGE', 'sqlite').lower()
STORAGE = build_storage_backend(AI_SIEM_STORAGE)
MAX_PAGE_LIMIT = int(os.getenv('AI_SIEM_MAX_PAGE_LIMIT', '1000'))
DEFAULT_PAGE_LIMIT = int(os.getenv('AI_SIEM_DEFAULT_PAGE_LIMIT', str(MAX_PAGE_LIMIT)))
DATA_FILE = Path(__file__).resolve().parents[1] / 'data' / 'sample_logs.json'

app = FastAPI(title='AI-SIEM Live SOC Command Center', version='3.3.0')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in AI_SIEM_ALLOWED_ORIGIN.split(',')
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['content-type', 'authorization'],
)

TRIAGE = STORAGE.load_triage(limit=10000) if AI_SIEM_STORAGE != 'memory' else []
INGEST_BATCHES = STORAGE.load_ingest_batches(limit=10000) if AI_SIEM_STORAGE != 'memory' else []
INGESTION_PIPELINE = AsyncIngestionPipeline(
    storage_enabled=AI_SIEM_STORAGE != 'memory',
    persist_callback=STORAGE.save_events,
)


def _load_sample_events():
    if DATA_FILE.exists():
        events = parse_events(json.loads(DATA_FILE.read_text(encoding='utf-8')))
        for event in events:
            event.tenant_id = 'default'
        return events
    return []


def load_events():
    if AI_SIEM_STORAGE != 'memory':
        stored = STORAGE.load_events(limit=MAX_IN_MEMORY_EVENTS)
        if stored:
            return stored
        sample = _load_sample_events()
        STORAGE.save_events(sample)
        return sample
    return _load_sample_events()


EVENTS = load_events()


def _record_ingest_batch(record: dict) -> dict:
    if AI_SIEM_STORAGE != 'memory':
        return STORAGE.save_ingest_batch(record)
    INGEST_BATCHES.append(record)
    return record


def tenant_events(tenant_id: str) -> list:
    return [event for event in EVENTS if event.tenant_id == tenant_id]


def alerts(tenant_id: str | None = None):
    return run_detections(tenant_events(tenant_id) if tenant_id else EVENTS)


def incidents(tenant_id: str | None = None):
    return correlate(alerts(tenant_id))


def anomalies(tenant_id: str | None = None):
    return detect_anomalies(tenant_events(tenant_id) if tenant_id else EVENTS)


def _page(items, limit: int, offset: int, response: Response):
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f'limit must be between 1 and {MAX_PAGE_LIMIT}',
        )
    if offset < 0:
        raise HTTPException(status_code=400, detail='offset must be non-negative')
    total = len(items)
    response.headers['X-Total-Count'] = str(total)
    response.headers['X-Page-Limit'] = str(limit)
    response.headers['X-Page-Offset'] = str(offset)
    next_offset = offset + limit if offset + limit < total else ''
    response.headers['X-Next-Offset'] = str(next_offset)
    return items[offset:offset + limit]


@app.middleware('http')
async def security_middleware(request: Request, call_next):
    request.state.request_id = uuid4().hex
    try:
        if request.method != 'OPTIONS':
            enforce_rate_limit(request)
            context = enforce_auth(request)
            request.state.auth = context
            if context is not None:
                enforce_permission(request, context)
    except HTTPException as exc:
        response = JSONResponse(
            status_code=exc.status_code,
            content={'detail': exc.detail},
        )
        response.headers['X-Request-ID'] = request.state.request_id
        return response

    if not hasattr(request.state, 'auth'):
        request.state.auth = None
    response = await call_next(request)
    response.headers['X-Request-ID'] = request.state.request_id
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    audit_log(request, 'validation', 'failed')
    return JSONResponse(
        status_code=400,
        content={'detail': 'Invalid request format', 'errors': exc.errors()},
    )


@app.exception_handler(ValueError)
async def value_error(request: Request, exc: ValueError):
    audit_log(request, 'validation', 'failed')
    return JSONResponse(status_code=400, content={'detail': str(exc)})


@app.get('/api/health')
def health():
    return {
        'status': 'ok',
        'service': 'AI-SIEM',
        'events_loaded': len(EVENTS),
        'allowed_origin': AI_SIEM_ALLOWED_ORIGIN,
        'storage': AI_SIEM_STORAGE,
    }


@app.get('/api/events')
def get_events(
    request: Request,
    response: Response,
    source: str | None = None,
    event_type: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    data = tenant_events(request.state.auth.tenant_id)
    if source:
        data = [e for e in data if e.source == source]
    if event_type:
        data = [e for e in data if e.event_type == event_type]
    if asset:
        data = [e for e in data if e.asset == asset]
    if user:
        data = [e for e in data if e.user == user]
    if src_ip:
        data = [e for e in data if e.src_ip == src_ip]
    return [e.to_dict() for e in _page(data, limit, offset, response)]


@app.get('/api/alerts')
def get_alerts(
    request: Request,
    response: Response,
    severity: str | None = None,
    tactic: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    data = alerts(request.state.auth.tenant_id)
    if severity:
        data = [a for a in data if a.severity == severity]
    if tactic:
        data = [a for a in data if a.tactic == tactic]
    if asset:
        data = [a for a in data if a.asset == asset]
    if user:
        data = [a for a in data if a.user == user]
    if src_ip:
        data = [a for a in data if a.src_ip == src_ip]
    return [a.to_dict() for a in _page(data, limit, offset, response)]


@app.get('/api/incidents')
def get_incidents(
    request: Request,
    response: Response,
    status: str | None = None,
    priority: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    data = incidents(request.state.auth.tenant_id)
    if status:
        data = [i for i in data if i.status == status]
    if priority:
        data = [i for i in data if i.priority == priority]
    return [i.to_dict() for i in _page(data, limit, offset, response)]


@app.get('/api/incidents/{incident_id}')
def get_incident(request: Request, incident_id: str):
    for incident in incidents(request.state.auth.tenant_id):
        if incident.incident_id == incident_id:
            return incident.to_dict()
    raise HTTPException(status_code=404, detail='Incident not found')


@app.get('/api/anomalies')
def get_anomalies(request: Request, response: Response, limit: int = DEFAULT_PAGE_LIMIT, offset: int = 0):
    return [a.to_dict() for a in _page(anomalies(request.state.auth.tenant_id), limit, offset, response)]


@app.get('/api/threat-intel/status')
def threat_intel_status():
    return {
        'providers': THREAT_INTEL.configured_providers(),
        'max_indicators_per_request': MAX_INDICATORS_PER_REQUEST,
        'cache_ttl_seconds': CACHE_TTL_SECONDS,
    }


@app.post('/api/threat-intel/enrich')
async def enrich_threat_intel(request: Request):
    try:
        payload = await request.json()
    except Exception as exc:
        audit_log(request, 'threat_intel', 'invalid_json', str(exc))
        raise HTTPException(status_code=400, detail='Invalid JSON body') from exc
    indicators = payload.get('indicators') if isinstance(payload, dict) else None
    if not isinstance(indicators, list) or not indicators:
        raise HTTPException(status_code=400, detail='indicators must be a non-empty list')
    if len(indicators) > MAX_INDICATORS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f'Maximum {MAX_INDICATORS_PER_REQUEST} indicators per request',
        )
    normalized = normalize_indicators(indicators)
    results = await asyncio.to_thread(THREAT_INTEL.enrich, normalized)
    audit_log(request, 'threat_intel', 'success', f'count={len(results)}')
    return {'tenant_id': request.state.auth.tenant_id, 'results': results}


@app.get('/api/rules/sigma')
def export_sigma_rules():
    return PlainTextResponse(
        export_sigma(get_rules()),
        media_type='application/yaml',
        headers={'Content-Disposition': 'attachment; filename=ai-siem-rules.yml'},
    )


@app.post('/api/rules/sigma/import')
async def import_sigma_rules(request: Request):
    try:
        raw = await request.body()
        imported = import_sigma(raw)
    except SigmaRuleError as exc:
        audit_log(request, 'sigma_import', 'rejected', str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    existing_ids = {str(rule.get('rule_id')) for rule in RULES}
    duplicate_ids = sorted(
        rule['rule_id'] for rule in imported if rule['rule_id'] in existing_ids
    )
    if duplicate_ids:
        audit_log(request, 'sigma_import', 'duplicate_rule', ','.join(duplicate_ids))
        raise HTTPException(status_code=409, detail='Rule already exists')
    RULES.extend(imported)
    audit_log(request, 'sigma_import', 'success', f'count={len(imported)}')
    return {'imported': len(imported), 'rule_ids': [rule['rule_id'] for rule in imported]}


@app.get('/api/rules')
def get_rules():
    return [r if isinstance(r, dict) else r.__dict__ for r in RULES]


@app.get('/api/coverage/attack')
def get_attack_coverage():
    return generate_attack_coverage(get_rules())


@app.get('/api/metrics')
def get_metrics(request: Request):
    events = tenant_events(request.state.auth.tenant_id)
    tenant_alerts = alerts(request.state.auth.tenant_id)
    tenant_incidents = incidents(request.state.auth.tenant_id)
    metrics = calculate_metrics(events, tenant_alerts, tenant_incidents)
    unknown = sum(1 for event in events if event.source == 'unknown')
    metrics['parsing_failed_events'] = unknown
    metrics['unknown_event_rate_pct'] = round((unknown / max(len(events), 1)) * 100, 2)
    metrics['tenant_id'] = request.state.auth.tenant_id
    return metrics


@app.get('/api/parser/stats')
def get_parser_stats():
    return parser_stats()


@app.get('/api/storage/stats')
def get_storage_stats(request: Request):
    tenant_id = request.state.auth.tenant_id
    if AI_SIEM_STORAGE != 'memory':
        return STORAGE.stats(tenant_id=tenant_id)
    return {
        'backend': 'memory',
        'tenant_id': tenant_id,
        'stored_events': len(tenant_events(tenant_id)),
        'stored_triage_records': len([record for record in TRIAGE if record.get('tenant_id') == tenant_id]),
        'stored_ingest_batches': len([record for record in INGEST_BATCHES if record.get('tenant_id') == tenant_id]),
    }


def _extract_items(payload: Any, tenant_id: str):
    if isinstance(payload, dict):
        if 'logs' in payload:
            items = payload['logs']
        elif 'events' in payload:
            items = payload['events']
        else:
            items = [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        raise ValueError('Request body must be JSON object or list')

    if len(items) > MAX_EVENTS_PER_INGEST:
        raise HTTPException(
            status_code=413,
            detail=f'Maximum {MAX_EVENTS_PER_INGEST} events per ingest request',
        )

    if len(tenant_events(tenant_id)) + len(items) > MAX_IN_MEMORY_EVENTS:
        raise HTTPException(
            status_code=413,
            detail=f'Maximum in-memory event capacity {MAX_IN_MEMORY_EVENTS} reached for tenant',
        )

    for item in items:
        raw = item if isinstance(item, str) else json.dumps(item, separators=(',', ':'))
        if len(raw.encode('utf-8')) > MAX_RAW_LOG_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f'Maximum raw event size is {MAX_RAW_LOG_BYTES} bytes',
            )

    return items


@app.post('/api/ingest')
async def ingest(request: Request):
    tenant_id = request.state.auth.tenant_id
    principal_id = request.state.auth.principal_id
    batch_id = uuid4().hex
    received_at = datetime.now(timezone.utc).isoformat()
    try:
        payload = await request.json()
    except Exception:
        _record_ingest_batch({
            'batch_id': batch_id,
            'tenant_id': tenant_id,
            'principal_id': principal_id,
            'received_at': received_at,
            'item_count': 0,
            'rejected_count': 1,
            'status': 'rejected',
            'error': 'Invalid JSON body',
        })
        audit_log(request, 'ingest', 'invalid_json', f'batch_id={batch_id}')
        raise HTTPException(status_code=400, detail='Invalid JSON body')

    items = _extract_items(payload, tenant_id)
    before_stats = parser_stats()
    try:
        result = await INGESTION_PIPELINE.process(items, tenant_id)
        parsed = result.events
    except ValueError as exc:
        _record_ingest_batch({
            'batch_id': batch_id,
            'tenant_id': tenant_id,
            'principal_id': principal_id,
            'received_at': received_at,
            'item_count': len(items),
            'rejected_count': len(items),
            'status': 'rejected',
            'error': str(exc),
        })
        audit_log(request, 'ingest', 'parse_failed', f'batch_id={batch_id}')
        raise
    EVENTS.extend(parsed)

    after_stats = parser_stats()
    unknown_count = after_stats['unknown_events'] - before_stats['unknown_events']
    batch = _record_ingest_batch({
        'batch_id': batch_id,
        'tenant_id': tenant_id,
        'principal_id': principal_id,
        'received_at': received_at,
        'item_count': len(items),
        'accepted_count': len(parsed),
        'rejected_count': 0,
        'unknown_count': unknown_count,
        'status': 'accepted_with_unknowns' if unknown_count else 'accepted',
    })
    audit_log(request, 'ingest', 'success', f'batch_id={batch_id};count={len(parsed)}')

    return {
        'batch_id': batch['batch_id'],
        'ingested': len(parsed),
        'total_events': len(tenant_events(tenant_id)),
        'storage': AI_SIEM_STORAGE,
        'unknown_events_detected': unknown_count,
    }


@app.get('/api/ingest/batches')
def get_ingest_batches(request: Request, response: Response, limit: int = DEFAULT_PAGE_LIMIT, offset: int = 0):
    tenant_id = request.state.auth.tenant_id
    if AI_SIEM_STORAGE != 'memory':
        data = STORAGE.load_ingest_batches(tenant_id=tenant_id, limit=10000, offset=0)
    else:
        data = [record for record in reversed(INGEST_BATCHES) if record.get('tenant_id') == tenant_id]
    return _page(data, limit, offset, response)


@app.get('/api/me')
def get_me(request: Request):
    return request.state.auth.to_dict()


@app.get('/api/triage')
def get_triage(request: Request, response: Response, limit: int = DEFAULT_PAGE_LIMIT, offset: int = 0):
    tenant_id = request.state.auth.tenant_id
    data = (
        STORAGE.load_triage(limit=10000, tenant_id=tenant_id)
        if AI_SIEM_STORAGE != 'memory'
        else [record for record in reversed(TRIAGE) if record.get('tenant_id') == tenant_id]
    )
    return _page(data, limit, offset, response)


@app.post('/api/triage')
async def triage(request: Request):
    try:
        payload = await request.json()
    except Exception:
        audit_log(request, 'triage', 'invalid_json')
        raise HTTPException(status_code=400, detail='Invalid JSON body')

    if not isinstance(payload, dict) or not payload.get('alert_id') or not payload.get('action'):
        audit_log(request, 'triage', 'invalid_payload')
        raise HTTPException(status_code=400, detail='alert_id and action are required')

    def bounded_text(name: str, default: str, max_length: int = 256) -> str:
        value = payload.get(name, default)
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(status_code=400, detail=f'{name} must be a non-empty string')
        value = value.strip()
        if len(value) > max_length:
            raise HTTPException(status_code=400, detail=f'{name} exceeds {max_length} characters')
        return value

    record = {
        'alert_id': bounded_text('alert_id', ''),
        'action': bounded_text('action', ''),
        'analyst': bounded_text('analyst', 'frontend', 128),
        'status': 'recorded',
        'request_id': getattr(request.state, 'request_id', None),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'tenant_id': request.state.auth.tenant_id,
        'principal_id': request.state.auth.principal_id,
    }
    if AI_SIEM_STORAGE != 'memory':
        record = STORAGE.save_triage(record)
    else:
        record['triage_id'] = uuid4().hex
        TRIAGE.append(record)

    audit_log(request, 'triage', 'success', f"alert_id={record['alert_id']}")
    return record
