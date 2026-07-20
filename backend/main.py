from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .anomaly import detect_anomalies
from .correlation import correlate
from .coverage import generate_attack_coverage
from .detection import run_detections
from .metrics import calculate_metrics
from .operations import OperationNotFound, OperationsStore
from .parser import parse_events, parser_stats
from .rules import RULES
from .security import (
    MAX_EVENTS_PER_INGEST,
    MAX_IN_MEMORY_EVENTS,
    MAX_RAW_LOG_BYTES,
    MAX_REQUEST_BYTES,
    access_context,
    audit_log,
    enforce_auth,
    enforce_rate_limit,
    require_admin_access,
    require_operator_access,
    role_capabilities,
)
from .storage import existing_event_ids, init_db
from .storage import load_events as load_stored_events
from .storage import load_triage_records, save_events, save_triage_record
from .storage import stats as storage_stats

AI_SIEM_HOST = os.getenv('AI_SIEM_HOST', '0.0.0.0')
AI_SIEM_PORT = int(os.getenv('AI_SIEM_PORT', '8000'))
AI_SIEM_ALLOWED_ORIGIN = os.getenv(
    'AI_SIEM_ALLOWED_ORIGIN',
    'http://localhost:5173',
)
AI_SIEM_STORAGE = os.getenv('AI_SIEM_STORAGE', 'sqlite').lower()
DATA_FILE = Path(__file__).resolve().parents[1] / 'data' / 'sample_logs.json'
APP_VERSION = '4.0.0'
STARTED_AT = time.monotonic()
TRIAGE_ACTIONS = {
    'acknowledged',
    'investigating',
    'false_positive',
    'resolved',
    'frontend_review',
}
_ALERT_ID_PATTERN = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')

app = FastAPI(title='AI-SIEM Live SOC Command Center', version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip() for origin in AI_SIEM_ALLOWED_ORIGIN.split(',') if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'PATCH', 'OPTIONS'],
    allow_headers=['content-type', 'authorization'],
)

TRIAGE: deque[dict[str, Any]] = deque(maxlen=1000)
_STATE_LOCK = threading.RLock()
_STATE_VERSION = 0
_ANALYSIS_CACHE_KEY: tuple[int, int, str | None] | None = None
_ANALYSIS_CACHE: dict[str, Any] | None = None


def _load_sample_events():
    if DATA_FILE.exists():
        return parse_events(json.loads(DATA_FILE.read_text(encoding='utf-8')))
    return []


def load_events():
    if AI_SIEM_STORAGE == 'sqlite':
        init_db()
        stored = load_stored_events(limit=MAX_IN_MEMORY_EVENTS)
        if stored:
            return stored
        sample = _load_sample_events()
        save_events(sample)
        return sample
    return _load_sample_events()


EVENTS = load_events()
_EVENT_IDS = {event.id for event in EVENTS}
OPERATIONS = OperationsStore(persistent=AI_SIEM_STORAGE == 'sqlite')


def _analysis_snapshot() -> dict[str, Any]:
    global _ANALYSIS_CACHE, _ANALYSIS_CACHE_KEY
    with _STATE_LOCK:
        cache_key = (
            _STATE_VERSION,
            len(EVENTS),
            EVENTS[-1].id if EVENTS else None,
        )
        if _ANALYSIS_CACHE_KEY == cache_key and _ANALYSIS_CACHE is not None:
            return _ANALYSIS_CACHE
        events_copy = list(EVENTS)

    alert_data = run_detections(events_copy)
    incident_data = correlate(alert_data)
    anomaly_data = detect_anomalies(events_copy)
    OPERATIONS.sync_alerts(alert_data)
    OPERATIONS.sync_incidents(incident_data)
    snapshot = {
        'events': events_copy,
        'alerts': alert_data,
        'incidents': incident_data,
        'anomalies': anomaly_data,
        'metrics': calculate_metrics(events_copy, alert_data, incident_data),
    }

    with _STATE_LOCK:
        current_key = (
            _STATE_VERSION,
            len(EVENTS),
            EVENTS[-1].id if EVENTS else None,
        )
        if current_key == cache_key:
            _ANALYSIS_CACHE_KEY = cache_key
            _ANALYSIS_CACHE = snapshot
    return snapshot


def alerts():
    return _analysis_snapshot()['alerts']


def incidents():
    return _analysis_snapshot()['incidents']


def anomalies():
    return _analysis_snapshot()['anomalies']


def _pagination(data: list[Any], offset: int, limit: int) -> list[Any]:
    return data[offset : offset + limit]


def _secure_response(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response


@app.middleware('http')
async def security_middleware(request: Request, call_next):
    if request.method != 'OPTIONS':
        try:
            enforce_rate_limit(request)
            enforce_auth(request)
        except HTTPException as exc:
            return _secure_response(
                JSONResponse(
                    status_code=exc.status_code,
                    content={'detail': exc.detail},
                )
            )

    response = await call_next(request)
    return _secure_response(response)


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
        'version': APP_VERSION,
        'events_loaded': len(EVENTS),
        'storage': AI_SIEM_STORAGE,
        'rbac': True,
        'uptime_seconds': round(time.monotonic() - STARTED_AT, 1),
    }


@app.get('/api/session')
def get_session(request: Request):
    access = access_context(request)
    return {
        'authenticated': True,
        'role': access.role,
        'capabilities': role_capabilities(access.role),
    }


@app.get('/api/events')
def get_events(
    source: str | None = None,
    event_type: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(500, ge=1, le=1000),
):
    with _STATE_LOCK:
        data = list(EVENTS)
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
    return [e.to_dict() for e in _pagination(data, offset, limit)]


@app.get('/api/alerts')
def get_alerts(
    severity: str | None = None,
    tactic: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    status: str | None = None,
    assigned_to: str | None = None,
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(500, ge=1, le=1000),
):
    data = OPERATIONS.alert_views(alerts())
    if severity:
        data = [alert for alert in data if alert['severity'] == severity]
    if tactic:
        data = [alert for alert in data if alert['tactic'] == tactic]
    if asset:
        data = [alert for alert in data if alert['asset'] == asset]
    if user:
        data = [alert for alert in data if alert['user'] == user]
    if src_ip:
        data = [alert for alert in data if alert['src_ip'] == src_ip]
    if status:
        data = [alert for alert in data if alert.get('status') == status]
    if assigned_to:
        data = [alert for alert in data if alert.get('assigned_to') == assigned_to]
    return _pagination(data, offset, limit)


@app.get('/api/incidents')
def get_incidents(
    status: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(500, ge=1, le=1000),
):
    data = OPERATIONS.incident_views(incidents())
    if status:
        data = [incident for incident in data if incident['status'] == status]
    if priority:
        data = [incident for incident in data if incident['priority'] == priority]
    if assigned_to:
        data = [
            incident for incident in data if incident.get('assigned_to') == assigned_to
        ]
    return _pagination(data, offset, limit)


@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id: str):
    for incident in OPERATIONS.incident_views(incidents()):
        if incident['incident_id'] == incident_id:
            return incident
    raise HTTPException(status_code=404, detail='Incident not found')


@app.get('/api/anomalies')
def get_anomalies(
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(500, ge=1, le=1000),
):
    return [anomaly.to_dict() for anomaly in _pagination(anomalies(), offset, limit)]


@app.get('/api/rules')
def get_rules():
    return [r if isinstance(r, dict) else r.__dict__ for r in RULES]


@app.get('/api/coverage/attack')
def get_attack_coverage():
    return generate_attack_coverage(get_rules())


@app.get('/api/metrics')
def get_metrics():
    metrics = dict(_analysis_snapshot()['metrics'])
    unknown = parser_stats()['unknown_events']
    metrics['parsing_failed_events'] = unknown
    metrics['unknown_event_rate_pct'] = round((unknown / max(len(EVENTS), 1)) * 100, 2)
    metrics['operations'] = OPERATIONS.summary()
    return metrics


@app.get('/api/parser/stats')
def get_parser_stats(request: Request):
    require_admin_access(request)
    return parser_stats()


@app.get('/api/storage/stats')
def get_storage_stats(request: Request):
    require_admin_access(request)
    if AI_SIEM_STORAGE == 'sqlite':
        return storage_stats()
    return {'backend': 'memory', 'stored_events': len(EVENTS)}


def _extract_items(payload: Any):
    if isinstance(payload, dict):
        if 'logs' in payload and 'events' in payload:
            raise ValueError('Use either logs or events, not both')
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

    if not isinstance(items, list):
        raise ValueError('logs and events must be JSON arrays')

    if len(items) > MAX_EVENTS_PER_INGEST:
        raise HTTPException(
            status_code=413,
            detail=f'Maximum {MAX_EVENTS_PER_INGEST} events per ingest request',
        )

    for item in items:
        if not isinstance(item, (str, dict)):
            raise ValueError('Each event must be a string or JSON object')
        raw = item if isinstance(item, str) else json.dumps(item, separators=(',', ':'))
        if len(raw.encode('utf-8')) > MAX_RAW_LOG_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f'Maximum raw event size is {MAX_RAW_LOG_BYTES} bytes',
            )

    return items


async def _read_json_body(request: Request, action: str) -> Any:
    content_length = request.headers.get('content-length')
    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail='Invalid Content-Length')
        if declared_size < 0:
            raise HTTPException(status_code=400, detail='Invalid Content-Length')
        if declared_size > MAX_REQUEST_BYTES:
            audit_log(request, action, 'request_too_large')
            raise HTTPException(status_code=413, detail='Request body too large')

    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > MAX_REQUEST_BYTES:
            audit_log(request, action, 'request_too_large')
            raise HTTPException(status_code=413, detail='Request body too large')
        chunks.append(chunk)
    body = b''.join(chunks)
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        audit_log(request, action, 'invalid_json')
        raise HTTPException(status_code=400, detail='Invalid JSON body')


@app.post('/api/ingest')
async def ingest(request: Request):
    global _STATE_VERSION
    require_operator_access(request)
    payload = await _read_json_body(request, 'ingest')
    items = _extract_items(payload)
    before_stats = parser_stats()
    parsed = parse_events(items)
    with _STATE_LOCK:
        duplicate_ids = set(_EVENT_IDS)
        if AI_SIEM_STORAGE == 'sqlite':
            duplicate_ids.update(existing_event_ids(event.id for event in parsed))
        unique_events = []
        pending_ids: set[str] = set()
        for event in parsed:
            if event.id in duplicate_ids or event.id in pending_ids:
                continue
            unique_events.append(event)
            pending_ids.add(event.id)

        if len(EVENTS) + len(unique_events) > MAX_IN_MEMORY_EVENTS:
            raise HTTPException(
                status_code=413,
                detail=(
                    'Maximum in-memory event capacity '
                    f'{MAX_IN_MEMORY_EVENTS} reached'
                ),
            )

        if AI_SIEM_STORAGE == 'sqlite':
            save_events(unique_events)
        EVENTS.extend(unique_events)
        _EVENT_IDS.update(pending_ids)
        if unique_events:
            _STATE_VERSION += 1

    after_stats = parser_stats()
    audit_log(request, 'ingest', 'success', f'count={len(unique_events)}')

    return {
        'ingested': len(unique_events),
        'duplicates_ignored': len(parsed) - len(unique_events),
        'total_events': len(EVENTS),
        'storage': AI_SIEM_STORAGE,
        'unknown_events_detected': (
            after_stats['unknown_events'] - before_stats['unknown_events']
        ),
    }


@app.post('/api/triage')
async def triage(request: Request):
    access = require_operator_access(request)
    payload = await _read_json_body(request, 'triage')
    if (
        not isinstance(payload, dict)
        or not payload.get('alert_id')
        or not payload.get('action')
    ):
        raise HTTPException(
            status_code=400,
            detail='alert_id and action are required',
        )

    alert_id = str(payload['alert_id']).strip()
    action = str(payload['action']).strip().lower()
    analyst = str(payload.get('analyst', 'frontend')).strip()
    note = str(payload.get('note', '')).strip()
    if not _ALERT_ID_PATTERN.fullmatch(alert_id):
        raise HTTPException(status_code=400, detail='Invalid alert_id')
    if action not in TRIAGE_ACTIONS:
        raise HTTPException(status_code=400, detail='Unsupported triage action')
    if not 1 <= len(analyst) <= 80:
        raise HTTPException(status_code=400, detail='Invalid analyst')
    if len(note) > 1000:
        raise HTTPException(status_code=400, detail='Triage note is too long')
    if alert_id not in {alert.alert_id for alert in alerts()}:
        raise HTTPException(status_code=404, detail='Alert not found')

    if action != 'frontend_review':
        try:
            OPERATIONS.update_alert(
                alert_id,
                status=action,
                assigned_to=analyst,
                resolution_note=note if note else None,
                actor=analyst or f'{access.role}-session',
            )
        except OperationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    record = {
        'record_id': f'TRG-{uuid4().hex[:12].upper()}',
        'alert_id': alert_id,
        'action': action,
        'analyst': analyst,
        'note': note,
        'status': 'recorded',
        'created_at': datetime.now(timezone.utc).isoformat(),
    }
    if AI_SIEM_STORAGE == 'sqlite':
        save_triage_record(record)
    else:
        TRIAGE.append(record)

    audit_log(request, 'triage', 'success', f'alert_id={alert_id}')
    return record


@app.get('/api/triage')
def get_triage(limit: int = Query(100, ge=1, le=1000)):
    if AI_SIEM_STORAGE == 'sqlite':
        return load_triage_records(limit=limit)
    return list(TRIAGE)[-limit:][::-1]


def _operation_update_payload(payload: Any, default_actor: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError('Request body must be a JSON object')
    allowed = {'status', 'assigned_to', 'resolution_note'}
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f'Unsupported operation fields: {", ".join(sorted(unknown))}')
    if not ({'status', 'assigned_to', 'resolution_note'} & set(payload)):
        raise ValueError('Provide status, assigned_to, or resolution_note')
    for key in allowed:
        if (
            key in payload
            and payload[key] is not None
            and not isinstance(payload[key], str)
        ):
            raise ValueError(f'{key} must be a string')
    return {
        'status': payload.get('status'),
        'assigned_to': payload.get('assigned_to'),
        'resolution_note': payload.get('resolution_note'),
        'actor': default_actor,
    }


@app.patch('/api/alerts/{alert_id}')
async def update_alert(alert_id: str, request: Request):
    access = require_operator_access(request)
    if not _ALERT_ID_PATTERN.fullmatch(alert_id):
        raise HTTPException(status_code=400, detail='Invalid alert_id')
    alerts()
    values = _operation_update_payload(
        await _read_json_body(request, 'alert_update'),
        f'{access.role}-session',
    )
    try:
        updated = OPERATIONS.update_alert(alert_id, **values)
    except OperationNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    audit_log(
        request,
        'alert_update',
        'success',
        f'alert_id={alert_id} status={updated["status"]}',
    )
    return updated


@app.patch('/api/incidents/{incident_id}')
async def update_incident(incident_id: str, request: Request):
    access = require_operator_access(request)
    if not _ALERT_ID_PATTERN.fullmatch(incident_id):
        raise HTTPException(status_code=400, detail='Invalid incident_id')
    incidents()
    values = _operation_update_payload(
        await _read_json_body(request, 'incident_update'),
        f'{access.role}-session',
    )
    try:
        updated = OPERATIONS.update_incident(incident_id, **values)
    except OperationNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    audit_log(
        request,
        'incident_update',
        'success',
        f'incident_id={incident_id} status={updated["status"]}',
    )
    return updated


@app.get('/api/operations/summary')
def get_operations_summary():
    _analysis_snapshot()
    return OPERATIONS.summary()


@app.get('/api/operations/history')
def get_operations_history(
    object_type: str | None = None,
    object_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    _analysis_snapshot()
    return OPERATIONS.history(
        object_type=object_type,
        object_id=object_id,
        limit=limit,
    )
