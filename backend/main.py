from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .anomaly import detect_anomalies
from .correlation import correlate
from .coverage import generate_attack_coverage
from .detection import run_detections
from .incident_storage import (
    incident_snapshots_dirty,
    load_incident as load_stored_incident,
    mark_incident_snapshots_dirty,
    replace_incidents,
    search_incidents as search_stored_incidents,
)
from .investigation import build_investigation
from .metrics import calculate_metrics
from .parser import parse_events, parser_stats
from .rules import RULES
from .security import (
    MAX_EVENTS_PER_INGEST,
    MAX_IN_MEMORY_EVENTS,
    MAX_RAW_LOG_BYTES,
    audit_log,
    enforce_auth,
    enforce_rate_limit,
)
from .storage import (
    existing_event_ids,
    init_db,
    load_alerts,
    load_events as load_stored_events,
    load_incident_case,
    load_triage,
    save_alerts,
    save_events,
    save_incident_case,
    save_triage,
    search_alerts as search_stored_alerts,
    search_events as search_stored_events,
)
from .storage import stats as storage_stats
from .threat_intel import ThreatIntelIndex

AI_SIEM_HOST = os.getenv('AI_SIEM_HOST', '0.0.0.0')
AI_SIEM_PORT = int(os.getenv('AI_SIEM_PORT', '8000'))
AI_SIEM_ALLOWED_ORIGIN = os.getenv(
    'AI_SIEM_ALLOWED_ORIGIN',
    'http://localhost:5173',
)
AI_SIEM_STORAGE = os.getenv('AI_SIEM_STORAGE', 'sqlite').lower()
MAX_PAGE_LIMIT = int(os.getenv('AI_SIEM_MAX_PAGE_LIMIT', '1000'))
DEFAULT_PAGE_LIMIT = int(os.getenv('AI_SIEM_DEFAULT_PAGE_LIMIT', str(MAX_PAGE_LIMIT)))
DATA_FILE = Path(__file__).resolve().parents[1] / 'data' / 'sample_logs.json'
THREAT_INTEL_FILE = Path(
    os.getenv(
        'AI_SIEM_THREAT_INTEL_FILE',
        str(Path(__file__).resolve().parents[1] / 'data' / 'threat_intel.json'),
    )
)

VALID_INCIDENT_STATUSES = {'open', 'investigating', 'contained', 'resolved', 'closed'}
VALID_INCIDENT_DISPOSITIONS = {
    'undetermined',
    'true_positive',
    'false_positive',
    'benign',
    'duplicate',
}

app = FastAPI(title='AI-SIEM Live SOC Command Center', version='3.13.0')
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

TRIAGE = load_triage(limit=10000) if AI_SIEM_STORAGE == 'sqlite' else []
INCIDENT_CASES: dict[str, dict[str, Any]] = {}
THREAT_INTEL = ThreatIntelIndex.from_json_file(THREAT_INTEL_FILE)


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


def alerts():
    current = run_detections(EVENTS)
    if AI_SIEM_STORAGE == 'sqlite':
        save_alerts(current)
        return load_alerts()
    return current


def _case_for(incident_id: str) -> dict[str, Any] | None:
    if AI_SIEM_STORAGE == 'sqlite':
        return load_incident_case(incident_id)
    value = INCIDENT_CASES.get(incident_id)
    return dict(value) if value else None


def _apply_case(incident):
    case = _case_for(incident.incident_id)
    if case:
        incident.status = case['status']
        incident.owner = case['owner']
    return incident


def _incident_dict(incident) -> dict[str, Any]:
    data = incident.to_dict()
    data['case'] = _case_for(incident.incident_id)
    return data


def _refresh_incident_snapshots():
    current = [_apply_case(item) for item in correlate(alerts())]
    replace_incidents(current)
    return current


def _ensure_incident_snapshots() -> None:
    if AI_SIEM_STORAGE == 'sqlite' and incident_snapshots_dirty():
        _refresh_incident_snapshots()


def incidents():
    if AI_SIEM_STORAGE == 'sqlite':
        _ensure_incident_snapshots()
        _, total = search_stored_incidents(limit=1)
        if total == 0:
            return []
        results, _ = search_stored_incidents(limit=total)
        return results
    return [_apply_case(item) for item in correlate(alerts())]


def anomalies():
    return detect_anomalies(EVENTS)


def _validate_page(limit: int, offset: int) -> None:
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f'limit must be between 1 and {MAX_PAGE_LIMIT}',
        )
    if offset < 0:
        raise HTTPException(status_code=400, detail='offset must be non-negative')


def _set_page_headers(total: int, limit: int, offset: int, response: Response) -> None:
    response.headers['X-Total-Count'] = str(total)
    response.headers['X-Page-Limit'] = str(limit)
    response.headers['X-Page-Offset'] = str(offset)
    next_offset = offset + limit if offset + limit < total else ''
    response.headers['X-Next-Offset'] = str(next_offset)


def _page(items, limit: int, offset: int, response: Response):
    _validate_page(limit, offset)
    total = len(items)
    _set_page_headers(total, limit, offset, response)
    return items[offset:offset + limit]


@app.middleware('http')
async def security_middleware(request: Request, call_next):
    request.state.request_id = uuid4().hex
    try:
        if request.method != 'OPTIONS':
            enforce_rate_limit(request)
            enforce_auth(request)
    except HTTPException as exc:
        response = JSONResponse(
            status_code=exc.status_code,
            content={'detail': exc.detail},
        )
        response.headers['X-Request-ID'] = request.state.request_id
        return response

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
        'threat_intel': THREAT_INTEL.stats(),
    }


@app.get('/api/events')
def get_events(
    response: Response,
    source: str | None = None,
    event_type: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    data = EVENTS
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


@app.get('/api/search/events')
def search_event_history(
    response: Response,
    source: str | None = None,
    q: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    _validate_page(limit, offset)
    if q is not None and len(q) > 512:
        raise HTTPException(status_code=400, detail='q exceeds 512 characters')
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=400, detail='start must not be after end')

    if AI_SIEM_STORAGE == 'sqlite':
        results, total = search_stored_events(
            source=source,
            query=q,
            start=start,
            end=end,
            limit=limit,
            offset=offset,
        )
    else:
        data = EVENTS
        if source:
            data = [event for event in data if event.source == source]
        if q:
            data = [event for event in data if q in event.raw_log]
        if start:
            data = [event for event in data if event.timestamp >= start]
        if end:
            data = [event for event in data if event.timestamp <= end]
        data = sorted(data, key=lambda event: event.timestamp, reverse=True)
        total = len(data)
        results = data[offset:offset + limit]

    _set_page_headers(total, limit, offset, response)
    return [event.to_dict() for event in results]


@app.get('/api/events/{event_id}/threat-intel')
def get_event_threat_intel(event_id: str):
    event = next((item for item in EVENTS if item.id == event_id), None)
    if event is None:
        raise HTTPException(status_code=404, detail='Event not found')
    return {
        'event_id': event.id,
        'matches': THREAT_INTEL.enrich_events([event]),
    }


@app.get('/api/threat-intel/lookup')
def get_threat_intel_lookup(indicator: str):
    if not indicator.strip():
        raise HTTPException(status_code=400, detail='indicator is required')
    if len(indicator) > 512:
        raise HTTPException(status_code=400, detail='indicator exceeds 512 characters')
    return THREAT_INTEL.lookup(indicator)


@app.get('/api/threat-intel/stats')
def get_threat_intel_stats():
    return THREAT_INTEL.stats()


@app.get('/api/alerts')
def get_alerts(
    response: Response,
    severity: str | None = None,
    tactic: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    rule_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    _validate_page(limit, offset)
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=400, detail='start must not be after end')

    if AI_SIEM_STORAGE == 'sqlite':
        save_alerts(run_detections(EVENTS))
        results, total = search_stored_alerts(
            severity=severity,
            tactic=tactic,
            asset=asset,
            user=user,
            src_ip=src_ip,
            rule_id=rule_id,
            start=start,
            end=end,
            limit=limit,
            offset=offset,
        )
    else:
        data = alerts()
        if severity:
            data = [alert for alert in data if alert.severity == severity]
        if tactic:
            data = [alert for alert in data if alert.tactic == tactic]
        if asset:
            data = [alert for alert in data if alert.asset == asset]
        if user:
            data = [alert for alert in data if alert.user == user]
        if src_ip:
            data = [alert for alert in data if alert.src_ip == src_ip]
        if rule_id:
            data = [alert for alert in data if alert.rule_id == rule_id]
        if start:
            data = [alert for alert in data if alert.timestamp >= start]
        if end:
            data = [alert for alert in data if alert.timestamp <= end]
        data = sorted(data, key=lambda alert: (alert.timestamp, alert.alert_id), reverse=True)
        total = len(data)
        results = data[offset:offset + limit]

    _set_page_headers(total, limit, offset, response)
    return [alert.to_dict() for alert in results]


@app.get('/api/incidents')
def get_incidents(
    response: Response,
    status: str | None = None,
    priority: str | None = None,
    owner: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
):
    _validate_page(limit, offset)
    if AI_SIEM_STORAGE == 'sqlite':
        _ensure_incident_snapshots()
        results, total = search_stored_incidents(
            status=status,
            priority=priority,
            owner=owner,
            limit=limit,
            offset=offset,
        )
        _set_page_headers(total, limit, offset, response)
        return [_incident_dict(item) for item in results]

    data = incidents()
    if status:
        data = [i for i in data if i.status == status]
    if priority:
        data = [i for i in data if i.priority == priority]
    if owner:
        data = [i for i in data if i.owner == owner]
    return [_incident_dict(i) for i in _page(data, limit, offset, response)]


@app.get('/api/incidents/{incident_id}')
def get_incident(incident_id: str):
    if AI_SIEM_STORAGE == 'sqlite':
        _ensure_incident_snapshots()
        incident = load_stored_incident(incident_id)
        if incident is not None:
            return _incident_dict(incident)
        raise HTTPException(status_code=404, detail='Incident not found')

    for incident in incidents():
        if incident.incident_id == incident_id:
            return _incident_dict(incident)
    raise HTTPException(status_code=404, detail='Incident not found')


@app.post('/api/incidents/{incident_id}/case')
async def update_incident_case(incident_id: str, request: Request):
    if AI_SIEM_STORAGE == 'sqlite':
        _ensure_incident_snapshots()
        incident = load_stored_incident(incident_id)
    else:
        incident = next((item for item in incidents() if item.incident_id == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail='Incident not found')

    try:
        payload = await request.json()
    except Exception:
        audit_log(request, 'incident_case', 'invalid_json')
        raise HTTPException(status_code=400, detail='Invalid JSON body')
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='Request body must be a JSON object')

    current = _case_for(incident_id) or {
        'status': incident.status,
        'owner': incident.owner,
        'disposition': 'undetermined',
        'note': '',
    }

    def bounded_text(name: str, default: str, max_length: int) -> str:
        value = payload.get(name, default)
        if not isinstance(value, str):
            raise HTTPException(status_code=400, detail=f'{name} must be a string')
        value = value.strip()
        if len(value) > max_length:
            raise HTTPException(status_code=400, detail=f'{name} exceeds {max_length} characters')
        return value

    status = bounded_text('status', current['status'], 32)
    if status not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail='status must be one of: closed, contained, investigating, open, resolved',
        )
    disposition = bounded_text('disposition', current['disposition'], 32)
    if disposition not in VALID_INCIDENT_DISPOSITIONS:
        raise HTTPException(
            status_code=400,
            detail='disposition must be one of: benign, duplicate, false_positive, true_positive, undetermined',
        )
    owner = bounded_text('owner', current['owner'], 128) or 'unassigned'
    note = bounded_text('note', current['note'], 2048)

    record = {
        'incident_id': incident_id,
        'status': status,
        'owner': owner,
        'disposition': disposition,
        'note': note,
        'updated_by': getattr(request.state, 'auth_role', 'unknown'),
        'request_id': getattr(request.state, 'request_id', None),
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }
    if AI_SIEM_STORAGE == 'sqlite':
        record = save_incident_case(record)
        mark_incident_snapshots_dirty()
    else:
        INCIDENT_CASES[incident_id] = dict(record)

    audit_log(
        request,
        'incident_case',
        'success',
        f'incident_id={incident_id} status={status} owner={owner}',
    )
    return record


@app.get('/api/incidents/{incident_id}/investigation')
def get_incident_investigation(incident_id: str):
    current_alerts = alerts()
    if AI_SIEM_STORAGE == 'sqlite':
        _ensure_incident_snapshots()
        incident = load_stored_incident(incident_id)
    else:
        incident = next(
            (item for item in incidents() if item.incident_id == incident_id),
            None,
        )
    if incident is None:
        raise HTTPException(status_code=404, detail='Incident not found')

    analysis = build_investigation(
        incident,
        current_alerts,
        EVENTS,
        anomalies(),
    )
    related_event_ids = set(analysis['related_event_ids'])
    related_events = [event for event in EVENTS if event.id in related_event_ids]
    analysis['threat_intelligence'] = THREAT_INTEL.enrich_events(related_events)
    analysis['case'] = _case_for(incident_id)
    analysis['grounding']['generated_from'].append('threat_intelligence')
    if analysis['case']:
        analysis['grounding']['generated_from'].append('incident_case')
    return analysis


@app.get('/api/anomalies')
def get_anomalies(response: Response, limit: int = DEFAULT_PAGE_LIMIT, offset: int = 0):
    return [a.to_dict() for a in _page(anomalies(), limit, offset, response)]


@app.get('/api/rules')
def get_rules():
    return [r if isinstance(r, dict) else r.__dict__ for r in RULES]


@app.get('/api/coverage/attack')
def get_attack_coverage():
    return generate_attack_coverage(get_rules())


@app.get('/api/metrics')
def get_metrics():
    metrics = calculate_metrics(EVENTS, alerts(), incidents())
    unknown = parser_stats()['unknown_events']
    metrics['parsing_failed_events'] = unknown
    metrics['unknown_event_rate_pct'] = round((unknown / max(len(EVENTS), 1)) * 100, 2)
    return metrics


@app.get('/api/parser/stats')
def get_parser_stats():
    return parser_stats()


@app.get('/api/storage/stats')
def get_storage_stats():
    if AI_SIEM_STORAGE == 'sqlite':
        result = storage_stats()
        result['incident_snapshots_dirty'] = incident_snapshots_dirty()
        return result
    return {
        'backend': 'memory',
        'stored_events': len(EVENTS),
        'stored_incident_cases': len(INCIDENT_CASES),
    }


def _extract_items(payload: Any):
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

    for item in items:
        raw = item if isinstance(item, str) else json.dumps(item, separators=(',', ':'))
        if len(raw.encode('utf-8')) > MAX_RAW_LOG_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f'Maximum raw event size is {MAX_RAW_LOG_BYTES} bytes',
            )

    return items


def _deduplicate_ingest(parsed):
    known_ids = {event.id for event in EVENTS}
    if AI_SIEM_STORAGE == 'sqlite':
        known_ids.update(existing_event_ids(event.id for event in parsed))

    accepted = []
    seen_ids = set(known_ids)
    for event in parsed:
        if event.id in seen_ids:
            continue
        seen_ids.add(event.id)
        accepted.append(event)
    return accepted, len(parsed) - len(accepted)


def _refresh_hot_window(accepted) -> None:
    EVENTS.extend(accepted)
    EVENTS.sort(key=lambda event: event.timestamp)
    if len(EVENTS) > MAX_IN_MEMORY_EVENTS:
        del EVENTS[:-MAX_IN_MEMORY_EVENTS]


@app.post('/api/ingest')
async def ingest(request: Request):
    try:
        payload = await request.json()
    except Exception:
        audit_log(request, 'ingest', 'invalid_json')
        raise HTTPException(status_code=400, detail='Invalid JSON body')

    items = _extract_items(payload)
    before_stats = parser_stats()
    parsed = parse_events(items)
    accepted, duplicates_ignored = _deduplicate_ingest(parsed)

    if AI_SIEM_STORAGE == 'sqlite':
        save_events(accepted)
        _refresh_hot_window(accepted)
        save_alerts(run_detections(EVENTS))
        if accepted:
            mark_incident_snapshots_dirty()
    else:
        if len(EVENTS) + len(accepted) > MAX_IN_MEMORY_EVENTS:
            raise HTTPException(
                status_code=413,
                detail=f'Maximum in-memory event capacity {MAX_IN_MEMORY_EVENTS} reached',
            )
        EVENTS.extend(accepted)

    after_stats = parser_stats()
    audit_log(
        request,
        'ingest',
        'success',
        f'count={len(accepted)} duplicates_ignored={duplicates_ignored}',
    )

    return {
        'ingested': len(accepted),
        'duplicates_ignored': duplicates_ignored,
        'total_events': len(EVENTS),
        'hot_events': len(EVENTS),
        'storage': AI_SIEM_STORAGE,
        'unknown_events_detected': (
            after_stats['unknown_events'] - before_stats['unknown_events']
        ),
    }


@app.get('/api/triage')
def get_triage(response: Response, limit: int = DEFAULT_PAGE_LIMIT, offset: int = 0):
    data = load_triage(limit=10000) if AI_SIEM_STORAGE == 'sqlite' else list(reversed(TRIAGE))
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
    }
    if AI_SIEM_STORAGE == 'sqlite':
        record = save_triage(record)
    else:
        record['triage_id'] = uuid4().hex
        TRIAGE.append(record)

    audit_log(request, 'triage', 'success', f"alert_id={record['alert_id']}")
    return record