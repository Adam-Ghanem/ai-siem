from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque

from fastapi import HTTPException, Request

API_KEY = os.getenv('AI_SIEM_API_KEY', '').strip()
GLOBAL_RATE_LIMIT_PER_MINUTE = int(os.getenv('AI_SIEM_RATE_LIMIT_PER_MINUTE', '60'))
INGEST_RATE_LIMIT_PER_MINUTE = int(os.getenv('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '10'))
MAX_EVENTS_PER_INGEST = int(os.getenv('AI_SIEM_MAX_EVENTS_PER_INGEST', '100'))
MAX_RAW_LOG_BYTES = int(os.getenv('AI_SIEM_MAX_RAW_LOG_BYTES', str(10 * 1024)))
MAX_IN_MEMORY_EVENTS = int(os.getenv('AI_SIEM_MAX_IN_MEMORY_EVENTS', '10000'))
AUDIT_LOG_PATH = Path(os.getenv('AI_SIEM_AUDIT_LOG', 'logs/audit.log'))

_GLOBAL_BUCKETS: dict[str, Deque[float]] = defaultdict(deque)
_INGEST_BUCKETS: dict[str, Deque[float]] = defaultdict(deque)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get('x-forwarded-for')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.client.host if request.client else 'unknown'


def audit_log(request: Request, action: str, result: str) -> None:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = (
        f"timestamp={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
        f"client_ip={client_ip(request)} endpoint={request.url.path} "
        f"action={action} result={result}\n"
    )
    with AUDIT_LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(line)


def _check_bucket(bucket: dict[str, Deque[float]], key: str, limit: int) -> bool:
    now = time.time()
    values = bucket[key]
    while values and values[0] < now - 60:
        values.popleft()
    if len(values) >= limit:
        return False
    values.append(now)
    return True


def enforce_rate_limit(request: Request) -> None:
    ip = client_ip(request)
    if not _check_bucket(_GLOBAL_BUCKETS, ip, GLOBAL_RATE_LIMIT_PER_MINUTE):
        audit_log(request, 'rate_limit', 'global_exceeded')
        raise HTTPException(status_code=429, detail='Global rate limit exceeded')
    if request.url.path == '/api/ingest' and not _check_bucket(_INGEST_BUCKETS, ip, INGEST_RATE_LIMIT_PER_MINUTE):
        audit_log(request, 'rate_limit', 'ingest_exceeded')
        raise HTTPException(status_code=429, detail='Ingest rate limit exceeded')


def enforce_auth(request: Request) -> None:
    if request.url.path == '/api/health':
        return
    expected = f'Bearer {API_KEY}'
    if not API_KEY or request.headers.get('authorization', '') != expected:
        audit_log(request, 'auth', 'failed')
        raise HTTPException(status_code=401, detail='Missing or invalid bearer token')


def reset_rate_limit_state() -> None:
    _GLOBAL_BUCKETS.clear()
    _INGEST_BUCKETS.clear()
