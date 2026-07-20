from __future__ import annotations

import hmac
import os
import re
import threading
import time
from collections import deque
from ipaddress import ip_address
from pathlib import Path
from typing import Deque

from fastapi import HTTPException, Request


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f'{name} must be an integer') from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f'{name} must be between {minimum} and {maximum}')
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    raise RuntimeError(f'{name} must be a boolean')


API_KEY = os.getenv('AI_SIEM_API_KEY', '').strip()
GLOBAL_RATE_LIMIT_PER_MINUTE = _bounded_int(
    'AI_SIEM_RATE_LIMIT_PER_MINUTE', 60, 1, 100_000
)
INGEST_RATE_LIMIT_PER_MINUTE = _bounded_int(
    'AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', 10, 1, 100_000
)
MAX_EVENTS_PER_INGEST = _bounded_int('AI_SIEM_MAX_EVENTS_PER_INGEST', 100, 1, 10_000)
MAX_RAW_LOG_BYTES = _bounded_int(
    'AI_SIEM_MAX_RAW_LOG_BYTES', 10 * 1024, 256, 1024 * 1024
)
MAX_REQUEST_BYTES = _bounded_int(
    'AI_SIEM_MAX_REQUEST_BYTES', 1024 * 1024, 1024, 16 * 1024 * 1024
)
MAX_IN_MEMORY_EVENTS = _bounded_int(
    'AI_SIEM_MAX_IN_MEMORY_EVENTS', 10_000, 100, 1_000_000
)
TRUST_PROXY_HEADERS = _env_bool('AI_SIEM_TRUST_PROXY_HEADERS', False)
AUDIT_LOG_PATH = Path(os.getenv('AI_SIEM_AUDIT_LOG', 'logs/audit.log'))

_GLOBAL_BUCKETS: dict[str, Deque[float]] = {}
_INGEST_BUCKETS: dict[str, Deque[float]] = {}
_RATE_LIMIT_LOCK = threading.Lock()
_CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f]+')


def _safe_log_value(value: object, limit: int = 256) -> str:
    sanitized = _CONTROL_CHARACTERS.sub(' ', str(value)).strip()
    return sanitized[:limit]


def _valid_ip(value: str) -> str | None:
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get('x-forwarded-for', '')
        candidate = _valid_ip(forwarded.split(',')[0]) if forwarded else None
        if candidate:
            return candidate
    peer = request.client.host if request.client else 'unknown'
    return _safe_log_value(peer, 64) or 'unknown'


def audit_log(request: Request, action: str, result: str, detail: str = '') -> None:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    safe_detail = _safe_log_value(detail, 512)
    detail_text = f' detail={safe_detail}' if safe_detail else ''
    line = (
        f"timestamp={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
        f"client_ip={client_ip(request)} "
        f"endpoint={_safe_log_value(request.url.path)} "
        f"action={_safe_log_value(action, 64)} "
        f"result={_safe_log_value(result, 64)}{detail_text}\n"
    )
    with AUDIT_LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(line)


def _check_bucket(bucket: dict[str, Deque[float]], key: str, limit: int) -> bool:
    now = time.time()
    values = bucket.setdefault(key, deque())
    while values and values[0] < now - 60:
        values.popleft()
    if len(values) >= limit:
        return False
    values.append(now)
    return True


def enforce_rate_limit(request: Request) -> None:
    ip = client_ip(request)
    with _RATE_LIMIT_LOCK:
        global_allowed = _check_bucket(
            _GLOBAL_BUCKETS, ip, GLOBAL_RATE_LIMIT_PER_MINUTE
        )
        ingest_allowed = request.url.path != '/api/ingest' or _check_bucket(
            _INGEST_BUCKETS, ip, INGEST_RATE_LIMIT_PER_MINUTE
        )
    if not global_allowed:
        audit_log(request, 'rate_limit', 'global_exceeded')
        raise HTTPException(status_code=429, detail='Global rate limit exceeded')
    if not ingest_allowed:
        audit_log(request, 'rate_limit', 'ingest_exceeded')
        raise HTTPException(status_code=429, detail='Ingest rate limit exceeded')


def enforce_auth(request: Request) -> None:
    if request.url.path == '/api/health':
        return
    authorization = request.headers.get('authorization', '')
    scheme, separator, token = authorization.partition(' ')
    valid = bool(
        API_KEY
        and separator
        and scheme.lower() == 'bearer'
        and hmac.compare_digest(token, API_KEY)
    )
    if not valid:
        audit_log(request, 'auth', 'failed')
        raise HTTPException(status_code=401, detail='Missing or invalid bearer token')


def reset_rate_limit_state() -> None:
    with _RATE_LIMIT_LOCK:
        _GLOBAL_BUCKETS.clear()
        _INGEST_BUCKETS.clear()
