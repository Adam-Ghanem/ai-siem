import json
import os
import secrets
import threading
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
MAX_RATE_LIMIT_KEYS = int(os.getenv('AI_SIEM_MAX_RATE_LIMIT_KEYS', '10000'))
TRUST_PROXY_HEADERS = os.getenv('AI_SIEM_TRUST_PROXY_HEADERS', 'false').lower() == 'true'
AUDIT_LOG_PATH = Path(os.getenv('AI_SIEM_AUDIT_LOG', 'logs/audit.log'))

VALID_ROLES = {'viewer', 'analyst', 'ingestor', 'admin'}


def _load_api_keys(raw: str) -> dict[str, str | dict[str, str]]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError('AI_SIEM_API_KEYS must be valid JSON') from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            'AI_SIEM_API_KEYS must be a JSON object mapping tokens to roles or identities'
        )

    keys: dict[str, str | dict[str, str]] = {}
    for token, identity in payload.items():
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError('AI_SIEM_API_KEYS contains an empty or invalid token')

        if isinstance(identity, str):
            if identity not in VALID_ROLES:
                raise RuntimeError(
                    'AI_SIEM_API_KEYS roles must be one of: admin, analyst, ingestor, viewer'
                )
            keys[token] = identity
            continue

        if not isinstance(identity, dict):
            raise RuntimeError(
                'AI_SIEM_API_KEYS values must be a role string or identity object'
            )

        role = identity.get('role')
        principal = identity.get('principal')
        if not isinstance(role, str) or role not in VALID_ROLES:
            raise RuntimeError(
                'AI_SIEM_API_KEYS identity roles must be one of: admin, analyst, ingestor, viewer'
            )
        if not isinstance(principal, str) or not principal.strip():
            raise RuntimeError('AI_SIEM_API_KEYS identity principal must be a non-empty string')
        keys[token] = {'role': role, 'principal': principal.strip()}
    return keys


API_KEYS = _load_api_keys(os.getenv('AI_SIEM_API_KEYS', ''))

_GLOBAL_BUCKETS: dict[str, Deque[float]] = defaultdict(deque)
_INGEST_BUCKETS: dict[str, Deque[float]] = defaultdict(deque)
_BUCKET_LOCK = threading.Lock()


def _safe_text(value: object, max_length: int = 256) -> str:
    text = str(value or '')
    text = text.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    return text[:max_length]


def client_ip(request: Request) -> str:
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get('x-forwarded-for')
        if forwarded:
            candidate = forwarded.split(',')[0].strip()
            if candidate:
                return _safe_text(candidate, 128)
    return _safe_text(request.client.host if request.client else 'unknown', 128)


def audit_log(request: Request, action: str, result: str, detail: str = '') -> None:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    request_id = getattr(request.state, 'request_id', '')
    role = getattr(
        request.state,
        'authz_role',
        getattr(request.state, 'auth_role', ''),
    )
    principal = getattr(request.state, 'auth_principal', '')
    line = (
        f'timestamp={time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())} '
        f'request_id={_safe_text(request_id, 64)} '
        f'client_ip={_safe_text(client_ip(request), 128)} '
        f'endpoint={_safe_text(request.url.path, 256)} '
        f'action={_safe_text(action, 64)} '
        f'result={_safe_text(result, 64)}'
    )
    if role:
        line += f' role={_safe_text(role, 32)}'
    if principal:
        line += f' principal={_safe_text(principal, 128)}'
    if detail:
        line += f' detail={_safe_text(detail)}'
    with AUDIT_LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(line + '\n')


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
    with _BUCKET_LOCK:
        if len(_GLOBAL_BUCKETS) >= MAX_RATE_LIMIT_KEYS and ip not in _GLOBAL_BUCKETS:
            audit_log(request, 'rate_limit', 'key_capacity_exceeded')
            raise HTTPException(status_code=429, detail='Rate limit capacity exceeded')
        if not _check_bucket(_GLOBAL_BUCKETS, ip, GLOBAL_RATE_LIMIT_PER_MINUTE):
            audit_log(request, 'rate_limit', 'global_exceeded')
            raise HTTPException(status_code=429, detail='Global rate limit exceeded')
        if request.url.path == '/api/ingest':
            if not _check_bucket(_INGEST_BUCKETS, ip, INGEST_RATE_LIMIT_PER_MINUTE):
                audit_log(request, 'rate_limit', 'ingest_exceeded')
                raise HTTPException(status_code=429, detail='Ingest rate limit exceeded')


def _resolve_identity(token: str) -> tuple[str, str] | None:
    for configured_token, identity in API_KEYS.items():
        if not secrets.compare_digest(token, configured_token):
            continue
        if isinstance(identity, str):
            return identity, ''
        return identity['role'], identity['principal']
    if API_KEY and secrets.compare_digest(token, API_KEY):
        return 'admin', ''
    return None


def _resolve_role(token: str) -> str | None:
    identity = _resolve_identity(token)
    return identity[0] if identity else None


def _required_roles(request: Request) -> set[str]:
    if request.method == 'POST' and request.url.path == '/api/ingest':
        return {'ingestor', 'admin'}
    if request.method == 'POST' and request.url.path == '/api/triage':
        return {'analyst', 'admin'}
    if (
        request.method == 'POST'
        and request.url.path.startswith('/api/incidents/')
        and request.url.path.endswith('/case')
    ):
        return {'analyst', 'admin'}
    return VALID_ROLES


def enforce_auth(request: Request) -> None:
    if request.url.path == '/api/health':
        return
    authorization = request.headers.get('authorization', '')
    scheme, _, token = authorization.partition(' ')
    identity = _resolve_identity(token) if scheme.lower() == 'bearer' and token else None
    if identity is None:
        audit_log(request, 'auth', 'failed')
        raise HTTPException(status_code=401, detail='Missing or invalid bearer token')

    role, principal = identity
    request.state.authz_role = role
    request.state.auth_role = principal or role
    if principal:
        request.state.auth_principal = principal
    if role not in _required_roles(request):
        audit_log(request, 'authz', 'forbidden')
        raise HTTPException(status_code=403, detail='Insufficient role for this operation')


def reset_rate_limit_state() -> None:
    with _BUCKET_LOCK:
        _GLOBAL_BUCKETS.clear()
        _INGEST_BUCKETS.clear()
