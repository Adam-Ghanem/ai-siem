import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque

from fastapi import HTTPException, Request

API_KEY = os.getenv('AI_SIEM_API_KEY', '').strip()
DEFAULT_TENANT = os.getenv('AI_SIEM_DEFAULT_TENANT', 'default').strip() or 'default'
DEFAULT_PRINCIPAL = os.getenv('AI_SIEM_DEFAULT_PRINCIPAL', 'legacy-admin').strip() or 'legacy-admin'
GLOBAL_RATE_LIMIT_PER_MINUTE = int(os.getenv('AI_SIEM_RATE_LIMIT_PER_MINUTE', '60'))
INGEST_RATE_LIMIT_PER_MINUTE = int(os.getenv('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '10'))
MAX_EVENTS_PER_INGEST = int(os.getenv('AI_SIEM_MAX_EVENTS_PER_INGEST', '100'))
MAX_RAW_LOG_BYTES = int(os.getenv('AI_SIEM_MAX_RAW_LOG_BYTES', str(10 * 1024)))
MAX_IN_MEMORY_EVENTS = int(os.getenv('AI_SIEM_MAX_IN_MEMORY_EVENTS', '10000'))
MAX_RATE_LIMIT_KEYS = int(os.getenv('AI_SIEM_MAX_RATE_LIMIT_KEYS', '10000'))
TRUST_PROXY_HEADERS = os.getenv('AI_SIEM_TRUST_PROXY_HEADERS', 'false').lower() == 'true'
AUDIT_LOG_PATH = Path(os.getenv('AI_SIEM_AUDIT_LOG', 'logs/audit.log'))

_GLOBAL_BUCKETS: dict[str, Deque[float]] = defaultdict(deque)
_INGEST_BUCKETS: dict[str, Deque[float]] = defaultdict(deque)
_BUCKET_LOCK = threading.Lock()
_AUDIT_LOCK = threading.Lock()


@dataclass(frozen=True)
class AuthContext:
    principal_id: str
    tenant_id: str
    roles: frozenset[str]

    def has_any_role(self, *required: str) -> bool:
        return bool(self.roles.intersection(required))

    def to_dict(self) -> dict[str, object]:
        return {
            'principal_id': self.principal_id,
            'tenant_id': self.tenant_id,
            'roles': sorted(self.roles),
        }


def _load_principals() -> dict[str, AuthContext]:
    raw = os.getenv('AI_SIEM_PRINCIPALS', '').strip()
    if not raw:
        if not API_KEY:
            return {}
        return {
            API_KEY: AuthContext(
                DEFAULT_PRINCIPAL,
                DEFAULT_TENANT,
                frozenset({'admin'}),
            )
        }

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError('AI_SIEM_PRINCIPALS must be valid JSON') from exc
    if not isinstance(data, dict):
        raise RuntimeError('AI_SIEM_PRINCIPALS must be a JSON object')

    principals: dict[str, AuthContext] = {}
    for token, value in data.items():
        if not isinstance(token, str) or not token.strip() or not isinstance(value, dict):
            raise RuntimeError('Each AI_SIEM_PRINCIPALS entry must map a token to an object')
        principal_id = str(value.get('principal_id') or '').strip()
        tenant_id = str(value.get('tenant_id') or '').strip()
        roles = value.get('roles', [])
        if not principal_id or not tenant_id or not isinstance(roles, list) or not roles:
            raise RuntimeError(
                'Each principal requires principal_id, tenant_id, and a non-empty roles list'
            )
        normalized_roles = frozenset(str(role).strip().lower() for role in roles if str(role).strip())
        if not normalized_roles:
            raise RuntimeError('Each principal requires at least one non-empty role')
        principals[token] = AuthContext(principal_id, tenant_id, normalized_roles)
    return principals


PRINCIPALS = _load_principals()


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
    line = (
        f'timestamp={time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())} '
        f'request_id={_safe_text(request_id, 64)} '
        f'principal_id={_safe_text(getattr(getattr(request.state, "auth", None), "principal_id", "anonymous"), 128)} '
        f'tenant_id={_safe_text(getattr(getattr(request.state, "auth", None), "tenant_id", "unknown"), 128)} '
        f'client_ip={_safe_text(client_ip(request), 128)} '
        f'endpoint={_safe_text(request.url.path, 256)} '
        f'action={_safe_text(action, 64)} '
        f'result={_safe_text(result, 64)}'
    )
    if detail:
        line += f' detail={_safe_text(detail)}'
    with _AUDIT_LOCK:
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


def enforce_auth(request: Request) -> AuthContext | None:
    if request.url.path == '/api/health':
        return None
    authorization = request.headers.get('authorization', '')
    scheme, _, token = authorization.partition(' ')
    context = None
    for candidate, candidate_context in PRINCIPALS.items():
        if secrets.compare_digest(token, candidate):
            context = candidate_context
            break
    if scheme.lower() != 'bearer' or not token or context is None:
        audit_log(request, 'auth', 'failed')
        raise HTTPException(status_code=401, detail='Missing or invalid bearer token')
    return context


def enforce_permission(request: Request, context: AuthContext) -> None:
    if request.url.path == '/api/ingest' and request.method == 'POST':
        required = ('admin', 'ingestor')
    elif request.url.path == '/api/triage' and request.method == 'POST':
        required = ('admin', 'analyst', 'responder')
    elif request.url.path == '/api/threat-intel/enrich' and request.method == 'POST':
        required = ('admin', 'analyst', 'responder')
    else:
        required = ('admin', 'reader', 'ingestor', 'analyst', 'responder')
    if not context.has_any_role(*required):
        audit_log(request, 'authorization', 'failed', f'required={"/".join(required)}')
        raise HTTPException(status_code=403, detail='Insufficient role for this operation')


def reset_rate_limit_state() -> None:
    with _BUCKET_LOCK:
        _GLOBAL_BUCKETS.clear()
        _INGEST_BUCKETS.clear()
