import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path
from typing import Deque
from urllib.parse import quote

from fastapi import HTTPException, Request

try:
    import fcntl
except ImportError:  # pragma: no cover - production container is POSIX/Linux
    fcntl = None


def _load_audit_hmac_previous_keys(raw: str) -> tuple[bytes, ...]:
    raw = raw.strip()
    if not raw:
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            'AI_SIEM_AUDIT_HMAC_PREVIOUS_KEYS must be a JSON array of strings'
        ) from exc
    if not isinstance(payload, list):
        raise RuntimeError(
            'AI_SIEM_AUDIT_HMAC_PREVIOUS_KEYS must be a JSON array of strings'
        )

    keys = []
    for value in payload:
        if not isinstance(value, str) or not value:
            raise RuntimeError(
                'AI_SIEM_AUDIT_HMAC_PREVIOUS_KEYS must contain only non-empty strings'
            )
        keys.append(value.encode('utf-8'))
    return tuple(keys)


API_KEY = os.getenv('AI_SIEM_API_KEY', '').strip()
GLOBAL_RATE_LIMIT_PER_MINUTE = int(os.getenv('AI_SIEM_RATE_LIMIT_PER_MINUTE', '60'))
INGEST_RATE_LIMIT_PER_MINUTE = int(os.getenv('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '10'))
MAX_EVENTS_PER_INGEST = int(os.getenv('AI_SIEM_MAX_EVENTS_PER_INGEST', '100'))
MAX_RAW_LOG_BYTES = int(os.getenv('AI_SIEM_MAX_RAW_LOG_BYTES', str(10 * 1024)))
MAX_IN_MEMORY_EVENTS = int(os.getenv('AI_SIEM_MAX_IN_MEMORY_EVENTS', '10000'))
MAX_RATE_LIMIT_KEYS = int(os.getenv('AI_SIEM_MAX_RATE_LIMIT_KEYS', '10000'))
TRUST_PROXY_HEADERS = os.getenv('AI_SIEM_TRUST_PROXY_HEADERS', 'false').lower() == 'true'
TRUSTED_PROXY_CIDRS = os.getenv('AI_SIEM_TRUSTED_PROXY_CIDRS', '').strip()
AUDIT_LOG_PATH = Path(os.getenv('AI_SIEM_AUDIT_LOG', 'logs/audit.log'))
AUDIT_HMAC_KEY = os.getenv('AI_SIEM_AUDIT_HMAC_KEY', '').encode('utf-8')
AUDIT_HMAC_PREVIOUS_KEYS = _load_audit_hmac_previous_keys(
    os.getenv('AI_SIEM_AUDIT_HMAC_PREVIOUS_KEYS', '')
)
if AUDIT_HMAC_PREVIOUS_KEYS and not AUDIT_HMAC_KEY:
    raise RuntimeError(
        'AI_SIEM_AUDIT_HMAC_PREVIOUS_KEYS requires AI_SIEM_AUDIT_HMAC_KEY'
    )

VALID_ROLES = {'viewer', 'analyst', 'ingestor', 'admin'}
READ_ROLES = {'viewer', 'analyst', 'admin'}
RATE_LIMIT_WINDOW_SECONDS = 60
AUDIT_GENESIS_HASH = '0' * 64


def _load_trusted_proxy_networks(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for value in raw.split(','):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise RuntimeError(
                'AI_SIEM_TRUSTED_PROXY_CIDRS must contain valid comma-separated CIDRs'
            ) from exc
    return tuple(networks)


TRUSTED_PROXY_NETWORKS = _load_trusted_proxy_networks(TRUSTED_PROXY_CIDRS)


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
_AUDIT_LOCK = threading.Lock()
_AUDIT_HEAD_CACHE: dict[Path, tuple[int, int, str]] = {}


def _safe_text(value: object, max_length: int = 256) -> str:
    text = str(value or '')
    text = text.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    return text[:max_length]


def _audit_value(value: object, max_length: int = 256) -> str:
    return quote(_safe_text(value, max_length), safe='-._~:@/')


def _audit_record_payload(previous_hash: str, record: str) -> bytes:
    return f'{previous_hash} {record}'.encode('utf-8')


def _audit_record_hash(previous_hash: str, record: str) -> str:
    return hashlib.sha256(_audit_record_payload(previous_hash, record)).hexdigest()


def _audit_record_mac(previous_hash: str, record: str, key: bytes | None = None) -> str:
    signing_key = AUDIT_HMAC_KEY if key is None else key
    return hmac.new(
        signing_key,
        _audit_record_payload(previous_hash, record),
        hashlib.sha256,
    ).hexdigest()


@contextmanager
def _audit_file_lock(path: Path):
    if fcntl is None:
        yield
        return

    lock_path = path.with_name(f'.{path.name}.lock')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a+', encoding='utf-8') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _audit_chain_state(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return True, AUDIT_GENESIS_HASH

    previous_hash = AUDIT_GENESIS_HASH
    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        marker = ' prev_hash='
        if marker not in line:
            if AUDIT_HMAC_KEY:
                return False, previous_hash
            previous_hash = _audit_record_hash(previous_hash, line)
            continue

        record, integrity = line.rsplit(marker, 1)
        claimed_previous, separator, hash_and_fields = integrity.partition(' hash=')
        if not separator:
            return False, previous_hash
        claimed_hash, _, trailing_fields = hash_and_fields.partition(' ')
        if claimed_previous != previous_hash or len(claimed_hash) != 64:
            return False, previous_hash

        expected_hash = _audit_record_hash(previous_hash, record)
        if not secrets.compare_digest(claimed_hash, expected_hash):
            return False, previous_hash

        signed_record = record.endswith(' integrity=hmac-sha256')
        mac_value = ''
        if trailing_fields:
            fields = trailing_fields.split()
            if len(fields) != 1 or not fields[0].startswith('mac='):
                return False, previous_hash
            mac_value = fields[0][4:]

        if AUDIT_HMAC_KEY:
            if not signed_record or len(mac_value) != 64:
                return False, previous_hash
            verification_keys = (AUDIT_HMAC_KEY, *AUDIT_HMAC_PREVIOUS_KEYS)
            if not any(
                secrets.compare_digest(
                    mac_value,
                    _audit_record_mac(previous_hash, record, key),
                )
                for key in verification_keys
            ):
                return False, previous_hash
        elif signed_record or mac_value:
            return False, previous_hash

        previous_hash = claimed_hash
    return True, previous_hash


def verify_audit_log(path: Path | None = None) -> bool:
    target = path or AUDIT_LOG_PATH
    with _AUDIT_LOCK:
        with _audit_file_lock(target):
            valid, _ = _audit_chain_state(target)
    return valid


def _current_audit_head(path: Path) -> str:
    if not path.exists():
        _AUDIT_HEAD_CACHE.pop(path, None)
        return AUDIT_GENESIS_HASH

    stat = path.stat()
    cached = _AUDIT_HEAD_CACHE.get(path)
    if cached and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
        return cached[2]

    valid, head = _audit_chain_state(path)
    if not valid:
        raise RuntimeError('Existing audit log failed integrity verification')
    _AUDIT_HEAD_CACHE[path] = (stat.st_size, stat.st_mtime_ns, head)
    return head


def _trusted_proxy_peer(host: str) -> bool:
    if not TRUSTED_PROXY_NETWORKS:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in TRUSTED_PROXY_NETWORKS)


def _forwarded_client_ip(forwarded: str) -> str | None:
    hops: list[str] = []
    for value in forwarded.split(','):
        value = value.strip()
        if not value:
            return None
        try:
            hops.append(str(ipaddress.ip_address(value)))
        except ValueError:
            return None

    for hop in reversed(hops):
        if not _trusted_proxy_peer(hop):
            return hop
    return hops[0] if hops else None


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else 'unknown'
    if TRUST_PROXY_HEADERS and _trusted_proxy_peer(peer):
        forwarded = request.headers.get('x-forwarded-for')
        if forwarded:
            candidate = _forwarded_client_ip(forwarded)
            if candidate:
                return _safe_text(candidate, 128)
    return _safe_text(peer, 128)


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
        f'request_id={_audit_value(request_id, 64)} '
        f'client_ip={_audit_value(client_ip(request), 128)} '
        f'endpoint={_audit_value(request.url.path, 256)} '
        f'action={_audit_value(action, 64)} '
        f'result={_audit_value(result, 64)}'
    )
    if role:
        line += f' role={_audit_value(role, 32)}'
    if principal:
        line += f' principal={_audit_value(principal, 128)}'
    if detail:
        line += f' detail={_audit_value(detail)}'

    with _AUDIT_LOCK:
        with _audit_file_lock(AUDIT_LOG_PATH):
            previous_hash = _current_audit_head(AUDIT_LOG_PATH)
            record = line
            if AUDIT_HMAC_KEY:
                record += ' integrity=hmac-sha256'
            record_hash = _audit_record_hash(previous_hash, record)
            chained_line = f'{record} prev_hash={previous_hash} hash={record_hash}'
            if AUDIT_HMAC_KEY:
                chained_line += f' mac={_audit_record_mac(previous_hash, record)}'
            with AUDIT_LOG_PATH.open('a', encoding='utf-8') as handle:
                handle.write(chained_line + '\n')
            stat = AUDIT_LOG_PATH.stat()
            _AUDIT_HEAD_CACHE[AUDIT_LOG_PATH] = (
                stat.st_size,
                stat.st_mtime_ns,
                record_hash,
            )


def _expire_values(values: Deque[float], now: float) -> None:
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    while values and values[0] < cutoff:
        values.popleft()


def _prune_bucket(bucket: dict[str, Deque[float]], now: float) -> None:
    for key in list(bucket):
        values = bucket[key]
        _expire_values(values, now)
        if not values:
            del bucket[key]


def _check_bucket(
    bucket: dict[str, Deque[float]],
    key: str,
    limit: int,
    now: float | None = None,
) -> bool:
    now = time.time() if now is None else now
    values = bucket[key]
    _expire_values(values, now)
    if len(values) >= limit:
        return False
    values.append(now)
    return True


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


def _rate_limit_key(request: Request) -> str:
    authorization = request.headers.get('authorization', '')
    scheme, _, token = authorization.partition(' ')
    if scheme.lower() == 'bearer' and token:
        identity = _resolve_identity(token)
        if identity is not None:
            _, principal = identity
            if principal:
                return f'principal:{principal}'
            token_digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
            return f'token:{token_digest}'
    return client_ip(request)


def enforce_rate_limit(request: Request) -> None:
    key = _rate_limit_key(request)
    with _BUCKET_LOCK:
        now = time.time()
        _prune_bucket(_GLOBAL_BUCKETS, now)
        _prune_bucket(_INGEST_BUCKETS, now)
        if len(_GLOBAL_BUCKETS) >= MAX_RATE_LIMIT_KEYS and key not in _GLOBAL_BUCKETS:
            audit_log(request, 'rate_limit', 'key_capacity_exceeded')
            raise HTTPException(status_code=429, detail='Rate limit capacity exceeded')
        if not _check_bucket(_GLOBAL_BUCKETS, key, GLOBAL_RATE_LIMIT_PER_MINUTE, now):
            audit_log(request, 'rate_limit', 'global_exceeded')
            raise HTTPException(status_code=429, detail='Global rate limit exceeded')
        if request.url.path == '/api/ingest':
            if not _check_bucket(_INGEST_BUCKETS, key, INGEST_RATE_LIMIT_PER_MINUTE, now):
                audit_log(request, 'rate_limit', 'ingest_exceeded')
                raise HTTPException(status_code=429, detail='Ingest rate limit exceeded')


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
    if request.method in {'GET', 'HEAD'}:
        return READ_ROLES
    return {'admin'}


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
