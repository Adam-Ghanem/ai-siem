from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from .security_types import AuthContext


class JWTValidationError(ValueError):
    pass


def _decode_part(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise JWTValidationError('malformed JWT encoding') from exc


def _string_claim(payload: dict[str, Any], name: str, max_length: int = 256) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise JWTValidationError(f'invalid JWT {name} claim')
    return value.strip()


def verify_hs256(
    token: str,
    secret: str,
    issuer: str,
    audience: str,
    clock_skew_seconds: int = 30,
) -> AuthContext:
    if not secret:
        raise JWTValidationError('JWT is not configured')
    if len(token) > 4096:
        raise JWTValidationError('JWT is too large')
    parts = token.split('.')
    if len(parts) != 3:
        raise JWTValidationError('JWT must contain three segments')
    encoded_header, encoded_payload, encoded_signature = parts
    try:
        header = json.loads(_decode_part(encoded_header))
        payload = json.loads(_decode_part(encoded_payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JWTValidationError('JWT contains invalid JSON') from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTValidationError('JWT header and payload must be objects')
    if header.get('alg') != 'HS256' or header.get('typ', 'JWT') != 'JWT':
        raise JWTValidationError('unsupported JWT algorithm or type')
    signed = f'{encoded_header}.{encoded_payload}'.encode('ascii')
    expected = hmac.new(secret.encode('utf-8'), signed, hashlib.sha256).digest()
    supplied = _decode_part(encoded_signature)
    if not hmac.compare_digest(expected, supplied):
        raise JWTValidationError('invalid JWT signature')

    now = int(time.time())
    exp = payload.get('exp')
    if not isinstance(exp, (int, float)) or now >= int(exp) + clock_skew_seconds:
        raise JWTValidationError('JWT is expired or has no valid exp claim')
    nbf = payload.get('nbf')
    if nbf is not None and (not isinstance(nbf, (int, float)) or now + clock_skew_seconds < int(nbf)):
        raise JWTValidationError('JWT is not active yet')
    iat = payload.get('iat')
    if iat is not None and (not isinstance(iat, (int, float)) or int(iat) > now + clock_skew_seconds):
        raise JWTValidationError('JWT iat is in the future')
    if payload.get('iss') != issuer:
        raise JWTValidationError('JWT issuer mismatch')
    token_audience = payload.get('aud')
    if token_audience != audience and not (
        isinstance(token_audience, list) and audience in token_audience
    ):
        raise JWTValidationError('JWT audience mismatch')

    principal_id = _string_claim(payload, 'sub')
    tenant_id = _string_claim(payload, 'tenant_id')
    roles = payload.get('roles')
    if not isinstance(roles, list) or not roles:
        raise JWTValidationError('JWT roles claim must be a non-empty list')
    normalized_roles = frozenset(
        str(role).strip().lower() for role in roles if isinstance(role, str) and role.strip()
    )
    allowed_roles = {'admin', 'reader', 'ingestor', 'analyst', 'responder', 'viewer'}
    if not normalized_roles or not normalized_roles.issubset(allowed_roles):
        raise JWTValidationError('JWT contains unsupported roles')
    if 'viewer' in normalized_roles:
        normalized_roles = frozenset(set(normalized_roles) | {'reader'})
    return AuthContext(principal_id, tenant_id, normalized_roles)
