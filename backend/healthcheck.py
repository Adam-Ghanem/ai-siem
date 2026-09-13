from __future__ import annotations

import json
import os
import urllib.request


READ_ROLES = {'viewer', 'analyst', 'admin'}


def resolve_readiness_token() -> str:
    legacy_token = os.getenv('AI_SIEM_API_KEY', '').strip()
    if legacy_token:
        return legacy_token

    raw_keys = os.getenv('AI_SIEM_API_KEYS', '').strip()
    if not raw_keys:
        raise RuntimeError(
            'Container readiness requires AI_SIEM_API_KEY or a read-capable AI_SIEM_API_KEYS token'
        )

    try:
        configured = json.loads(raw_keys)
    except json.JSONDecodeError as exc:
        raise RuntimeError('AI_SIEM_API_KEYS must be valid JSON') from exc
    if not isinstance(configured, dict):
        raise RuntimeError('AI_SIEM_API_KEYS must be a JSON object')

    for token, identity in configured.items():
        if not isinstance(token, str) or not token:
            continue
        if isinstance(identity, str):
            role = identity
        elif isinstance(identity, dict):
            role = identity.get('role')
        else:
            continue
        if role in READ_ROLES:
            return token

    raise RuntimeError('AI_SIEM_API_KEYS has no read-capable readiness token')


def main() -> None:
    token = resolve_readiness_token()
    request = urllib.request.Request(
        'http://127.0.0.1:8000/api/ready',
        headers={'Authorization': f'Bearer {token}'},
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        response.read()


if __name__ == '__main__':
    main()
