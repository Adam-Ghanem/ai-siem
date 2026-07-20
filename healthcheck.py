import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

MAX_RESPONSE_BYTES = 1024 * 1024
LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
ENDPOINTS = [
    ('/api/health', False),
    ('/api/metrics', True),
    ('/api/alerts?limit=1', True),
    ('/api/incidents?limit=1', True),
]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def validate_api_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('API URL must be an absolute HTTP or HTTPS URL')
    if parsed.username or parsed.password:
        raise ValueError('API URL must not contain credentials')
    if parsed.query or parsed.fragment:
        raise ValueError('API URL must not contain a query or fragment')
    if parsed.path not in {'', '/'}:
        raise ValueError('API URL must not contain a path')
    if parsed.scheme != 'https' and parsed.hostname not in LOCAL_HOSTS:
        raise ValueError('Remote health checks require HTTPS')
    return urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))


API_BASE = validate_api_url(os.getenv('AI_SIEM_API_URL', 'http://localhost:8000'))
API_KEY = os.getenv('AI_SIEM_API_KEY', '').strip()


def check(path: str, requires_auth: bool) -> None:
    headers = {}
    if requires_auth:
        if not API_KEY:
            raise RuntimeError('AI_SIEM_API_KEY is required for protected checks')
        headers['Authorization'] = f'Bearer {API_KEY}'
    request = urllib.request.Request(API_BASE + path, headers=headers)
    with _OPENER.open(request, timeout=3) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError('response exceeded safety limit')
        json.loads(body.decode('utf-8'))


def main() -> int:
    ok = True
    for endpoint, protected in ENDPOINTS:
        try:
            check(endpoint, protected)
            print(f'[OK] {API_BASE}{endpoint}')
        except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
            ok = False
            print(f'[FAIL] {API_BASE}{endpoint} -> {str(exc).replace(chr(10), " ")}')

    if not ok:
        return 1

    print('AI-SIEM backend healthcheck passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
