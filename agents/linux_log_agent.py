#!/usr/bin/env python3
"""
AI-SIEM Linux log agent.

Tails authorized local log files and sends committed batches to the AI-SIEM
ingest endpoint. Offsets advance only after the backend accepts a batch.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DEFAULT_FILES = [
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/nginx/access.log',
    '/var/log/apache2/access.log',
]
MAX_RESPONSE_BYTES = 64 * 1024
LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}


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
        raise ValueError('Remote API connections require HTTPS')
    return urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))


def _read_response(response) -> str:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError('Backend response exceeded the safety limit')
    return body.decode('utf-8', errors='replace').replace('\r', ' ').replace('\n', ' ')


def post_logs(api: str, token: str, lines: list[str], timeout: float = 10.0) -> None:
    if not lines:
        return
    payload = json.dumps({'logs': lines}).encode('utf-8')
    request = urllib.request.Request(
        api.rstrip('/') + '/api/ingest',
        data=payload,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'ai-siem-linux-agent/1.1',
        },
    )
    with _OPENER.open(request, timeout=timeout) as response:
        body = _read_response(response)
        print(f'[sent] {len(lines)} lines -> {response.status} {body}')


def read_new_lines(
    path: Path, offset: int | None, max_lines: int
) -> tuple[list[str], int | None]:
    if not path.exists() or not path.is_file():
        return [], offset
    current_size = path.stat().st_size
    start_offset = current_size if offset is None else offset
    if start_offset > current_size:
        start_offset = 0
    lines: list[str] = []
    with path.open('r', encoding='utf-8', errors='replace') as handle:
        handle.seek(start_offset)
        for line in handle:
            clean = line.strip()
            if clean:
                lines.append(clean)
            if len(lines) >= max_lines:
                break
        next_offset = handle.tell()
    return lines, next_offset


def load_offsets(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): value
        for key, value in payload.items()
        if isinstance(value, int) and value >= 0
    }


def save_offsets(path: Path, offsets: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(offsets, indent=2), encoding='utf-8')
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(path)


def _http_error_text(exc: urllib.error.HTTPError) -> str:
    body = exc.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        return 'response exceeded safety limit'
    return body.decode('utf-8', errors='replace').replace('\r', ' ').replace('\n', ' ')


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Tail authorized Linux/web logs and ingest them into AI-SIEM.'
    )
    parser.add_argument(
        '--api', default='http://localhost:8000', help='AI-SIEM backend URL'
    )
    parser.add_argument(
        '--token',
        default=os.getenv('AI_SIEM_API_KEY', ''),
        help='AI-SIEM API key; prefer the AI_SIEM_API_KEY environment variable',
    )
    parser.add_argument(
        '--file',
        action='append',
        dest='files',
        help='Log file to tail. Can be repeated.',
    )
    parser.add_argument(
        '--state', default='.agent_state/linux_offsets.json', help='Offset state file'
    )
    parser.add_argument(
        '--interval', type=float, default=2.0, help='Polling interval in seconds'
    )
    parser.add_argument(
        '--batch-size', type=int, default=25, help='Max lines per file per send'
    )
    parser.add_argument(
        '--from-start',
        action='store_true',
        help='Read existing file contents from start on first run',
    )
    args = parser.parse_args()

    try:
        api = validate_api_url(args.api)
    except ValueError as exc:
        parser.error(str(exc))
    token = args.token.strip()
    if not token:
        parser.error('Set AI_SIEM_API_KEY or provide --token')
    if not 0.1 <= args.interval <= 3600:
        parser.error('--interval must be between 0.1 and 3600 seconds')
    if not 1 <= args.batch_size <= 100:
        parser.error('--batch-size must be between 1 and 100')

    files = [Path(value) for value in (args.files or DEFAULT_FILES)]
    state_path = Path(args.state)
    offsets = load_offsets(state_path)
    if args.from_start:
        for file in files:
            offsets.setdefault(str(file), 0)

    print('[agent] watching:')
    for file in files:
        print(f'  - {file}')
    print(f'[agent] backend={api}')

    try:
        while True:
            for file in files:
                key = str(file)
                try:
                    lines, next_offset = read_new_lines(
                        file, offsets.get(key), args.batch_size
                    )
                    if lines:
                        post_logs(api, token, lines)
                        if next_offset is not None:
                            offsets[key] = next_offset
                            save_offsets(state_path, offsets)
                    elif next_offset is not None and offsets.get(key) != next_offset:
                        offsets[key] = next_offset
                        save_offsets(state_path, offsets)
                except urllib.error.HTTPError as exc:
                    print(
                        f'[error] backend returned {exc.code}: {_http_error_text(exc)}'
                    )
                except (OSError, RuntimeError, urllib.error.URLError) as exc:
                    print(f'[error] {file}: {str(exc).replace(chr(10), " ")}')
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print('\n[agent] stopped')
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
