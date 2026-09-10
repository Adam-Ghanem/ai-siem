#!/usr/bin/env python3
"""
AI-SIEM Linux log agent.

Tails real local log files and sends new lines to the AI-SIEM /api/ingest endpoint.
Designed for an authorized lab host that you own or administer.
"""
from __future__ import annotations
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

DEFAULT_FILES = [
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/nginx/access.log',
    '/var/log/apache2/access.log',
]


def post_logs(api: str, token: str, lines: list[str]) -> None:
    if not lines:
        return
    payload = json.dumps({'logs': lines}).encode('utf-8')
    req = urllib.request.Request(
        api.rstrip('/') + '/api/ingest',
        data=payload,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'ai-siem-linux-agent/1.0',
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode('utf-8', errors='replace')
        print(f'[sent] {len(lines)} lines -> {resp.status} {body}')


def read_new_lines(path: Path, offsets: dict[str, int], max_lines: int) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    key = str(path)
    current_size = path.stat().st_size
    offset = offsets.get(key, current_size)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        offset = current_size
    if offset > current_size:
        offset = 0
    lines: list[str] = []
    with path.open('r', encoding='utf-8', errors='replace') as handle:
        handle.seek(offset)
        for line in handle:
            clean = line.strip()
            if clean:
                lines.append(clean)
            if len(lines) >= max_lines:
                break
        offsets[key] = handle.tell()
    return lines


def process_file(
    path: Path,
    offsets: dict[str, int],
    max_lines: int,
    sender: Callable[[list[str]], None],
) -> list[str]:
    key = str(path)
    had_offset = key in offsets
    previous_offset = offsets.get(key)
    lines = read_new_lines(path, offsets, max_lines)
    if not lines:
        return []

    try:
        sender(lines)
    except Exception:
        if had_offset:
            offsets[key] = previous_offset
        else:
            offsets.pop(key, None)
        raise
    return lines


def load_offsets(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): value
        for key, value in payload.items()
        if isinstance(key, str)
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    }


def save_offsets(path: Path, offsets: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    try:
        with temp_path.open('w', encoding='utf-8') as handle:
            json.dump(offsets, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description='Tail real Linux/web logs and ingest them into AI-SIEM.')
    parser.add_argument('--api', default='http://localhost:8000', help='AI-SIEM backend URL')
    parser.add_argument('--token', required=True, help='AI-SIEM API key')
    parser.add_argument('--file', action='append', dest='files', help='Log file to tail. Can be repeated.')
    parser.add_argument('--state', default='.agent_state/linux_offsets.json', help='Offset state file')
    parser.add_argument('--interval', type=float, default=2.0, help='Polling interval in seconds')
    parser.add_argument('--batch-size', type=int, default=25, help='Max lines per file per send')
    parser.add_argument('--from-start', action='store_true', help='Read existing file contents from start on first run')
    args = parser.parse_args()

    files = [Path(x) for x in (args.files or DEFAULT_FILES)]
    state_path = Path(args.state)
    offsets = load_offsets(state_path)
    if args.from_start:
        for file in files:
            offsets.setdefault(str(file), 0)

    print('[agent] watching:')
    for file in files:
        print(f'  - {file}')
    print(f'[agent] backend={args.api}')

    while True:
        for file in files:
            try:
                lines = process_file(
                    file,
                    offsets,
                    args.batch_size,
                    lambda batch: post_logs(args.api, args.token, batch),
                )
                if lines:
                    save_offsets(state_path, offsets)
            except urllib.error.HTTPError as exc:
                print(f'[error] backend returned {exc.code}: {exc.read().decode("utf-8", errors="replace")}')
            except Exception as exc:
                print(f'[error] {file}: {exc}')
        time.sleep(args.interval)


if __name__ == '__main__':
    raise SystemExit(main())
