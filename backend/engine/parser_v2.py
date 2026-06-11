from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .event_model import NormalizedEvent, parse_ts

LINUX_AUTH = re.compile(r'(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<asset>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)')
WIN_EVENT = re.compile(r'WinEvent\s+Time=(?P<ts>\S+)\s+Host=(?P<asset>\S+)\s+EventID=(?P<event_id>\d+)\s+User=(?P<user>\S+)(?:\s+Process=(?P<process>\S+))?(?:\s+CommandLine="(?P<cmd>[^"]*)")?.*', re.I)
FIREWALL = re.compile(r'(?P<ts>\S+)\s+(?P<asset>\S+)\s+FW\s+action=(?P<action>\S+)\s+src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+dpt=(?P<port>\d+)\s+proto=(?P<proto>\S+)\s+msg="(?P<msg>[^"]*)"', re.I)
WEB = re.compile(r'(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d+)\s+\S+\s+"(?P<ua>[^"]*)"')


def _linux_timestamp(mon: str, day: str, clock: str) -> datetime:
    year = datetime.now(timezone.utc).year
    return datetime.strptime(f'{year} {mon} {int(day)} {clock}', '%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc)


def _linux_user(msg: str) -> str | None:
    invalid = re.search(r'invalid user (\S+)', msg)
    if invalid:
        return invalid.group(1)
    normal = re.search(r'for (\S+) from', msg)
    return normal.group(1) if normal else None


def _linux_ip(msg: str) -> str | None:
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
    return match.group(1) if match else None


def parse_event(item: str | dict[str, Any]) -> NormalizedEvent:
    if isinstance(item, dict):
        return NormalizedEvent.from_dict(item)
    raw = str(item).strip()
    if not raw:
        raise ValueError('Empty log line')
    if raw.startswith('{'):
        try:
            return NormalizedEvent.from_dict(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid JSON event: {exc.msg}') from exc
    if match := LINUX_AUTH.match(raw):
        msg = match.group('msg')
        status = 'success' if 'Accepted password' in msg else 'failure' if 'Failed password' in msg else 'unknown'
        return NormalizedEvent(id=f'evt-{uuid4().hex[:12]}', timestamp=_linux_timestamp(match.group('mon'), match.group('day'), match.group('time')), source='linux_auth', event_type='ssh_login', asset=match.group('asset'), user=_linux_user(msg), src_ip=_linux_ip(msg), status=status, message=msg, raw_log=raw)
    if match := WIN_EVENT.match(raw):
        eid = match.group('event_id')
        event_type = 'powershell_execution' if eid == '4104' or 'powershell' in raw.lower() else 'admin_account_change' if eid in {'4720','4732'} else 'windows_event'
        return NormalizedEvent(id=f'evt-{uuid4().hex[:12]}', timestamp=parse_ts(match.group('ts')), source='windows', event_type=event_type, asset=match.group('asset'), user=match.group('user'), process_name=match.group('process'), command_line=match.group('cmd') or '', status='success', message=raw, raw_log=raw)
    if match := FIREWALL.match(raw):
        return NormalizedEvent(id=f'evt-{uuid4().hex[:12]}', timestamp=parse_ts(match.group('ts')), source='firewall', event_type='network_connection', asset=match.group('asset'), src_ip=match.group('src'), dst_ip=match.group('dst'), status=match.group('action').lower(), message=f"{match.group('msg')} dst_port={match.group('port')} proto={match.group('proto')}", raw_log=raw)
    if match := WEB.match(raw):
        timestamp = datetime.strptime(match.group('ts').split()[0], '%d/%b/%Y:%H:%M:%S').replace(tzinfo=timezone.utc)
        return NormalizedEvent(id=f'evt-{uuid4().hex[:12]}', timestamp=timestamp, source='waf', event_type='http_request', asset='web01', src_ip=match.group('src'), status=match.group('status'), message=f"{match.group('method')} {match.group('path')} user_agent={match.group('ua')}", raw_log=raw)
    return NormalizedEvent(id=f'evt-{uuid4().hex[:12]}', timestamp=datetime.now(timezone.utc), source='unknown', event_type='unknown', message=raw, raw_log=raw)


def parse_events(items: list[str | dict[str, Any]]) -> list[NormalizedEvent]:
    return [parse_event(item) for item in items]
