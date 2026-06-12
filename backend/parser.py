from __future__ import annotations
import json, re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from .models import Event, parse_time

LINUX = re.compile(r'(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\s+(?P<asset>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)')
WIN = re.compile(r'WinEvent\s+Time=(?P<ts>\S+)\s+Host=(?P<asset>\S+)\s+EventID=(?P<eid>\d+)\s+User=(?P<user>\S+)(?:\s+Process=(?P<proc>\S+))?(?:\s+CommandLine="(?P<cmd>[^"]*)")?.*', re.I)
FW = re.compile(r'(?P<ts>\S+)\s+(?P<asset>\S+)\s+FW\s+action=(?P<action>\S+)\s+src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+dpt=(?P<port>\d+)\s+proto=(?P<proto>\S+)\s+msg="(?P<msg>[^"]*)"', re.I)
WEB = re.compile(r'(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d+)\s+\S+\s+"(?P<ua>[^"]*)"')

def _linux_time(mon, day, clock):
    year = datetime.now(timezone.utc).year
    return datetime.strptime(f'{year} {mon} {int(day)} {clock}', '%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc)

def _linux_user(msg):
    m = re.search(r'invalid user (\S+)', msg) or re.search(r'for (\S+) from', msg)
    return m.group(1) if m else None

def _linux_ip(msg):
    m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
    return m.group(1) if m else None

def parse_event(item: str | dict[str, Any]) -> Event:
    if isinstance(item, dict):
        return Event.from_dict(item)
    raw = str(item).strip()
    if not raw: raise ValueError('empty log line')
    if raw.startswith('{'):
        try: return Event.from_dict(json.loads(raw))
        except json.JSONDecodeError as e: raise ValueError(f'invalid JSON event: {e.msg}') from e
    if m := LINUX.match(raw):
        msg = m.group('msg'); status = 'success' if 'Accepted password' in msg else 'failure' if 'Failed password' in msg else 'unknown'
        return Event(f'evt-{uuid4().hex[:12]}', _linux_time(m.group('mon'),m.group('day'),m.group('clock')), 'linux_auth','ssh_login', m.group('asset'), _linux_user(msg), _linux_ip(msg), None, None, None, status, msg, raw)
    if m := WIN.match(raw):
        eid=m.group('eid'); et='powershell_execution' if eid=='4104' or 'powershell' in raw.lower() else 'admin_account_change' if eid in {'4720','4732'} else 'windows_event'
        return Event(f'evt-{uuid4().hex[:12]}', parse_time(m.group('ts')), 'windows', et, m.group('asset'), m.group('user'), None, None, m.group('proc'), m.group('cmd') or '', 'success', raw, raw)
    if m := FW.match(raw):
        return Event(f'evt-{uuid4().hex[:12]}', parse_time(m.group('ts')), 'firewall', 'network_connection', m.group('asset'), None, m.group('src'), m.group('dst'), None, None, m.group('action').lower(), f"{m.group('msg')} dst_port={m.group('port')} proto={m.group('proto')}", raw)
    if m := WEB.match(raw):
        ts = datetime.strptime(m.group('ts').split()[0], '%d/%b/%Y:%H:%M:%S').replace(tzinfo=timezone.utc)
        return Event(f'evt-{uuid4().hex[:12]}', ts, 'waf', 'http_request', 'web01', None, m.group('src'), None, None, None, m.group('status'), f"{m.group('method')} {m.group('path')} user_agent={m.group('ua')}", raw)
    return Event(f'evt-{uuid4().hex[:12]}', datetime.now(timezone.utc), 'unknown', 'unknown', message=raw, raw_log=raw)

def parse_events(items): return [parse_event(x) for x in items]
