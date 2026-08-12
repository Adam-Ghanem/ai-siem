from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import Event, parse_time

LINUX = re.compile(
    r'(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\s+'
    r'(?P<asset>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)'
)
FW = re.compile(
    r'(?P<ts>\S+)\s+(?P<asset>\S+)\s+FW\s+action=(?P<action>\S+)\s+'
    r'src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+dpt=(?P<port>\d+)\s+'
    r'proto=(?P<proto>\S+)\s+msg="(?P<msg>[^"]*)"',
    re.I,
)
WEB = re.compile(
    r'(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+\S+\s+"(?P<ua>[^"]*)"'
)
KEY_VALUE = re.compile(
    r'(?P<key>[A-Za-z][A-Za-z0-9_.-]*)='
    r'(?P<value>"(?:\\.|[^"\\])*"|\S+)'
)
WINDOWS_PREFIX = re.compile(r'^(?P<prefix>WinEvent|WindowsEvent|Sysmon)\b', re.I)

WINDOWS_EVENT_TYPES = {
    '4624': ('windows_logon', 'success'),
    '4625': ('windows_logon', 'failure'),
    '4688': ('process_creation', 'observed'),
    '4104': ('powershell_execution', 'observed'),
    '4720': ('admin_account_change', 'observed'),
    '4732': ('admin_account_change', 'observed'),
}
SYSMON_EVENT_TYPES = {
    '1': ('process_creation', 'observed'),
    '3': ('network_connection', 'observed'),
    '7': ('image_load', 'observed'),
    '10': ('process_access', 'observed'),
    '11': ('file_creation', 'observed'),
    '12': ('registry_event', 'observed'),
    '13': ('registry_event', 'observed'),
    '22': ('dns_query', 'observed'),
}
MAX_NORMALIZED_FIELD_LENGTH = 4096
PARSER_STATS = {
    'parsed_events': 0,
    'parsing_failed_events': 0,
    'unknown_events': 0,
    'unknown_samples': [],
}
_STATS_LOCK = threading.Lock()


def reset_parser_stats():
    with _STATS_LOCK:
        PARSER_STATS.update(
            {
                'parsed_events': 0,
                'parsing_failed_events': 0,
                'unknown_events': 0,
                'unknown_samples': [],
            }
        )


def parser_stats():
    with _STATS_LOCK:
        return {
            **PARSER_STATS,
            'unknown_samples': list(PARSER_STATS['unknown_samples']),
        }


def _increment(name: str) -> None:
    with _STATS_LOCK:
        PARSER_STATS[name] += 1


def _bounded(value: Any, limit: int = MAX_NORMALIZED_FIELD_LENGTH) -> str:
    return str(value or '')[:limit]


def _unknown(raw):
    _increment('unknown_events')
    with _STATS_LOCK:
        if len(PARSER_STATS['unknown_samples']) < 10:
            PARSER_STATS['unknown_samples'].append(_bounded(raw, 200))
    return Event(
        f'evt-{uuid4().hex[:12]}',
        datetime.now(timezone.utc),
        'unknown',
        'unknown',
        message=_bounded(raw),
        raw_log=_bounded(raw),
    )


def _linux_time(mon, day, clock):
    year = datetime.now(timezone.utc).year
    return datetime.strptime(
        f'{year} {mon} {int(day)} {clock}', '%Y %b %d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)


def _linux_user(msg):
    match = re.search(r'invalid user (\S+)', msg) or re.search(
        r'for (?:invalid user )?(\S+) from', msg
    )
    return match.group(1) if match else None


def _linux_ip(msg):
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
    return match.group(1) if match else None


def _ssh_status(msg):
    lowered = msg.lower()
    if lowered.startswith('accepted '):
        return 'success'
    if lowered.startswith('failed '):
        return 'failure'
    return 'unknown'


def _mapping(data: dict[str, Any]) -> dict[str, Any]:
    return {str(key).lower(): value for key, value in data.items()}


def _pick(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key.lower())
        if value not in (None, ''):
            return value
    return None


def _looks_like_windows_mapping(data: dict[str, Any]) -> bool:
    lowered = _mapping(data)
    source = str(_pick(lowered, 'source', 'provider', 'log_source') or '').lower()
    return bool(
        _pick(lowered, 'eventid', 'event_id', 'eid')
        or source in {'windows', 'sysmon'}
        or 'sysmon' in source
    )


def _parse_windows_mapping(data: dict[str, Any], raw: str) -> Event:
    lowered = _mapping(data)
    source_hint = str(
        _pick(lowered, 'source', 'provider', 'log_source') or ''
    ).lower()
    event_id = _bounded(_pick(lowered, 'eventid', 'event_id', 'eid') or 'unknown', 32)
    is_sysmon = source_hint == 'sysmon' or 'sysmon' in source_hint
    event_types = SYSMON_EVENT_TYPES if is_sysmon else WINDOWS_EVENT_TYPES
    event_type, default_status = event_types.get(
        event_id, ('sysmon_event' if is_sysmon else 'windows_event', 'observed')
    )
    status = _bounded(_pick(lowered, 'status') or default_status, 32)
    asset = _bounded(_pick(lowered, 'asset', 'host', 'hostname', 'computer') or 'unknown', 256)
    user = _bounded(
        _pick(lowered, 'user', 'targetusername', 'subjectusername', 'accountname') or '',
        256,
    ) or None
    process_name = _bounded(
        _pick(lowered, 'process_name', 'process', 'processname', 'image', 'newprocessname') or '',
        1024,
    ) or None
    command_line = _bounded(
        _pick(lowered, 'command_line', 'commandline', 'scriptblocktext') or '',
        MAX_NORMALIZED_FIELD_LENGTH,
    ) or None
    src_ip = _bounded(
        _pick(lowered, 'src_ip', 'sourceip', 'ipaddress') or '', 128
    ) or None
    dst_ip = _bounded(
        _pick(lowered, 'dst_ip', 'destinationip') or '', 128
    ) or None
    message = _bounded(
        _pick(lowered, 'message')
        or f'EventID={event_id} source={"sysmon" if is_sysmon else "windows"}',
        MAX_NORMALIZED_FIELD_LENGTH,
    )
    return Event(
        f'evt-{uuid4().hex[:12]}',
        parse_time(_pick(lowered, 'timestamp', 'time', 'eventtime')),
        'sysmon' if is_sysmon else 'windows',
        event_type,
        asset,
        user,
        src_ip,
        dst_ip,
        process_name,
        command_line,
        status,
        message,
        _bounded(raw),
        str(_pick(lowered, 'tenant_id') or 'default'),
        event_id,
    )


def _parse_windows_kv(raw: str) -> Event:
    fields = {}
    for match in KEY_VALUE.finditer(raw):
        value = match.group('value')
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('\\"', '"').replace('\\n', '\n')
        fields[match.group('key').lower()] = value
    prefix = WINDOWS_PREFIX.match(raw)
    if prefix and prefix.group('prefix').lower() == 'sysmon':
        fields.setdefault('source', 'sysmon')
    elif prefix:
        fields.setdefault('source', 'windows')
    return _parse_windows_mapping(fields, raw)


def parse_event(item: str | dict[str, Any]) -> Event:
    try:
        if isinstance(item, dict):
            if _looks_like_windows_mapping(item):
                event = _parse_windows_mapping(item, json.dumps(item, ensure_ascii=False))
            else:
                event = Event.from_dict(item)
            _increment('parsed_events')
            return event
        raw = str(item).strip()
        if not raw:
            raise ValueError('empty log line')
        if raw.startswith('{'):
            return parse_event(json.loads(raw))
        if WINDOWS_PREFIX.match(raw) or re.search(r'\bEventID=', raw, re.I):
            event = _parse_windows_kv(raw)
            _increment('parsed_events')
            return event
        if m := LINUX.match(raw):
            msg = m.group('msg')
            event = Event(
                f'evt-{uuid4().hex[:12]}',
                _linux_time(m.group('mon'), m.group('day'), m.group('clock')),
                'linux_auth',
                'ssh_login',
                m.group('asset'),
                _linux_user(msg),
                _linux_ip(msg),
                None,
                None,
                None,
                _ssh_status(msg),
                msg,
                raw,
            )
            _increment('parsed_events')
            return event
        if m := FW.match(raw):
            event = Event(
                f'evt-{uuid4().hex[:12]}',
                parse_time(m.group('ts')),
                'firewall',
                'network_connection',
                m.group('asset'),
                None,
                m.group('src'),
                m.group('dst'),
                None,
                None,
                m.group('action').lower(),
                f"{m.group('msg')} dst_port={m.group('port')} proto={m.group('proto')}",
                raw,
            )
            _increment('parsed_events')
            return event
        if m := WEB.match(raw):
            timestamp = datetime.strptime(
                m.group('ts').split()[0], '%d/%b/%Y:%H:%M:%S'
            ).replace(tzinfo=timezone.utc)
            event = Event(
                f'evt-{uuid4().hex[:12]}',
                timestamp,
                'waf',
                'http_request',
                'web01',
                None,
                m.group('src'),
                None,
                None,
                None,
                m.group('status'),
                f"{m.group('method')} {m.group('path')} user_agent={m.group('ua')}",
                raw,
            )
            _increment('parsed_events')
            return event
        return _unknown(raw)
    except Exception:
        _increment('parsing_failed_events')
        raise


def parse_events(items):
    return [parse_event(item) for item in items]
