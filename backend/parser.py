from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, TypedDict
from uuid import uuid4

from .models import Event, parse_time

LINUX = re.compile(
    r'(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<clock>\d\d:\d\d:\d\d)\s+(?P<asset>\S+)\s+'
    r'sshd\[\d+\]:\s+(?P<msg>.*)'
)
WIN = re.compile(
    r'WinEvent\s+Time=(?P<ts>\S+)\s+Host=(?P<asset>\S+)\s+'
    r'EventID=(?P<eid>\d+)\s+User=(?P<user>\S+)'
    r'(?:\s+Process=(?P<proc>\S+))?'
    r'(?:\s+CommandLine="(?P<cmd>[^"]*)")?.*',
    re.I,
)
FW = re.compile(
    r'(?P<ts>\S+)\s+(?P<asset>\S+)\s+FW\s+'
    r'action=(?P<action>\S+)\s+src=(?P<src>\S+)\s+'
    r'dst=(?P<dst>\S+)\s+dpt=(?P<port>\d+)\s+'
    r'proto=(?P<proto>\S+)\s+msg="(?P<msg>[^"]*)"',
    re.I,
)
WEB = re.compile(
    r'(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+\S+\s+"(?P<ua>[^"]*)"'
)


class ParserStats(TypedDict):
    parsed_events: int
    parsing_failed_events: int
    unknown_events: int
    unknown_samples: list[str]


PARSER_STATS: ParserStats = {
    'parsed_events': 0,
    'parsing_failed_events': 0,
    'unknown_events': 0,
    'unknown_samples': [],
}


def reset_parser_stats() -> None:
    PARSER_STATS.update(
        {
            'parsed_events': 0,
            'parsing_failed_events': 0,
            'unknown_events': 0,
            'unknown_samples': [],
        }
    )


def parser_stats() -> ParserStats:
    return {
        'parsed_events': PARSER_STATS['parsed_events'],
        'parsing_failed_events': PARSER_STATS['parsing_failed_events'],
        'unknown_events': PARSER_STATS['unknown_events'],
        'unknown_samples': list(PARSER_STATS['unknown_samples']),
    }


def _unknown(raw: object) -> Event:
    PARSER_STATS['unknown_events'] += 1
    if len(PARSER_STATS['unknown_samples']) < 10:
        PARSER_STATS['unknown_samples'].append(str(raw)[:200])
    return Event(
        f'evt-{uuid4().hex[:12]}',
        datetime.now(timezone.utc),
        'unknown',
        'unknown',
        message=str(raw),
        raw_log=str(raw),
    )


def _linux_time(month: str, day: str, clock: str) -> datetime:
    year = datetime.now(timezone.utc).year
    return datetime.strptime(
        f'{year} {month} {int(day)} {clock}', '%Y %b %d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)


def _linux_user(message: str) -> str | None:
    match = re.search(r'invalid user (\S+)', message) or re.search(
        r'for (?:invalid user )?(\S+) from', message
    )
    return match.group(1) if match else None


def _linux_ip(message: str) -> str | None:
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
    return match.group(1) if match else None


def _ssh_status(message: str) -> str:
    lowered = message.lower()
    if lowered.startswith('accepted '):
        return 'success'
    if lowered.startswith('failed '):
        return 'failure'
    return 'unknown'


def parse_event(item: str | dict[str, Any]) -> Event:
    try:
        if isinstance(item, dict):
            event = Event.from_dict(item)
            PARSER_STATS['parsed_events'] += 1
            return event

        raw = str(item).strip()
        if not raw:
            raise ValueError('empty log line')
        if raw.startswith('{'):
            event = Event.from_dict(json.loads(raw))
            PARSER_STATS['parsed_events'] += 1
            return event

        if match := LINUX.match(raw):
            message = match.group('msg')
            PARSER_STATS['parsed_events'] += 1
            return Event(
                f'evt-{uuid4().hex[:12]}',
                _linux_time(
                    match.group('mon'),
                    match.group('day'),
                    match.group('clock'),
                ),
                'linux_auth',
                'ssh_login',
                match.group('asset'),
                _linux_user(message),
                _linux_ip(message),
                None,
                None,
                None,
                _ssh_status(message),
                message,
                raw,
            )

        if match := WIN.match(raw):
            event_id = match.group('eid')
            if event_id == '4104' or 'powershell' in raw.lower():
                event_type = 'powershell_execution'
            elif event_id in {'4720', '4732'}:
                event_type = 'admin_account_change'
            else:
                event_type = 'windows_event'
            PARSER_STATS['parsed_events'] += 1
            return Event(
                f'evt-{uuid4().hex[:12]}',
                parse_time(match.group('ts')),
                'windows',
                event_type,
                match.group('asset'),
                match.group('user'),
                None,
                None,
                match.group('proc'),
                match.group('cmd') or '',
                'success',
                raw,
                raw,
            )

        if match := FW.match(raw):
            PARSER_STATS['parsed_events'] += 1
            message = (
                f"{match.group('msg')} dst_port={match.group('port')} "
                f"proto={match.group('proto')}"
            )
            return Event(
                f'evt-{uuid4().hex[:12]}',
                parse_time(match.group('ts')),
                'firewall',
                'network_connection',
                match.group('asset'),
                None,
                match.group('src'),
                match.group('dst'),
                None,
                None,
                match.group('action').lower(),
                message,
                raw,
            )

        if match := WEB.match(raw):
            timestamp = datetime.strptime(
                match.group('ts').split()[0], '%d/%b/%Y:%H:%M:%S'
            ).replace(tzinfo=timezone.utc)
            PARSER_STATS['parsed_events'] += 1
            message = (
                f"{match.group('method')} {match.group('path')} "
                f"user_agent={match.group('ua')}"
            )
            return Event(
                f'evt-{uuid4().hex[:12]}',
                timestamp,
                'waf',
                'http_request',
                'web01',
                None,
                match.group('src'),
                None,
                None,
                None,
                match.group('status'),
                message,
                raw,
            )

        return _unknown(raw)
    except Exception:
        PARSER_STATS['parsing_failed_events'] += 1
        raise


def parse_events(items: Iterable[str | dict[str, Any]]) -> list[Event]:
    return [parse_event(item) for item in items]
