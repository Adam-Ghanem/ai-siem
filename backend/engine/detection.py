from __future__ import annotations

import re
from collections import defaultdict
from uuid import uuid4

from .event_model import Alert, NormalizedEvent
from .rules import RULES

SEVERITY_ACTIONS = {
    'critical': 'Escalate immediately, preserve evidence, and contain affected asset if confirmed.',
    'high': 'Review evidence, validate scope, and apply containment if unauthorized.',
    'medium': 'Investigate context, tune if benign, and monitor for progression.',
    'low': 'Document and monitor.'
}

PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')


def _value(event: NormalizedEvent, field: str):
    return getattr(event, field, None)


def _matches_static(rule: dict, event: NormalizedEvent) -> bool:
    for field, expected in rule.get('field_equals', {}).items():
        if _value(event, field) != expected:
            return False
    for field, values in rule.get('contains', {}).items():
        haystack = str(_value(event, field) or '').lower()
        if values and not any(str(v).lower() in haystack for v in values):
            return False
    for field, patterns in rule.get('regex', {}).items():
        haystack = str(_value(event, field) or '')
        if patterns and not any(re.search(p, haystack) for p in patterns):
            return False
    return True


def _group_key(event: NormalizedEvent, fields: list[str]) -> tuple:
    return tuple(_value(event, field) for field in fields)


def _evidence(event: NormalizedEvent, fields: list[str]) -> str:
    parts = []
    for field in fields:
        val = _value(event, field)
        if val:
            parts.append(f'{field}={val}')
    return '; '.join(parts) or event.raw_log


def _make_alert(rule: dict, events: list[NormalizedEvent]) -> Alert:
    latest = max(events, key=lambda e: e.timestamp)
    return Alert(
        alert_id=f"AL-{uuid4().hex[:10]}",
        rule_id=rule['rule_id'],
        title=rule['name'],
        severity=rule['severity'],
        confidence=rule['confidence'],
        tactic=rule['tactic'],
        technique=rule['technique'],
        timestamp=latest.timestamp,
        asset=latest.asset,
        user=latest.user,
        src_ip=latest.src_ip,
        event_ids=[e.id for e in events],
        evidence=[_evidence(e, rule.get('evidence_fields', [])) for e in events][-10:],
        recommended_action=SEVERITY_ACTIONS.get(rule['severity'], SEVERITY_ACTIONS['medium']),
    )


def run_detections(events: list[NormalizedEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    seen_thresholds: set[tuple[str, tuple, str]] = set()
    historical_sources: dict[str, set[str]] = defaultdict(set)
    failed_logins: dict[tuple[str | None, str | None], list[NormalizedEvent]] = defaultdict(list)

    for idx, event in enumerate(sorted_events):
        if event.event_type == 'ssh_login' and event.status == 'failure':
            failed_logins[(event.src_ip, event.user)].append(event)

        for rule in RULES:
            if not _matches_static(rule, event):
                continue

            if rule['rule_id'] == 'DET-SSH-002':
                prior = [e for (src, user), vals in failed_logins.items() if src == event.src_ip and (user == event.user or user is None) for e in vals if 0 <= (event.timestamp - e.timestamp).total_seconds() <= rule['time_window_minutes'] * 60]
                if len(prior) >= rule['threshold']:
                    alerts.append(_make_alert(rule, prior + [event]))
                continue

            if rule['rule_id'] == 'DET-AI-001':
                known = historical_sources[event.user]
                if event.user and event.src_ip and known and event.src_ip not in known:
                    alerts.append(_make_alert(rule, [event]))
                if event.user and event.src_ip:
                    known.add(event.src_ip)
                continue

            if rule['rule_id'] == 'DET-AI-002':
                if event.user in {'root','admin','administrator'} and (event.timestamp.hour < 7 or event.timestamp.hour >= 20):
                    alerts.append(_make_alert(rule, [event]))
                continue

            group_fields = rule.get('group_by', [])
            key = _group_key(event, group_fields)
            window = [e for e in sorted_events[:idx+1] if _matches_static(rule, e) and _group_key(e, group_fields) == key and 0 <= (event.timestamp - e.timestamp).total_seconds() <= rule['time_window_minutes'] * 60]
            distinct_field = rule.get('distinct_field')
            count = len({getattr(e, distinct_field) for e in window if getattr(e, distinct_field)}) if distinct_field else len(window)
            marker = (rule['rule_id'], key, event.timestamp.isoformat()[:16])
            if count >= rule['threshold'] and marker not in seen_thresholds:
                alerts.append(_make_alert(rule, window))
                seen_thresholds.add(marker)

    return alerts
