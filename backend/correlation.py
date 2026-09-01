from __future__ import annotations
from hashlib import sha256
from itertools import islice
from .models import Alert, Incident

W = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def _shared_entities(a: Alert, b: Alert) -> set[str]:
    shared = set()
    if a.asset and a.asset == b.asset:
        shared.add('asset')
    if a.user and a.user == b.user:
        shared.add('user')
    if a.src_ip and a.src_ip == b.src_ip:
        shared.add('src_ip')
    return shared


def _rel(a: Alert, b: Alert, window_seconds: int) -> bool:
    close = abs((a.timestamp - b.timestamp).total_seconds()) <= window_seconds
    return close and bool(_shared_entities(a, b))


def _prio(group):
    s = sum(W.get(a.severity, 1) for a in group)
    return 'P1' if any(a.severity == 'critical' for a in group) or s >= 8 else 'P2' if any(a.severity == 'high' for a in group) or s >= 5 else 'P3'


def _stable_incident_id(group: list[Alert]) -> str:
    parts = []
    for a in sorted(group, key=lambda x: x.alert_id):
        parts.extend([a.alert_id, a.rule_id, ','.join(sorted(a.event_ids)), a.asset or '', a.user or '', a.src_ip or ''])
    return 'INC-' + sha256('|'.join(parts).encode('utf-8')).hexdigest()[:10].upper()


def correlate(alerts: list[Alert], window_seconds: int = 1800) -> list[Incident]:
    if window_seconds <= 0:
        raise ValueError('window_seconds must be greater than zero')

    used = set()
    incidents = []
    ordered = sorted(alerts, key=lambda a: a.timestamp)

    for anchor_index, anchor in enumerate(ordered):
        if anchor.alert_id in used:
            continue

        group = [anchor]
        used.add(anchor.alert_id)
        window_end = anchor.timestamp.timestamp() + window_seconds

        # Alerts before the anchor are necessarily already assigned. Starting at
        # the next position avoids rescanning an ever-growing historical prefix.
        # islice keeps this a lazy view instead of copying every suffix.
        for candidate in islice(ordered, anchor_index + 1, None):
            if candidate.timestamp.timestamp() > window_end:
                break
            if candidate.alert_id in used:
                continue
            if any(_rel(candidate, member, window_seconds) for member in group):
                group.append(candidate)
                used.add(candidate.alert_id)

        title = group[0].title if len(group) == 1 else 'Correlated SOC activity: ' + ', '.join(sorted({x.tactic for x in group}))
        incidents.append(
            Incident(
                _stable_incident_id(group),
                title,
                _prio(group),
                'open',
                'unassigned',
                [x.alert_id for x in group],
                sorted({x.asset for x in group if x.asset}),
                sorted({x.user for x in group if x.user}),
                sorted({x.src_ip for x in group if x.src_ip}),
                ' | '.join(sorted({x.title for x in group})),
                [
                    {
                        'timestamp': x.timestamp.isoformat(),
                        'alert_id': x.alert_id,
                        'title': x.title,
                        'severity': x.severity,
                        'asset': x.asset,
                        'user': x.user,
                        'src_ip': x.src_ip,
                        'tactic': x.tactic,
                    }
                    for x in group
                ],
                sorted({x.recommended_action for x in group}),
            )
        )
    return incidents
