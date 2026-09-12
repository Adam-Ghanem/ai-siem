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


def _entity_values(alert: Alert) -> tuple[str | None, str | None, str | None]:
    return alert.asset, alert.user, alert.src_ip


def _matches_group_entities(
    alert: Alert,
    assets: set[str],
    users: set[str],
    src_ips: set[str],
) -> bool:
    asset, user, src_ip = _entity_values(alert)
    return bool(
        (asset and asset in assets)
        or (user and user in users)
        or (src_ip and src_ip in src_ips)
    )


def _add_group_entities(
    alert: Alert,
    assets: set[str],
    users: set[str],
    src_ips: set[str],
) -> None:
    asset, user, src_ip = _entity_values(alert)
    if asset:
        assets.add(asset)
    if user:
        users.add(user)
    if src_ip:
        src_ips.add(src_ip)


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
        group_assets: set[str] = set()
        group_users: set[str] = set()
        group_src_ips: set[str] = set()
        _add_group_entities(anchor, group_assets, group_users, group_src_ips)

        # Every candidate considered here is inside the anchor-bounded incident
        # window. Because members are also inside that same forward-only window,
        # temporal proximity is guaranteed; correlation therefore only needs an
        # O(1) membership check against the entities already present in the group.
        # Adding each accepted candidate's entities preserves transitive chains
        # without rescanning an ever-growing list of prior members.
        for candidate in islice(ordered, anchor_index + 1, None):
            if candidate.timestamp.timestamp() > window_end:
                break
            if candidate.alert_id in used:
                continue
            if _matches_group_entities(candidate, group_assets, group_users, group_src_ips):
                group.append(candidate)
                used.add(candidate.alert_id)
                _add_group_entities(candidate, group_assets, group_users, group_src_ips)

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
