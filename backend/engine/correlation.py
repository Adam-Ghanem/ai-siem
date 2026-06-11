from __future__ import annotations

from uuid import uuid4

from .event_model import Alert, Incident

SEV_WEIGHT = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def _close(a: Alert, b: Alert, minutes: int = 30) -> bool:
    return abs((a.timestamp - b.timestamp).total_seconds()) <= minutes * 60


def _related(a: Alert, b: Alert) -> bool:
    return _close(a, b) and any([
        a.asset and a.asset == b.asset,
        a.user and a.user == b.user,
        a.src_ip and a.src_ip == b.src_ip,
        a.tactic == b.tactic,
    ])


def _priority(alerts: list[Alert]) -> str:
    score = sum(SEV_WEIGHT.get(a.severity, 1) for a in alerts)
    if any(a.severity == 'critical' for a in alerts) or score >= 8:
        return 'P1'
    if any(a.severity == 'high' for a in alerts) or score >= 5:
        return 'P2'
    return 'P3'


def correlate_alerts(alerts: list[Alert]) -> list[Incident]:
    incidents: list[Incident] = []
    used: set[str] = set()
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    for alert in ordered:
        if alert.alert_id in used:
            continue
        group = [alert]
        used.add(alert.alert_id)
        changed = True
        while changed:
            changed = False
            for other in ordered:
                if other.alert_id in used:
                    continue
                if any(_related(other, member) for member in group):
                    group.append(other)
                    used.add(other.alert_id)
                    changed = True
        related_assets = sorted({a.asset for a in group if a.asset})
        related_users = sorted({a.user for a in group if a.user})
        related_src_ips = sorted({a.src_ip for a in group if a.src_ip})
        timeline = [{'timestamp': a.timestamp.isoformat(), 'alert_id': a.alert_id, 'title': a.title, 'severity': a.severity, 'asset': a.asset, 'user': a.user, 'src_ip': a.src_ip, 'tactic': a.tactic} for a in group]
        title = group[0].title if len(group) == 1 else f"Correlated activity: {', '.join(sorted({a.tactic for a in group}))}"
        incidents.append(Incident(
            incident_id=f"INC-{uuid4().hex[:10]}",
            title=title,
            priority=_priority(group),
            status='open',
            owner='unassigned',
            related_alert_ids=[a.alert_id for a in group],
            related_assets=related_assets,
            related_users=related_users,
            related_src_ips=related_src_ips,
            evidence_summary=' | '.join(sorted({a.title for a in group})),
            timeline=timeline,
            recommended_actions=sorted({a.recommended_action for a in group}),
        ))
    return incidents
