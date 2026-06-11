from __future__ import annotations
from uuid import uuid4
from .models import Alert, Incident

PRIORITY = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

def _related(a: Alert, b: Alert) -> bool:
    close = abs((a.timestamp - b.timestamp).total_seconds()) <= 1800
    return close and any([
        a.asset and a.asset == b.asset,
        a.user and a.user == b.user,
        a.src_ip and a.src_ip == b.src_ip,
        a.tactic == b.tactic,
    ])

def correlate(alerts: list[Alert]) -> list[Incident]:
    incidents: list[Incident] = []
    used: set[str] = set()
    ordered = sorted(alerts, key=lambda a: a.timestamp)

    for alert in ordered:
        if alert.alert_id in used:
            continue
        group = [alert]
        used.add(alert.alert_id)
        for other in ordered:
            if other.alert_id not in used and any(_related(other, g) for g in group):
                group.append(other)
                used.add(other.alert_id)

        max_sev = max(group, key=lambda x: PRIORITY.get(x.severity, 0)).severity
        priority = 'P1' if max_sev == 'critical' or len(group) >= 4 else 'P2' if max_sev == 'high' else 'P3'
        timeline = [{'timestamp': a.timestamp.isoformat(), 'alert_id': a.alert_id, 'title': a.title, 'asset': a.asset, 'user': a.user, 'src_ip': a.src_ip} for a in group]
        summary = '; '.join(sorted(set(a.title for a in group)))
        actions = sorted(set(a.recommended_action for a in group))
        incidents.append(Incident(incident_id=f"INC-{uuid4().hex[:8]}", priority=priority, related_alert_ids=[a.alert_id for a in group], evidence_summary=summary, timeline=timeline, recommended_response_actions=actions))
    return incidents
