from __future__ import annotations

from collections import Counter

from .event_model import Alert, Incident, NormalizedEvent

SEVERITY_WEIGHT = {'critical': 20, 'high': 12, 'medium': 6, 'low': 2}
PRIORITY_WEIGHT = {'P1': 25, 'P2': 14, 'P3': 6}


def calculate_metrics(events: list[NormalizedEvent], alerts: list[Alert], incidents: list[Incident]) -> dict:
    severity_score = sum(SEVERITY_WEIGHT.get(a.severity, 1) for a in alerts)
    incident_score = sum(PRIORITY_WEIGHT.get(i.priority, 1) for i in incidents if i.status == 'open')
    risk_score = min(100, severity_score + incident_score)
    return {
        'total_events': len(events),
        'total_alerts': len(alerts),
        'critical_alerts': sum(1 for a in alerts if a.severity == 'critical'),
        'high_alerts': sum(1 for a in alerts if a.severity == 'high'),
        'open_incidents': sum(1 for i in incidents if i.status == 'open'),
        'risk_score': risk_score,
        'top_tactics': dict(Counter(a.tactic for a in alerts).most_common(5)),
        'source_distribution': dict(Counter(e.source for e in events)),
        'event_type_distribution': dict(Counter(e.event_type for e in events)),
    }
