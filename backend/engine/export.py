from __future__ import annotations

from .event_model import Alert, Incident, NormalizedEvent, Anomaly


def soc_snapshot(events: list[NormalizedEvent], alerts: list[Alert], incidents: list[Incident], anomalies: list[Anomaly], metrics: dict) -> dict:
    return {
        'summary': metrics,
        'events': [e.to_dict() for e in events],
        'alerts': [a.to_dict() for a in alerts],
        'incidents': [i.to_dict() for i in incidents],
        'anomalies': [a.to_dict() for a in anomalies],
    }
