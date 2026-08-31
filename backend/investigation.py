from __future__ import annotations

from typing import Any

from .models import Alert, Anomaly, Event, Incident

_SEVERITY_WEIGHT = {
    'critical': 35,
    'high': 24,
    'medium': 14,
    'low': 6,
}
_PRIORITY_BASE = {'P1': 55, 'P2': 38, 'P3': 22}


def _risk_level(score: int) -> str:
    if score >= 85:
        return 'critical'
    if score >= 65:
        return 'high'
    if score >= 40:
        return 'medium'
    return 'low'


def _related_anomalies(incident: Incident, anomalies: list[Anomaly]) -> list[Anomaly]:
    alert_event_ids = set()
    for anomaly in anomalies:
        if alert_event_ids.intersection(anomaly.related_event_ids):
            continue
    return [
        anomaly
        for anomaly in anomalies
        if anomaly.entity in incident.related_assets
        or anomaly.entity in incident.related_users
        or anomaly.entity in incident.related_src_ips
    ]


def build_investigation(
    incident: Incident,
    alerts: list[Alert],
    events: list[Event],
    anomalies: list[Anomaly],
) -> dict[str, Any]:
    related_alert_ids = set(incident.related_alert_ids)
    related_alerts = [a for a in alerts if a.alert_id in related_alert_ids]
    related_event_ids = {
        event_id
        for alert in related_alerts
        for event_id in alert.event_ids
    }
    related_events = [event for event in events if event.id in related_event_ids]
    related_anomalies = _related_anomalies(incident, anomalies)

    severity_bonus = max(
        (_SEVERITY_WEIGHT.get(alert.severity, 0) for alert in related_alerts),
        default=0,
    )
    correlation_bonus = min(max(len(related_alerts) - 1, 0) * 7, 21)
    anomaly_bonus = min(
        round(sum(a.anomaly_score for a in related_anomalies) * 6),
        18,
    )
    risk_score = min(
        100,
        _PRIORITY_BASE.get(incident.priority, 20)
        + severity_bonus
        + correlation_bonus
        + anomaly_bonus,
    )

    confidence = round(
        sum(alert.confidence for alert in related_alerts) / max(len(related_alerts), 1),
        3,
    )
    techniques = sorted({alert.technique for alert in related_alerts if alert.technique})
    tactics = sorted({alert.tactic for alert in related_alerts if alert.tactic})

    key_evidence: list[str] = []
    for alert in related_alerts:
        for evidence in alert.evidence:
            if evidence and evidence not in key_evidence:
                key_evidence.append(evidence)
    for anomaly in related_anomalies:
        text = f'Anomaly {anomaly.anomaly_id}: {anomaly.reason}'
        if text not in key_evidence:
            key_evidence.append(text)
    if not key_evidence and incident.evidence_summary:
        key_evidence.append(incident.evidence_summary)

    actions = list(dict.fromkeys(action for action in incident.recommended_actions if action))
    if related_anomalies:
        for anomaly in related_anomalies:
            if anomaly.recommended_action and anomaly.recommended_action not in actions:
                actions.append(anomaly.recommended_action)

    entities = []
    if incident.related_assets:
        entities.append(f"assets={','.join(incident.related_assets)}")
    if incident.related_users:
        entities.append(f"users={','.join(incident.related_users)}")
    if incident.related_src_ips:
        entities.append(f"source_ips={','.join(incident.related_src_ips)}")
    entity_text = '; '.join(entities) if entities else 'no scoped entities'

    summary = (
        f'{incident.priority} incident with {len(related_alerts)} related alert(s), '
        f'{len(related_events)} supporting event(s), and {len(related_anomalies)} '
        f'related anomaly signal(s). Activity spans '
        f"{', '.join(tactics) if tactics else 'unmapped tactics'}; {entity_text}."
    )

    return {
        'incident_id': incident.incident_id,
        'risk_score': risk_score,
        'risk_level': _risk_level(risk_score),
        'confidence': confidence,
        'summary': summary,
        'key_evidence': key_evidence[:12],
        'mitre_tactics': tactics,
        'mitre_techniques': techniques,
        'related_alert_ids': [alert.alert_id for alert in related_alerts],
        'related_event_ids': sorted(related_event_ids),
        'related_anomaly_ids': [a.anomaly_id for a in related_anomalies],
        'blast_radius': {
            'assets': incident.related_assets,
            'users': incident.related_users,
            'source_ips': incident.related_src_ips,
        },
        'recommended_actions': actions[:10],
        'grounding': {
            'mode': 'deterministic-evidence',
            'generated_from': ['incident', 'alerts', 'events', 'anomalies'],
            'external_model_used': False,
        },
    }
