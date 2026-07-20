"""Bounded, de-identified SOC summaries and evidence exports."""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f'{name} must be an integer') from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f'{name} must be between {minimum} and {maximum}')
    return value


MAX_EXPORT_ROWS = _bounded_int('AI_SIEM_MAX_EXPORT_ROWS', 2000, 1, 10_000)
_IP_ADDRESS = re.compile(
    r'(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])'
)
_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@')
CSV_FIELDS = (
    'record_type',
    'record_id',
    'title',
    'severity_or_priority',
    'status',
    'assigned_to',
    'rule_id',
    'tactic',
    'technique',
    'timestamp',
    'due_at',
    'sla_breached',
    'occurrence_count',
    'related_alert_ids',
    'recommended_action',
    'asset',
    'user',
    'src_ip',
    'related_assets',
    'related_users',
    'related_src_ips',
)


def _text(value: object, maximum: int = 512) -> str:
    return str(value or '').replace('\r', ' ').replace('\n', ' ').strip()[:maximum]


def _sensitive_values(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ('asset', 'hostname', 'host', 'src_ip', 'dst_ip', 'user'):
        value = _text(record.get(key), 256)
        if value:
            values.append(value)
    for key in ('related_assets', 'related_users', 'related_src_ips'):
        raw = record.get(key) or []
        if isinstance(raw, list):
            values.extend(_text(item, 256) for item in raw if _text(item, 256))
    return sorted(set(values), key=len, reverse=True)


def _redact(value: object, sensitive: Iterable[str], maximum: int = 512) -> str:
    text = _text(value, maximum)
    for item in sensitive:
        text = re.sub(re.escape(item), '[redacted]', text, flags=re.IGNORECASE)
    return _IP_ADDRESS.sub('[redacted-ip]', text)


def _counts(records: Iterable[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(
        sorted(
            Counter(_text(record.get(field), 64) or 'unknown' for record in records).items()
        )
    )


def build_report_summary(
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    metrics: dict[str, Any],
    operations: dict[str, int],
) -> dict[str, Any]:
    """Build an aggregate report without raw entities or evidence."""
    return {
        'schema_version': '1.0',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'privacy': {'aggregate_only': True, 'raw_targets_included': False},
        'overview': {
            'total_events': int(metrics.get('total_events') or 0),
            'total_alerts': len(alerts),
            'total_incidents': len(incidents),
            'risk_score': int(metrics.get('risk_score') or 0),
            **{key: int(value) for key, value in operations.items()},
        },
        'alerts_by_severity': _counts(alerts, 'severity'),
        'alerts_by_status': _counts(alerts, 'status'),
        'incidents_by_priority': _counts(incidents, 'priority'),
        'incidents_by_status': _counts(incidents, 'status'),
        'top_tactics': {
            _text(key, 128): int(value)
            for key, value in dict(metrics.get('top_tactics') or {}).items()
        },
    }


def _alert_record(
    alert: dict[str, Any], include_raw_targets: bool
) -> dict[str, Any]:
    sensitive = _sensitive_values(alert)
    record = {
        'record_type': 'alert',
        'record_id': _text(alert.get('alert_id'), 128),
        'title': _redact(alert.get('title'), sensitive, 256),
        'severity_or_priority': _text(alert.get('severity'), 32),
        'status': _text(alert.get('status'), 32),
        'assigned_to': _redact(alert.get('assigned_to'), sensitive, 80),
        'rule_id': _text(alert.get('rule_id'), 128),
        'tactic': _text(alert.get('tactic'), 128),
        'technique': _text(alert.get('technique'), 64),
        'timestamp': _text(alert.get('timestamp'), 64),
        'due_at': _text(alert.get('due_at'), 64),
        'sla_breached': bool(alert.get('sla_breached')),
        'occurrence_count': max(1, int(alert.get('occurrence_count') or 1)),
        'related_alert_ids': [],
        'recommended_action': _redact(
            alert.get('recommended_action'), sensitive, 512
        ),
    }
    if include_raw_targets:
        record.update(
            {
                'asset': _text(alert.get('asset'), 256),
                'user': _text(alert.get('user'), 256),
                'src_ip': _text(alert.get('src_ip'), 256),
            }
        )
    return record


def _incident_record(
    incident: dict[str, Any], include_raw_targets: bool
) -> dict[str, Any]:
    sensitive = _sensitive_values(incident)
    actions = incident.get('recommended_actions') or []
    record = {
        'record_type': 'incident',
        'record_id': _text(incident.get('incident_id'), 128),
        'title': _redact(incident.get('title'), sensitive, 256),
        'severity_or_priority': _text(incident.get('priority'), 32),
        'status': _text(incident.get('status'), 32),
        'assigned_to': _redact(
            incident.get('assigned_to') or incident.get('owner'), sensitive, 80
        ),
        'rule_id': '',
        'tactic': '',
        'technique': '',
        'timestamp': _text(incident.get('first_seen_at'), 64),
        'due_at': _text(incident.get('due_at'), 64),
        'sla_breached': bool(incident.get('sla_breached')),
        'occurrence_count': 1,
        'related_alert_ids': [
            _text(alert_id, 128) for alert_id in incident.get('related_alert_ids') or []
        ][:100],
        'recommended_action': _redact(
            ' | '.join(_text(action, 256) for action in actions), sensitive, 512
        ),
        'evidence_summary': _redact(
            incident.get('evidence_summary'), sensitive, 1000
        ),
    }
    if include_raw_targets:
        record.update(
            {
                'related_assets': [
                    _text(value, 256)
                    for value in incident.get('related_assets') or []
                ][:100],
                'related_users': [
                    _text(value, 256)
                    for value in incident.get('related_users') or []
                ][:100],
                'related_src_ips': [
                    _text(value, 256)
                    for value in incident.get('related_src_ips') or []
                ][:100],
            }
        )
    return record


def build_evidence_export(
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    metrics: dict[str, Any],
    operations: dict[str, int],
    *,
    include_raw_targets: bool,
    limit: int,
) -> dict[str, Any]:
    """Create a deterministic, bounded JSON-ready report bundle."""
    if not 1 <= limit <= MAX_EXPORT_ROWS:
        raise ValueError(f'limit must be between 1 and {MAX_EXPORT_ROWS}')
    remaining = limit
    alert_records = [
        _alert_record(alert, include_raw_targets) for alert in alerts[:remaining]
    ]
    remaining -= len(alert_records)
    incident_records = [
        _incident_record(incident, include_raw_targets)
        for incident in incidents[:remaining]
    ]
    return {
        'schema_version': '1.0',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'privacy': {
            'raw_targets_included': include_raw_targets,
            'raw_events_included': False,
            'raw_evidence_included': False,
        },
        'summary': build_report_summary(alerts, incidents, metrics, operations),
        'alerts': alert_records,
        'incidents': incident_records,
        'truncated': len(alerts) + len(incidents) > limit,
        'record_count': len(alert_records) + len(incident_records),
    }


def _csv_value(value: Any) -> str:
    if isinstance(value, (list, dict)):
        text = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    elif isinstance(value, bool):
        text = 'true' if value else 'false'
    else:
        text = _text(value, 2000)
    if text.lstrip().startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


def render_evidence_csv(bundle: dict[str, Any]) -> str:
    """Render report records as spreadsheet-safe UTF-8 CSV."""
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction='ignore')
    writer.writeheader()
    for record in [*bundle.get('alerts', []), *bundle.get('incidents', [])]:
        writer.writerow({field: _csv_value(record.get(field, '')) for field in CSV_FIELDS})
    return output.getvalue()
