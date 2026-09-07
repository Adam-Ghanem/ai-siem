from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def parse_time(value: Any | None) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None or value == '':
        return datetime.now(timezone.utc)
    text = str(value).strip()
    if not text:
        return datetime.now(timezone.utc)
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f'invalid event timestamp: {value!r}') from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _optional_text(data: dict[str, Any], field_name: str) -> str | None:
    value = data.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field_name} must be a string')
    return value


@dataclass
class Event:
    id: str
    timestamp: datetime
    source: str
    event_type: str
    asset: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    status: str | None = None
    message: str | None = None
    raw_log: str = ''

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Event':
        if not isinstance(data, dict):
            raise ValueError('event must be a JSON object')
        if not data.get('source') or not data.get('event_type'):
            raise ValueError('event requires source and event_type')
        return cls(
            id=str(data.get('id') or f'evt-{uuid4().hex[:12]}'),
            timestamp=parse_time(data.get('timestamp')),
            source=str(data['source']),
            event_type=str(data['event_type']),
            asset=_optional_text(data, 'asset'),
            user=_optional_text(data, 'user'),
            src_ip=_optional_text(data, 'src_ip'),
            dst_ip=_optional_text(data, 'dst_ip'),
            process_name=_optional_text(data, 'process_name'),
            command_line=_optional_text(data, 'command_line'),
            status=_optional_text(data, 'status'),
            message=_optional_text(data, 'message'),
            raw_log=str(data.get('raw_log') or data),
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self); d['timestamp'] = self.timestamp.isoformat(); return d


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str
    confidence: float
    tactic: str
    technique: str
    timestamp: datetime
    asset: str | None = None
    user: str | None = None
    src_ip: str | None = None
    event_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommended_action: str = ''
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self); d['timestamp'] = self.timestamp.isoformat(); return d


@dataclass
class Incident:
    incident_id: str
    title: str
    priority: str
    status: str
    owner: str
    related_alert_ids: list[str]
    related_assets: list[str]
    related_users: list[str]
    related_src_ips: list[str]
    evidence_summary: str
    timeline: list[dict[str, Any]]
    recommended_actions: list[str]
    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass
class Anomaly:
    anomaly_id: str
    entity: str
    anomaly_score: float
    reason: str
    contributing_features: dict[str, Any]
    related_event_ids: list[str]
    recommended_action: str
    def to_dict(self) -> dict[str, Any]: return asdict(self)
