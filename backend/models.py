from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def parse_time(value: Any | None) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


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
            asset=data.get('asset'), user=data.get('user'), src_ip=data.get('src_ip'), dst_ip=data.get('dst_ip'),
            process_name=data.get('process_name'), command_line=data.get('command_line'), status=data.get('status'),
            message=data.get('message'), raw_log=str(data.get('raw_log') or data),
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
