from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: Any | None) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return utc_now()
    text = str(value).strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return utc_now()


@dataclass
class NormalizedEvent:
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
    def from_dict(cls, data: dict[str, Any]) -> 'NormalizedEvent':
        if not isinstance(data, dict):
            raise ValueError('Normalized event must be an object')
        required = ['source', 'event_type']
        missing = [field for field in required if not data.get(field)]
        if missing:
            raise ValueError(f'Missing required event fields: {missing}')
        return cls(
            id=str(data.get('id') or f"evt-{uuid4().hex[:12]}"),
            timestamp=parse_ts(data.get('timestamp')),
            source=str(data.get('source')),
            event_type=str(data.get('event_type')),
            asset=data.get('asset'),
            user=data.get('user'),
            src_ip=data.get('src_ip'),
            dst_ip=data.get('dst_ip'),
            process_name=data.get('process_name'),
            command_line=data.get('command_line'),
            status=data.get('status'),
            message=data.get('message'),
            raw_log=str(data.get('raw_log') or data),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


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
    recommended_action: str = 'Review alert evidence and escalate if suspicious.'

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Anomaly:
    anomaly_id: str
    entity: str
    anomaly_score: float
    reason: str
    contributing_features: dict[str, Any]
    related_event_ids: list[str]
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
