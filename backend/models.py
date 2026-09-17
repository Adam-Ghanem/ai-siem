from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


MAX_EVENT_ID_LENGTH = 256
MAX_EVENT_SOURCE_LENGTH = 128
MAX_EVENT_TYPE_LENGTH = 128
MAX_EVENT_ENTITY_LENGTH = 256
MAX_EVENT_PROCESS_LENGTH = 512
MAX_EVENT_TEXT_LENGTH = 4096
MAX_EVENT_RAW_LOG_BYTES = 10 * 1024


def parse_time(value: Any | None) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
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
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _optional_text(
    data: dict[str, Any], field_name: str, max_length: int = MAX_EVENT_ENTITY_LENGTH
) -> str | None:
    value = data.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field_name} must be a string')
    normalized = value.strip()
    if not normalized:
        return None
    _require_max_length(field_name, normalized, max_length)
    return normalized


def _provided_text(data: dict[str, Any], field_name: str) -> str | None:
    value = data.get(field_name)
    if value is None or value == '':
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field_name} must be a string')
    return value


def _require_max_length(field_name: str, value: str, max_length: int) -> None:
    if len(value) > max_length:
        raise ValueError(f'{field_name} exceeds {max_length} characters')


def _require_max_bytes(field_name: str, value: str, max_bytes: int) -> None:
    if len(value.encode('utf-8')) > max_bytes:
        raise ValueError(f'{field_name} exceeds {max_bytes} bytes')


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
        if not isinstance(data['source'], str):
            raise ValueError('source must be a string')
        if not isinstance(data['event_type'], str):
            raise ValueError('event_type must be a string')
        source = data['source'].strip()
        event_type = data['event_type'].strip()
        if not source:
            raise ValueError('source must not be blank')
        if not event_type:
            raise ValueError('event_type must not be blank')
        _require_max_length('source', source, MAX_EVENT_SOURCE_LENGTH)
        _require_max_length('event_type', event_type, MAX_EVENT_TYPE_LENGTH)

        provided_event_id = _provided_text(data, 'id')
        if provided_event_id is not None:
            provided_event_id = provided_event_id.strip()
            if not provided_event_id:
                raise ValueError('id must not be blank')
            _require_max_length('id', provided_event_id, MAX_EVENT_ID_LENGTH)
        event_id = provided_event_id or f'evt-{uuid4().hex[:12]}'
        explicit_timestamp = data.get('timestamp')
        if (
            'timestamp' in data
            and isinstance(explicit_timestamp, str)
            and not explicit_timestamp.strip()
        ):
            raise ValueError('timestamp must not be blank')
        raw_log = _provided_text(data, 'raw_log')
        if raw_log is not None:
            _require_max_bytes('raw_log', raw_log, MAX_EVENT_RAW_LOG_BYTES)
        return cls(
            id=event_id,
            timestamp=parse_time(explicit_timestamp),
            source=source,
            event_type=event_type,
            asset=_optional_text(data, 'asset'),
            user=_optional_text(data, 'user'),
            src_ip=_optional_text(data, 'src_ip'),
            dst_ip=_optional_text(data, 'dst_ip'),
            process_name=_optional_text(data, 'process_name', MAX_EVENT_PROCESS_LENGTH),
            command_line=_optional_text(data, 'command_line', MAX_EVENT_TEXT_LENGTH),
            status=_optional_text(data, 'status'),
            message=_optional_text(data, 'message', MAX_EVENT_TEXT_LENGTH),
            raw_log=raw_log or str(data),
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
