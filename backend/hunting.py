"""Bounded, literal threat hunting over the active telemetry working set."""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Sequence, cast

from .models import Event


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f'{name} must be an integer') from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f'{name} must be between {minimum} and {maximum}')
    return value


MAX_HUNT_SCAN_EVENTS = _bounded_int(
    'AI_SIEM_MAX_HUNT_SCAN_EVENTS', 25_000, 100, 100_000
)
MAX_CONCURRENT_HUNTS = _bounded_int(
    'AI_SIEM_MAX_CONCURRENT_HUNTS', 2, 1, 16
)
MAX_HUNT_RESULTS = 500
MAX_RAW_PREVIEW_CHARS = 4096
_CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f]')
_FILTER_FIELDS = (
    'source',
    'event_type',
    'asset',
    'user',
    'src_ip',
    'dst_ip',
    'status',
    'process_name',
)
_SAFE_SEARCH_FIELDS = (
    'id',
    *_FILTER_FIELDS,
    'command_line',
    'message',
)
_ALLOWED_PAYLOAD_FIELDS = {
    'q',
    *_FILTER_FIELDS,
    'start_time',
    'end_time',
    'sort',
    'offset',
    'limit',
    'include_raw',
}
HuntSort = Literal['newest', 'oldest']


def _clean_text(value: Any, name: str, maximum: int) -> str | None:
    if value is None or value == '':
        return None
    if not isinstance(value, str):
        raise ValueError(f'{name} must be a string')
    if _CONTROL_CHARACTERS.search(value):
        raise ValueError(f'{name} contains control characters')
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > maximum:
        raise ValueError(f'{name} is too long')
    return cleaned


def _parse_time(value: Any, name: str) -> datetime | None:
    text = _clean_text(value, name, 64)
    if text is None:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f'{name} must be an ISO 8601 timestamp') from exc
    if parsed.tzinfo is None:
        raise ValueError(f'{name} must include a timezone')
    return parsed.astimezone(timezone.utc)


def _bounded_payload_int(
    value: Any,
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f'{name} must be an integer')
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return value


@dataclass(frozen=True)
class HuntQuery:
    """Validated structured hunt query with no executable expression syntax."""

    q: str | None = None
    source: str | None = None
    event_type: str | None = None
    asset: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    status: str | None = None
    process_name: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    sort: HuntSort = 'newest'
    offset: int = 0
    limit: int = 100
    include_raw: bool = False

    @classmethod
    def from_payload(cls, payload: Any) -> 'HuntQuery':
        if not isinstance(payload, dict):
            raise ValueError('Hunt request body must be a JSON object')
        unknown = set(payload) - _ALLOWED_PAYLOAD_FIELDS
        if unknown:
            raise ValueError(
                f'Unsupported hunt fields: {", ".join(sorted(unknown))}'
            )
        include_raw = payload.get('include_raw', False)
        if not isinstance(include_raw, bool):
            raise ValueError('include_raw must be a boolean')
        sort_value = payload.get('sort', 'newest')
        if (
            not isinstance(sort_value, str)
            or sort_value not in {'newest', 'oldest'}
        ):
            raise ValueError('sort must be newest or oldest')
        sort = cast(HuntSort, sort_value)
        start_time = _parse_time(payload.get('start_time'), 'start_time')
        end_time = _parse_time(payload.get('end_time'), 'end_time')
        if start_time and end_time and start_time > end_time:
            raise ValueError('start_time must not be after end_time')
        filters = {
            field: _clean_text(payload.get(field), field, 128)
            for field in _FILTER_FIELDS
        }
        return cls(
            q=_clean_text(payload.get('q'), 'q', 256),
            **filters,
            start_time=start_time,
            end_time=end_time,
            sort=sort,
            offset=_bounded_payload_int(
                payload.get('offset'), 'offset', 0, 0, 1_000_000
            ),
            limit=_bounded_payload_int(
                payload.get('limit'), 'limit', 100, 1, MAX_HUNT_RESULTS
            ),
            include_raw=include_raw,
        )

    def public_filters(self) -> dict[str, Any]:
        """Return normalized query state for the requesting analyst."""
        values: dict[str, Any] = {
            'q': self.q,
            **{field: getattr(self, field) for field in _FILTER_FIELDS},
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'sort': self.sort,
            'include_raw': self.include_raw,
        }
        return {key: value for key, value in values.items() if value is not None}

    def filter_count(self) -> int:
        return sum(
            value is not None
            for value in (
                self.q,
                *(getattr(self, field) for field in _FILTER_FIELDS),
                self.start_time,
                self.end_time,
            )
        )


def _matches(event: Event, query: HuntQuery) -> bool:
    if query.start_time and event.timestamp < query.start_time:
        return False
    if query.end_time and event.timestamp > query.end_time:
        return False
    for field in _FILTER_FIELDS:
        expected = getattr(query, field)
        if expected is None:
            continue
        actual = getattr(event, field)
        if actual is None or str(actual).casefold() != expected.casefold():
            return False
    if query.q:
        needle = query.q.casefold()
        search_fields = (
            (*_SAFE_SEARCH_FIELDS, 'raw_log')
            if query.include_raw
            else _SAFE_SEARCH_FIELDS
        )
        if not any(
            needle in str(getattr(event, field) or '').casefold()
            for field in search_fields
        ):
            return False
    return True


def _facet(events: Sequence[Event], field: str) -> list[dict[str, Any]]:
    counts = Counter(
        str(value)
        for event in events
        if (value := getattr(event, field)) is not None and str(value).strip()
    )
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0].casefold()))
    return [
        {'value': value[:128], 'count': count}
        for value, count in ranked[:12]
    ]


def event_payload(event: Event, include_raw: bool = False) -> dict[str, Any]:
    """Return the shared bounded safe or explicitly raw event representation."""
    payload = event.to_dict()
    raw_log = str(payload.pop('raw_log', '') or '')
    for field in ('message', 'command_line'):
        value = payload.get(field)
        if isinstance(value, str) and len(value) > MAX_RAW_PREVIEW_CHARS:
            payload[field] = value[:MAX_RAW_PREVIEW_CHARS]
            payload[f'{field}_truncated'] = True
    if include_raw:
        payload['raw_log'] = raw_log[:MAX_RAW_PREVIEW_CHARS]
        payload['raw_log_truncated'] = len(raw_log) > MAX_RAW_PREVIEW_CHARS
    return payload


def run_hunt(
    events: Sequence[Event],
    query: HuntQuery,
    *,
    available_events: int | None = None,
) -> dict[str, Any]:
    """Run a deterministic hunt over a bounded recent-event scope."""
    available = len(events) if available_events is None else available_events
    scoped = list(events[-MAX_HUNT_SCAN_EVENTS:])
    matched = [event for event in scoped if _matches(event, query)]
    matched.sort(
        key=lambda event: (event.timestamp, event.id),
        reverse=query.sort == 'newest',
    )
    page = matched[query.offset : query.offset + query.limit]
    return {
        'schema_version': '1.0',
        'query': query.public_filters(),
        'total_matches': len(matched),
        'offset': query.offset,
        'limit': query.limit,
        'has_more': query.offset + len(page) < len(matched),
        'scope': {
            'available_events': available,
            'scanned_events': len(scoped),
            'scan_limit': MAX_HUNT_SCAN_EVENTS,
            'scan_truncated': available > len(scoped),
            'selection': 'most_recent',
        },
        'time_bounds': {
            'oldest_match': (
                min(event.timestamp for event in matched).isoformat()
                if matched
                else None
            ),
            'newest_match': (
                max(event.timestamp for event in matched).isoformat()
                if matched
                else None
            ),
        },
        'facets': {
            field: _facet(matched, field)
            for field in ('source', 'event_type', 'status', 'asset', 'user', 'src_ip')
        },
        'events': [event_payload(event, query.include_raw) for event in page],
    }
