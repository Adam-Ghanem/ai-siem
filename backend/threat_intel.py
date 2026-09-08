from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import Event

_SEVERITY_ORDER = {'unknown': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _normalize_indicator(value: Any) -> str:
    text = str(value or '').strip().lower()
    if not text:
        return ''
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.rstrip('.')


def _is_container_value(value: Any) -> bool:
    return isinstance(value, (dict, list, tuple, set))


def _bounded_confidence(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _parse_optional_time(value: Any, field_name: str) -> datetime | None:
    if value is None or value == '':
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field_name} must be an ISO-8601 string')
    text = value.strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f'{field_name} must be a valid ISO-8601 timestamp') from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


def _parse_expiry(value: Any) -> datetime | None:
    return _parse_optional_time(value, 'expires_at')


def _entry_is_active(entry: dict[str, Any], now: datetime | None = None) -> bool:
    expires_at = entry.get('expires_at')
    if not expires_at:
        return True
    expiry = _parse_expiry(expires_at)
    current = now or datetime.now(timezone.utc)
    return expiry is None or expiry > current


def _entry_fingerprint(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (
        entry['indicator'],
        entry['type'],
        entry['source'],
        entry['confidence'],
        entry['severity'],
        tuple(entry['tags']),
        entry['description'],
        entry['first_seen'],
        entry['last_seen'],
        entry['expires_at'],
    )


class ThreatIntelIndex:
    def __init__(self, entries: Iterable[dict[str, Any]] | None = None):
        self._entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._networks: dict[int, list[tuple[ipaddress._BaseNetwork, dict[str, Any]]]] = {
            4: [],
            6: [],
        }
        self._fingerprints: set[tuple[Any, ...]] = set()
        for entry in entries or []:
            self.add(entry)

    @classmethod
    def from_json_file(cls, path: str | Path) -> 'ThreatIntelIndex':
        file_path = Path(path)
        if not file_path.exists():
            return cls()
        try:
            data = json.loads(file_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return cls()
        if isinstance(data, dict):
            data = data.get('indicators', [])
        return cls(data if isinstance(data, list) else [])

    def add(self, entry: dict[str, Any]) -> bool:
        if not isinstance(entry, dict):
            return False
        raw_indicator = entry.get('indicator')
        raw_source = entry.get('source')
        if not isinstance(raw_indicator, str) or not isinstance(raw_source, str):
            return False
        indicator = _normalize_indicator(raw_indicator)
        source = raw_source.strip()
        if not indicator or not source:
            return False

        try:
            expiry = _parse_expiry(entry.get('expires_at'))
            first_seen = _parse_optional_time(entry.get('first_seen'), 'first_seen')
            last_seen = _parse_optional_time(entry.get('last_seen'), 'last_seen')
        except ValueError:
            return False
        if expiry is not None and expiry <= datetime.now(timezone.utc):
            return False
        if first_seen is not None and last_seen is not None and last_seen < first_seen:
            return False

        network = None
        if '/' in indicator:
            try:
                network = ipaddress.ip_network(indicator, strict=False)
            except ValueError:
                return False
            indicator = str(network)

        severity = str(entry.get('severity') or 'unknown').strip().lower()
        if severity not in _SEVERITY_ORDER:
            severity = 'unknown'
        tags = entry.get('tags') or []
        if not isinstance(tags, list):
            tags = [tags]
        normalized = {
            'indicator': indicator,
            'type': str(entry.get('type') or ('cidr' if network else 'unknown')).strip().lower(),
            'source': source,
            'confidence': _bounded_confidence(entry.get('confidence')),
            'severity': severity,
            'tags': sorted({str(tag).strip().lower() for tag in tags if str(tag).strip()}),
            'description': str(entry.get('description') or '').strip(),
            'first_seen': first_seen.isoformat() if first_seen is not None else '',
            'last_seen': last_seen.isoformat() if last_seen is not None else '',
            'expires_at': expiry.isoformat() if expiry is not None else '',
        }
        fingerprint = _entry_fingerprint(normalized)
        if fingerprint in self._fingerprints:
            return False
        self._fingerprints.add(fingerprint)
        self._entries[indicator].append(normalized)
        if network is not None:
            self._networks[network.version].append((network, normalized))
        return True

    def lookup(self, indicator: Any) -> dict[str, Any]:
        normalized = _normalize_indicator(indicator)
        now = datetime.now(timezone.utc)
        matches = [
            entry for entry in self._entries.get(normalized, [])
            if _entry_is_active(entry, now)
        ]

        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            address = None
        if address is not None:
            matches.extend(
                entry
                for network, entry in self._networks[address.version]
                if address in network and _entry_is_active(entry, now)
            )

        severities = [item['severity'] for item in matches]
        max_severity = max(
            severities,
            key=lambda value: _SEVERITY_ORDER.get(value, 0),
            default='unknown',
        )
        return {
            'indicator': normalized,
            'matched': bool(matches),
            'match_count': len(matches),
            'max_confidence': max((item['confidence'] for item in matches), default=0),
            'max_severity': max_severity,
            'sources': sorted({item['source'] for item in matches}),
            'tags': sorted({tag for item in matches for tag in item['tags']}),
            'matched_indicators': sorted({item['indicator'] for item in matches}),
            'matches': sorted(matches, key=lambda item: item['confidence'], reverse=True),
        }

    def enrich_events(self, events: Iterable[Event]) -> list[dict[str, Any]]:
        enriched: dict[str, dict[str, Any]] = {}
        for event in events:
            for observable in (event.src_ip, event.dst_ip):
                if not observable:
                    continue
                result = self.lookup(observable)
                if not result['matched']:
                    continue
                indicator = result['indicator']
                current = enriched.setdefault(indicator, {**result, 'event_ids': []})
                if event.id not in current['event_ids']:
                    current['event_ids'].append(event.id)
        return sorted(
            enriched.values(),
            key=lambda item: (item['max_confidence'], item['indicator']),
            reverse=True,
        )

    def stats(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        active_entries_by_indicator = {
            indicator: [entry for entry in values if _entry_is_active(entry, now)]
            for indicator, values in self._entries.items()
        }
        active_entries_by_indicator = {
            indicator: values
            for indicator, values in active_entries_by_indicator.items()
            if values
        }
        entries = [
            item
            for values in active_entries_by_indicator.values()
            for item in values
        ]
        return {
            'unique_indicators': len(active_entries_by_indicator),
            'entries': len(entries),
            'network_indicators': sum(
                1
                for values in self._networks.values()
                for _, entry in values
                if _entry_is_active(entry, now)
            ),
            'sources': sorted({item['source'] for item in entries}),
        }
