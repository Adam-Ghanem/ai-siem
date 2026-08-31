from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
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


def _bounded_confidence(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


class ThreatIntelIndex:
    def __init__(self, entries: Iterable[dict[str, Any]] | None = None):
        self._entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
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
        indicator = _normalize_indicator(entry.get('indicator'))
        source = str(entry.get('source') or '').strip()
        if not indicator or not source:
            return False
        severity = str(entry.get('severity') or 'unknown').strip().lower()
        if severity not in _SEVERITY_ORDER:
            severity = 'unknown'
        tags = entry.get('tags') or []
        if not isinstance(tags, list):
            tags = [tags]
        normalized = {
            'indicator': indicator,
            'type': str(entry.get('type') or 'unknown').strip().lower(),
            'source': source,
            'confidence': _bounded_confidence(entry.get('confidence')),
            'severity': severity,
            'tags': sorted({str(tag).strip().lower() for tag in tags if str(tag).strip()}),
            'description': str(entry.get('description') or '').strip(),
            'first_seen': str(entry.get('first_seen') or '').strip(),
            'last_seen': str(entry.get('last_seen') or '').strip(),
        }
        self._entries[indicator].append(normalized)
        return True

    def lookup(self, indicator: Any) -> dict[str, Any]:
        normalized = _normalize_indicator(indicator)
        matches = list(self._entries.get(normalized, []))
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
        entries = [item for values in self._entries.values() for item in values]
        return {
            'unique_indicators': len(self._entries),
            'entries': len(entries),
            'sources': sorted({item['source'] for item in entries}),
        }
