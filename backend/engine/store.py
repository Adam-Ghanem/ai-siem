from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .anomaly import detect_anomalies
from .correlation import correlate_alerts
from .coverage import mitre_coverage
from .detection import run_detections
from .event_model import NormalizedEvent
from .export import soc_snapshot
from .metrics import calculate_metrics
from .parser_v2 import parse_events

ROOT = Path(__file__).resolve().parents[2]
DATA_FILE = ROOT / 'data' / 'sample_logs.json'

class SIEMStore:
    def __init__(self) -> None:
        self.events: list[NormalizedEvent] = []
        self.triage_records: list[dict[str, Any]] = []
        self.load_sample_data()

    def load_sample_data(self) -> None:
        if DATA_FILE.exists():
            payload = json.loads(DATA_FILE.read_text(encoding='utf-8'))
            self.events = parse_events(payload)

    def ingest(self, payload: Any) -> int:
        if isinstance(payload, dict) and 'events' in payload:
            items = payload['events']
        elif isinstance(payload, dict) and 'logs' in payload:
            items = payload['logs']
        elif isinstance(payload, list):
            items = payload
        elif isinstance(payload, (str, dict)):
            items = [payload]
        else:
            raise ValueError('POST /api/ingest expects one event, one log line, or a list of events/logs')
        parsed = parse_events(items)
        self.events.extend(parsed)
        return len(parsed)

    def alerts(self):
        return run_detections(self.events)

    def incidents(self):
        return correlate_alerts(self.alerts())

    def anomalies(self):
        return detect_anomalies(self.events)

    def metrics(self):
        alerts = self.alerts()
        incidents = self.incidents()
        return calculate_metrics(self.events, alerts, incidents)

    def coverage(self):
        return mitre_coverage(self.alerts())

    def snapshot(self):
        alerts = self.alerts()
        incidents = correlate_alerts(alerts)
        anomalies = detect_anomalies(self.events)
        metrics = calculate_metrics(self.events, alerts, incidents)
        return soc_snapshot(self.events, alerts, incidents, anomalies, metrics)

    def triage(self, record: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ValueError('triage body must be a JSON object')
        if not record.get('incident_id') and not record.get('alert_id'):
            raise ValueError('triage requires incident_id or alert_id')
        if not record.get('action'):
            raise ValueError('triage requires action')
        record['status'] = 'recorded'
        self.triage_records.append(record)
        return record
