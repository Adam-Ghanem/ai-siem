from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import Alert, Event
from .storage import connect, init_db


class IngestCommitRace(ValueError):
    """An accepted event ID became occupied before the SQLite commit."""


def _event_rows(events: Iterable[Event]) -> list[tuple]:
    rows = []
    for event in events:
        data = event.to_dict()
        rows.append((
            event.id,
            event.timestamp.isoformat(),
            event.source,
            event.event_type,
            event.asset,
            event.user,
            event.src_ip,
            event.dst_ip,
            event.raw_log,
            json.dumps(data, ensure_ascii=False),
        ))
    return rows


def _alert_rows(alerts: Iterable[Alert]) -> list[tuple]:
    rows = []
    for alert in alerts:
        data = alert.to_dict()
        rows.append((
            alert.alert_id,
            alert.timestamp.isoformat(),
            alert.rule_id,
            alert.severity,
            alert.tactic,
            alert.asset,
            alert.user,
            alert.src_ip,
            json.dumps(data, ensure_ascii=False),
        ))
    return rows


def save_ingest_batch(
    events: Iterable[Event],
    alerts: Iterable[Alert],
    path: str | Path | None = None,
) -> tuple[int, int]:
    """Persist accepted events and their derived alerts in one SQLite transaction."""
    event_rows = _event_rows(events)
    alert_rows = _alert_rows(alerts)
    if not event_rows and not alert_rows:
        return 0, 0

    init_db(path)
    with connect(path) as conn:
        before_events = conn.total_changes
        if event_rows:
            conn.executemany(
                '''
                INSERT OR IGNORE INTO events
                (id, timestamp, source, event_type, asset, user, src_ip, dst_ip, raw_log, event_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                event_rows,
            )
        saved_events = conn.total_changes - before_events
        if saved_events != len(event_rows):
            conn.rollback()
            raise IngestCommitRace(
                'Event ID became occupied before ingest commit'
            )

        before_alerts = conn.total_changes
        if alert_rows:
            conn.executemany(
                '''
                INSERT OR IGNORE INTO alerts
                (alert_id, timestamp, rule_id, severity, tactic, asset, user, src_ip, alert_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                alert_rows,
            )
        saved_alerts = conn.total_changes - before_alerts
        conn.commit()
        return saved_events, saved_alerts
