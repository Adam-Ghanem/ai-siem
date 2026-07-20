from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import Event

DEFAULT_DB_PATH = Path(os.getenv('AI_SIEM_DB_PATH', 'data/ai_siem.db'))

SCHEMA = '''
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    asset TEXT,
    user TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    raw_log TEXT,
    event_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source, event_type);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE TABLE IF NOT EXISTS triage_records (
    record_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    analyst TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_alert ON triage_records(alert_id);
CREATE INDEX IF NOT EXISTS idx_triage_created ON triage_records(created_at);
CREATE TABLE IF NOT EXISTS alert_operations (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_to TEXT NOT NULL,
    resolution_note TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    due_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_operations_status
ON alert_operations(status, severity);
CREATE INDEX IF NOT EXISTS idx_alert_operations_due
ON alert_operations(due_at);
CREATE TABLE IF NOT EXISTS incident_operations (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_to TEXT NOT NULL,
    resolution_note TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    due_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_operations_status
ON incident_operations(status, priority);
CREATE INDEX IF NOT EXISTS idx_incident_operations_due
ON incident_operations(due_at);
CREATE TABLE IF NOT EXISTS operation_history (
    history_id TEXT PRIMARY KEY,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_history_object
ON operation_history(object_type, object_id, created_at);
'''


def _db_path(path: str | Path | None = None) -> Path:
    value = Path(path) if path else DEFAULT_DB_PATH
    value.parent.mkdir(parents=True, exist_ok=True)
    return value


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str | Path | None = None) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def save_events(events: Iterable[Event], path: str | Path | None = None) -> int:
    init_db(path)
    rows = []
    for event in events:
        data = event.to_dict()
        rows.append(
            (
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
            )
        )
    if not rows:
        return 0
    with connect(path) as conn:
        conn.executemany(
            '''
            INSERT OR IGNORE INTO events
            (id, timestamp, source, event_type, asset, user, src_ip, dst_ip, raw_log, event_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            rows,
        )
        conn.commit()
        return conn.total_changes


def load_events(
    path: str | Path | None = None, limit: int | None = None
) -> list[Event]:
    init_db(path)
    query = 'SELECT event_json FROM events'
    params: tuple[int, ...] = ()
    if limit is not None:
        if limit < 1:
            raise ValueError('limit must be positive')
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params = (limit,)
    else:
        query += ' ORDER BY timestamp ASC'
    with connect(path) as conn:
        events = [
            Event.from_dict(json.loads(row['event_json']))
            for row in conn.execute(query, params)
        ]
    if limit is not None:
        events.reverse()
    return events


def existing_event_ids(
    event_ids: Iterable[str], path: str | Path | None = None
) -> set[str]:
    ids = list(dict.fromkeys(str(event_id) for event_id in event_ids))
    if not ids:
        return set()
    init_db(path)
    existing: set[str] = set()
    with connect(path) as conn:
        for start in range(0, len(ids), 500):
            chunk = ids[start : start + 500]
            placeholders = ','.join('?' for _ in chunk)
            rows = conn.execute(
                f'SELECT id FROM events WHERE id IN ({placeholders})',  # nosec B608
                chunk,
            )
            existing.update(row['id'] for row in rows)
    return existing


def save_triage_record(record: dict[str, Any], path: str | Path | None = None) -> None:
    init_db(path)
    with connect(path) as conn:
        conn.execute(
            '''
            INSERT INTO triage_records
            (record_id, alert_id, action, analyst, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (
                record['record_id'],
                record['alert_id'],
                record['action'],
                record['analyst'],
                record.get('note', ''),
                record['created_at'],
            ),
        )
        conn.commit()


def load_triage_records(
    path: str | Path | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise ValueError('limit must be between 1 and 1000')
    init_db(path)
    with connect(path) as conn:
        rows = conn.execute(
            '''
            SELECT record_id, alert_id, action, analyst, note, created_at
            FROM triage_records
            ORDER BY created_at DESC
            LIMIT ?
            ''',
            (limit,),
        ).fetchall()
    records = [dict(row) for row in rows]
    for record in records:
        record['status'] = 'recorded'
    return records


def stats(path: str | Path | None = None) -> dict:
    init_db(path)
    with connect(path) as conn:
        total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        triage_total = conn.execute('SELECT COUNT(*) FROM triage_records').fetchone()[0]
        alert_operations = conn.execute(
            'SELECT COUNT(*) FROM alert_operations'
        ).fetchone()[0]
        incident_operations = conn.execute(
            'SELECT COUNT(*) FROM incident_operations'
        ).fetchone()[0]
        sources = {
            row['source']: row['count']
            for row in conn.execute(
                'SELECT source, COUNT(*) count FROM events GROUP BY source'
            )
        }
        last = conn.execute(
            'SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1'
        ).fetchone()
    return {
        'backend': 'sqlite',
        'db_path': str(_db_path(path)),
        'stored_events': total,
        'triage_records': triage_total,
        'alert_operations': alert_operations,
        'incident_operations': incident_operations,
        'source_distribution': sources,
        'last_event_timestamp': last['timestamp'] if last else None,
    }
