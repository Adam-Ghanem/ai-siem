from __future__ import annotations
import json
import os
import sqlite3
from pathlib import Path
from typing import Iterable
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


def load_events(path: str | Path | None = None, limit: int | None = None) -> list[Event]:
    init_db(path)
    query = 'SELECT event_json FROM events ORDER BY timestamp ASC'
    params: tuple[int, ...] = ()
    if limit:
        query += ' LIMIT ?'
        params = (limit,)
    with connect(path) as conn:
        return [Event.from_dict(json.loads(row['event_json'])) for row in conn.execute(query, params)]


def stats(path: str | Path | None = None) -> dict:
    init_db(path)
    with connect(path) as conn:
        total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        sources = {row['source']: row['count'] for row in conn.execute('SELECT source, COUNT(*) count FROM events GROUP BY source')}
        last = conn.execute('SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1').fetchone()
    return {
        'backend': 'sqlite',
        'db_path': str(_db_path(path)),
        'stored_events': total,
        'source_distribution': sources,
        'last_event_timestamp': last['timestamp'] if last else None,
    }
