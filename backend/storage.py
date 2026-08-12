import json
import os
import sqlite3
from datetime import datetime, timezone
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
    event_json TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source, event_type);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);

CREATE TABLE IF NOT EXISTS ingest_batches (
    batch_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    received_at TEXT NOT NULL,
    item_count INTEGER NOT NULL,
    accepted_count INTEGER NOT NULL,
    rejected_count INTEGER NOT NULL,
    unknown_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_ingest_batches_tenant_received ON ingest_batches(tenant_id, received_at);

CREATE TABLE IF NOT EXISTS triage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    analyst TEXT NOT NULL,
    status TEXT NOT NULL,
    request_id TEXT,
    created_at TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    principal_id TEXT NOT NULL DEFAULT 'legacy-admin'
);
CREATE INDEX IF NOT EXISTS idx_triage_alert_id ON triage(alert_id);
'''


def _db_path(path: str | Path | None = None) -> Path:
    value = Path(path) if path else DEFAULT_DB_PATH
    value.parent.mkdir(parents=True, exist_ok=True)
    return value


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(path), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=10000')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row['name'] for row in conn.execute(f'PRAGMA table_info({table})')}
    if column not in columns:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')


def init_db(path: str | Path | None = None) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        _ensure_column(conn, 'events', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
        _ensure_column(conn, 'triage', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
        _ensure_column(conn, 'triage', 'principal_id', "TEXT NOT NULL DEFAULT 'legacy-admin'")
        conn.execute('CREATE INDEX IF NOT EXISTS idx_events_tenant_timestamp ON events(tenant_id, timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_triage_tenant_created_at ON triage(tenant_id, created_at)')
        conn.commit()


def save_events(events: Iterable[Event], path: str | Path | None = None) -> int:
    init_db(path)
    rows = []
    for event in events:
        event_id = event.id
        if event.tenant_id != 'default' and not event_id.startswith(f'{event.tenant_id}:'):
            event_id = f'{event.tenant_id}:{event_id}'
        data = event.to_dict()
        data['id'] = event_id
        rows.append((
            event_id,
            event.timestamp.isoformat(),
            event.source,
            event.event_type,
            event.asset,
            event.user,
            event.src_ip,
            event.dst_ip,
            event.raw_log,
            json.dumps(data, ensure_ascii=False),
            event.tenant_id,
        ))
    if not rows:
        return 0
    with connect(path) as conn:
        conn.executemany(
            '''
            INSERT OR IGNORE INTO events
            (id, timestamp, source, event_type, asset, user, src_ip, dst_ip, raw_log, event_json, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            rows,
        )
        conn.commit()
        return conn.total_changes


def load_events(
    path: str | Path | None = None,
    limit: int | None = None,
    tenant_id: str | None = None,
) -> list[Event]:
    init_db(path)
    query = 'SELECT event_json FROM events'
    params: list[object] = []
    if tenant_id:
        query += ' WHERE tenant_id = ?'
        params.append(tenant_id)
    query += ' ORDER BY timestamp ASC'
    if limit:
        query += ' LIMIT ?'
        params.append(limit)
    with connect(path) as conn:
        return [
            Event.from_dict(json.loads(row['event_json']))
            for row in conn.execute(query, tuple(params))
        ]


def save_ingest_batch(record: dict, path: str | Path | None = None) -> dict:
    init_db(path)
    values = (
        str(record['batch_id']),
        str(record.get('tenant_id') or 'default'),
        str(record.get('principal_id') or 'legacy-admin'),
        str(record.get('received_at') or datetime.now(timezone.utc).isoformat()),
        int(record.get('item_count') or 0),
        int(record.get('accepted_count') or 0),
        int(record.get('rejected_count') or 0),
        int(record.get('unknown_count') or 0),
        str(record.get('status') or 'accepted'),
        str(record.get('error') or '') or None,
    )
    with connect(path) as conn:
        conn.execute(
            '''
            INSERT OR REPLACE INTO ingest_batches
            (batch_id, tenant_id, principal_id, received_at, item_count, accepted_count,
             rejected_count, unknown_count, status, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            values,
        )
        conn.commit()
    return {
        'batch_id': values[0],
        'tenant_id': values[1],
        'principal_id': values[2],
        'received_at': values[3],
        'item_count': values[4],
        'accepted_count': values[5],
        'rejected_count': values[6],
        'unknown_count': values[7],
        'status': values[8],
        'error': values[9],
    }


def load_ingest_batches(
    path: str | Path | None = None,
    tenant_id: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict]:
    init_db(path)
    query = '''
        SELECT batch_id, tenant_id, principal_id, received_at, item_count, accepted_count,
               rejected_count, unknown_count, status, error
        FROM ingest_batches
    '''
    params: list[object] = []
    if tenant_id:
        query += ' WHERE tenant_id = ?'
        params.append(tenant_id)
    query += ' ORDER BY received_at DESC'
    if limit is not None:
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, max(offset, 0)])
    with connect(path) as conn:
        return [dict(row) for row in conn.execute(query, tuple(params))]


def save_triage(record: dict, path: str | Path | None = None) -> dict:
    init_db(path)
    created_at = record.get('created_at') or datetime.now(timezone.utc).isoformat()
    values = (
        str(record['alert_id']),
        str(record['action']),
        str(record.get('analyst') or 'unknown'),
        str(record.get('status') or 'recorded'),
        str(record.get('request_id') or ''),
        created_at,
        str(record.get('tenant_id') or 'default'),
        str(record.get('principal_id') or 'legacy-admin'),
    )
    with connect(path) as conn:
        cursor = conn.execute(
            '''
            INSERT INTO triage
            (alert_id, action, analyst, status, request_id, created_at, tenant_id, principal_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            values,
        )
        conn.commit()
        return {
            'triage_id': cursor.lastrowid,
            'alert_id': values[0],
            'action': values[1],
            'analyst': values[2],
            'status': values[3],
            'request_id': values[4] or None,
            'created_at': values[5],
            'tenant_id': values[6],
            'principal_id': values[7],
        }


def load_triage(
    path: str | Path | None = None,
    limit: int | None = None,
    offset: int = 0,
    tenant_id: str | None = None,
) -> list[dict]:
    init_db(path)
    query = '''
        SELECT id, alert_id, action, analyst, status, request_id, created_at, tenant_id, principal_id
        FROM triage
    '''
    params: list[object] = []
    if tenant_id:
        query += ' WHERE tenant_id = ?'
        params.append(tenant_id)
    query += ' ORDER BY id DESC'
    if limit is not None:
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, max(offset, 0)])
    with connect(path) as conn:
        return [
            {
                'triage_id': row['id'],
                'alert_id': row['alert_id'],
                'action': row['action'],
                'analyst': row['analyst'],
                'status': row['status'],
                'request_id': row['request_id'] or None,
                'created_at': row['created_at'],
                'tenant_id': row['tenant_id'],
                'principal_id': row['principal_id'],
            }
            for row in conn.execute(query, tuple(params))
        ]


def stats(path: str | Path | None = None, tenant_id: str | None = None) -> dict:
    init_db(path)
    with connect(path) as conn:
        if tenant_id:
            total = conn.execute('SELECT COUNT(*) FROM events WHERE tenant_id = ?', (tenant_id,)).fetchone()[0]
            triage_total = conn.execute('SELECT COUNT(*) FROM triage WHERE tenant_id = ?', (tenant_id,)).fetchone()[0]
            batch_total = conn.execute('SELECT COUNT(*) FROM ingest_batches WHERE tenant_id = ?', (tenant_id,)).fetchone()[0]
            sources = {
                row['source']: row['count']
                for row in conn.execute(
                    'SELECT source, COUNT(*) count FROM events WHERE tenant_id = ? GROUP BY source',
                    (tenant_id,),
                )
            }
            last = conn.execute(
                'SELECT timestamp FROM events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 1',
                (tenant_id,),
            ).fetchone()
        else:
            total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            triage_total = conn.execute('SELECT COUNT(*) FROM triage').fetchone()[0]
            batch_total = conn.execute('SELECT COUNT(*) FROM ingest_batches').fetchone()[0]
            sources = {
                row['source']: row['count']
                for row in conn.execute('SELECT source, COUNT(*) count FROM events GROUP BY source')
            }
            last = conn.execute('SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1').fetchone()
    return {
        'backend': 'sqlite',
        'db_path': str(_db_path(path)),
        'tenant_id': tenant_id,
        'stored_events': total,
        'stored_triage_records': triage_total,
        'stored_ingest_batches': batch_total,
        'source_distribution': sources,
        'last_event_timestamp': last['timestamp'] if last else None,
    }
