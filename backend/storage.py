import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import Alert, Event, parse_time

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
CREATE INDEX IF NOT EXISTS idx_events_timestamp_id ON events(timestamp, id);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source, event_type);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    tactic TEXT NOT NULL,
    asset TEXT,
    user TEXT,
    src_ip TEXT,
    alert_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_tactic ON alerts(tactic);
CREATE INDEX IF NOT EXISTS idx_alerts_asset ON alerts(asset);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);

CREATE TABLE IF NOT EXISTS triage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    analyst TEXT NOT NULL,
    status TEXT NOT NULL,
    request_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_alert_id ON triage(alert_id);
CREATE INDEX IF NOT EXISTS idx_triage_created_at ON triage(created_at);

CREATE TABLE IF NOT EXISTS incident_cases (
    incident_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    disposition TEXT NOT NULL,
    note TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    request_id TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_cases_status ON incident_cases(status);
CREATE INDEX IF NOT EXISTS idx_incident_cases_owner ON incident_cases(owner);
CREATE INDEX IF NOT EXISTS idx_incident_cases_updated_at ON incident_cases(updated_at);
'''


def _db_path(path: str | Path | None = None) -> Path:
    value = Path(path) if path else DEFAULT_DB_PATH
    value.parent.mkdir(parents=True, exist_ok=True)
    return value


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(
        _db_path(path),
        timeout=10,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=10000')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA foreign_keys=ON')
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


def existing_event_ids(
    event_ids: Iterable[str],
    path: str | Path | None = None,
) -> set[str]:
    ids = list(dict.fromkeys(str(event_id) for event_id in event_ids if event_id))
    if not ids:
        return set()

    init_db(path)
    existing: set[str] = set()
    batch_size = 500
    with connect(path) as conn:
        for start in range(0, len(ids), batch_size):
            batch = ids[start:start + batch_size]
            placeholders = ','.join('?' for _ in batch)
            query = f'SELECT id FROM events WHERE id IN ({placeholders})'
            existing.update(row['id'] for row in conn.execute(query, tuple(batch)))
    return existing


def load_events(path: str | Path | None = None, limit: int | None = None) -> list[Event]:
    init_db(path)
    params: tuple[int, ...] = ()
    if limit:
        query = '''
            SELECT event_json FROM (
                SELECT event_json, timestamp, id
                FROM events
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
            )
            ORDER BY timestamp ASC, id ASC
        '''
        params = (limit,)
    else:
        query = 'SELECT event_json FROM events ORDER BY timestamp ASC, id ASC'
    with connect(path) as conn:
        return [
            Event.from_dict(json.loads(row['event_json']))
            for row in conn.execute(query, params)
        ]


def _alert_from_dict(data: dict) -> Alert:
    return Alert(
        alert_id=str(data['alert_id']),
        rule_id=str(data['rule_id']),
        title=str(data['title']),
        severity=str(data['severity']),
        confidence=float(data['confidence']),
        tactic=str(data['tactic']),
        technique=str(data['technique']),
        timestamp=parse_time(data.get('timestamp')),
        asset=data.get('asset'),
        user=data.get('user'),
        src_ip=data.get('src_ip'),
        event_ids=list(data.get('event_ids') or []),
        evidence=list(data.get('evidence') or []),
        recommended_action=str(data.get('recommended_action') or ''),
    )


def save_alerts(alerts: Iterable[Alert], path: str | Path | None = None) -> int:
    init_db(path)
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
    if not rows:
        return 0
    with connect(path) as conn:
        conn.executemany(
            '''
            INSERT OR IGNORE INTO alerts
            (alert_id, timestamp, rule_id, severity, tactic, asset, user, src_ip, alert_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            rows,
        )
        conn.commit()
        return conn.total_changes


def load_alerts(
    path: str | Path | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[Alert]:
    init_db(path)
    query = 'SELECT alert_json FROM alerts ORDER BY timestamp DESC, alert_id DESC'
    params: list[int] = []
    if limit is not None:
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, max(offset, 0)])
    with connect(path) as conn:
        return [
            _alert_from_dict(json.loads(row['alert_json']))
            for row in conn.execute(query, tuple(params))
        ]


def search_alerts(
    path: str | Path | None = None,
    *,
    severity: str | None = None,
    tactic: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    rule_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Alert], int]:
    init_db(path)
    clauses: list[str] = []
    params: list[object] = []

    for column, value in (
        ('severity', severity),
        ('tactic', tactic),
        ('asset', asset),
        ('user', user),
        ('src_ip', src_ip),
        ('rule_id', rule_id),
    ):
        if value:
            clauses.append(f'{column} = ?')
            params.append(value)
    if start:
        clauses.append('timestamp >= ?')
        params.append(start.isoformat())
    if end:
        clauses.append('timestamp <= ?')
        params.append(end.isoformat())

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ''
    count_sql = f'SELECT COUNT(*) FROM alerts{where}'
    data_sql = (
        f'SELECT alert_json FROM alerts{where} '
        'ORDER BY timestamp DESC, alert_id DESC LIMIT ? OFFSET ?'
    )

    with connect(path) as conn:
        total = int(conn.execute(count_sql, tuple(params)).fetchone()[0])
        rows = conn.execute(
            data_sql,
            tuple(params + [limit, max(offset, 0)]),
        )
        results = [
            _alert_from_dict(json.loads(row['alert_json']))
            for row in rows
        ]
    return results, total


def _escape_like(value: str) -> str:
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def search_events(
    path: str | Path | None = None,
    *,
    source: str | None = None,
    event_type: str | None = None,
    asset: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    query: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Event], int]:
    init_db(path)
    clauses: list[str] = []
    params: list[object] = []

    for column, value in (
        ('source', source),
        ('event_type', event_type),
        ('asset', asset),
        ('user', user),
        ('src_ip', src_ip),
        ('dst_ip', dst_ip),
    ):
        if value:
            clauses.append(f'{column} = ?')
            params.append(value)
    if query:
        clauses.append("raw_log LIKE ? ESCAPE '\\'")
        params.append(f'%{_escape_like(query)}%')
    if start:
        clauses.append('timestamp >= ?')
        params.append(start.isoformat())
    if end:
        clauses.append('timestamp <= ?')
        params.append(end.isoformat())

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ''
    count_sql = f'SELECT COUNT(*) FROM events{where}'
    data_sql = (
        f'SELECT event_json FROM events{where} '
        'ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?'
    )

    with connect(path) as conn:
        total = int(conn.execute(count_sql, tuple(params)).fetchone()[0])
        rows = conn.execute(
            data_sql,
            tuple(params + [limit, max(offset, 0)]),
        )
        events = [
            Event.from_dict(json.loads(row['event_json']))
            for row in rows
        ]
    return events, total


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
    )
    with connect(path) as conn:
        cursor = conn.execute(
            '''
            INSERT INTO triage (alert_id, action, analyst, status, request_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
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
        }


def _triage_row(row: sqlite3.Row) -> dict:
    return {
        'triage_id': row['id'],
        'alert_id': row['alert_id'],
        'action': row['action'],
        'analyst': row['analyst'],
        'status': row['status'],
        'request_id': row['request_id'] or None,
        'created_at': row['created_at'],
    }


def load_triage(
    path: str | Path | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict]:
    init_db(path)
    query = '''
        SELECT id, alert_id, action, analyst, status, request_id, created_at
        FROM triage
        ORDER BY id DESC
    '''
    params: list[int] = []
    if limit is not None:
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, max(offset, 0)])
    with connect(path) as conn:
        return [_triage_row(row) for row in conn.execute(query, tuple(params))]


def search_triage(
    path: str | Path | None = None,
    *,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    init_db(path)
    with connect(path) as conn:
        total = int(conn.execute('SELECT COUNT(*) FROM triage').fetchone()[0])
        rows = conn.execute(
            '''
            SELECT id, alert_id, action, analyst, status, request_id, created_at
            FROM triage
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            ''',
            (limit, max(offset, 0)),
        )
        return [_triage_row(row) for row in rows], total


def save_incident_case(record: dict, path: str | Path | None = None) -> dict:
    init_db(path)
    updated_at = record.get('updated_at') or datetime.now(timezone.utc).isoformat()
    values = (
        str(record['incident_id']),
        str(record.get('status') or 'open'),
        str(record.get('owner') or 'unassigned'),
        str(record.get('disposition') or 'undetermined'),
        str(record.get('note') or ''),
        str(record.get('updated_by') or 'unknown'),
        str(record.get('request_id') or ''),
        updated_at,
    )
    with connect(path) as conn:
        conn.execute(
            '''
            INSERT INTO incident_cases
            (incident_id, status, owner, disposition, note, updated_by, request_id, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                status=excluded.status,
                owner=excluded.owner,
                disposition=excluded.disposition,
                note=excluded.note,
                updated_by=excluded.updated_by,
                request_id=excluded.request_id,
                updated_at=excluded.updated_at
            ''',
            values,
        )
        conn.commit()
    return {
        'incident_id': values[0],
        'status': values[1],
        'owner': values[2],
        'disposition': values[3],
        'note': values[4],
        'updated_by': values[5],
        'request_id': values[6] or None,
        'updated_at': values[7],
    }


def load_incident_case(
    incident_id: str,
    path: str | Path | None = None,
) -> dict | None:
    init_db(path)
    with connect(path) as conn:
        row = conn.execute(
            '''
            SELECT incident_id, status, owner, disposition, note,
                   updated_by, request_id, updated_at
            FROM incident_cases
            WHERE incident_id = ?
            ''',
            (incident_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        'incident_id': row['incident_id'],
        'status': row['status'],
        'owner': row['owner'],
        'disposition': row['disposition'],
        'note': row['note'],
        'updated_by': row['updated_by'],
        'request_id': row['request_id'] or None,
        'updated_at': row['updated_at'],
    }


def stats(path: str | Path | None = None) -> dict:
    init_db(path)
    with connect(path) as conn:
        total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        alert_total = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        triage_total = conn.execute('SELECT COUNT(*) FROM triage').fetchone()[0]
        incident_case_total = conn.execute('SELECT COUNT(*) FROM incident_cases').fetchone()[0]
        source_rows = conn.execute(
            'SELECT source, COUNT(*) AS count FROM events GROUP BY source ORDER BY count DESC'
        ).fetchall()
        event_type_rows = conn.execute(
            'SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type ORDER BY count DESC'
        ).fetchall()
    return {
        'backend': 'sqlite',
        'stored_events': total,
        'stored_alerts': alert_total,
        'stored_triage_records': triage_total,
        'stored_incident_cases': incident_case_total,
        'source_distribution': {row['source']: row['count'] for row in source_rows},
        'event_type_distribution': {row['event_type']: row['count'] for row in event_type_rows},
    }
