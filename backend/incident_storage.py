from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from .models import Incident
from .storage import connect, init_db

INCIDENT_SCHEMA = '''
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    incident_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_owner ON incidents(owner);
CREATE TABLE IF NOT EXISTS incident_snapshot_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    dirty INTEGER NOT NULL DEFAULT 1,
    refresh_claimed_at REAL
);
INSERT OR IGNORE INTO incident_snapshot_state (id, dirty) VALUES (1, 1);
'''

SNAPSHOT_FRESH = 0
SNAPSHOT_DIRTY = 1
SNAPSHOT_REFRESHING = 2
SNAPSHOT_REFRESH_LEASE_SECONDS = 60.0


def _ensure_schema(path: str | Path | None = None) -> None:
    init_db(path)
    with connect(path) as conn:
        conn.executescript(INCIDENT_SCHEMA)
        columns = {
            str(row['name'])
            for row in conn.execute('PRAGMA table_info(incident_snapshot_state)')
        }
        if 'refresh_claimed_at' not in columns:
            conn.execute(
                'ALTER TABLE incident_snapshot_state ADD COLUMN refresh_claimed_at REAL'
            )
        conn.commit()


def _incident_from_dict(data: dict) -> Incident:
    return Incident(
        incident_id=str(data['incident_id']),
        title=str(data['title']),
        priority=str(data['priority']),
        status=str(data.get('status') or 'open'),
        owner=str(data.get('owner') or 'unassigned'),
        related_alert_ids=list(data.get('related_alert_ids') or []),
        related_assets=list(data.get('related_assets') or []),
        related_users=list(data.get('related_users') or []),
        related_src_ips=list(data.get('related_src_ips') or []),
        evidence_summary=str(data.get('evidence_summary') or ''),
        timeline=list(data.get('timeline') or []),
        recommended_actions=list(data.get('recommended_actions') or []),
    )


def _incident_rows(incidents: Iterable[Incident]) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for incident in incidents:
        data = incident.to_dict()
        rows.append((
            incident.incident_id,
            incident.priority,
            incident.status,
            incident.owner,
            json.dumps(data, ensure_ascii=False),
        ))
    return rows


def mark_incident_snapshots_dirty(path: str | Path | None = None) -> None:
    _ensure_schema(path)
    with connect(path) as conn:
        conn.execute(
            'UPDATE incident_snapshot_state '
            'SET dirty = ?, refresh_claimed_at = NULL WHERE id = 1',
            (SNAPSHOT_DIRTY,),
        )
        conn.commit()


def incident_snapshots_dirty(path: str | Path | None = None) -> bool:
    """Atomically claim a pending snapshot refresh.

    Only the caller that moves the state from dirty to refreshing receives
    ``True``. Other readers can continue using the last materialized snapshot
    while that refresh is in flight instead of repeating the same expensive
    correlation work. A concurrent invalidation can still move refreshing back
    to dirty; ``replace_incidents`` preserves that newer dirty signal.

    Refresh claims are leased so an exception or worker termination cannot
    strand the snapshot state in ``refreshing`` forever. Once the lease expires,
    the next reader may reclaim the refresh and rebuild the materialized view.
    """
    _ensure_schema(path)
    now = time.time()
    with connect(path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT dirty, refresh_claimed_at '
            'FROM incident_snapshot_state WHERE id = 1'
        ).fetchone()
        state = SNAPSHOT_DIRTY if row is None else int(row['dirty'])
        claimed_at = None if row is None else row['refresh_claimed_at']
        lease_expired = (
            state == SNAPSHOT_REFRESHING
            and (
                claimed_at is None
                or now - float(claimed_at) >= SNAPSHOT_REFRESH_LEASE_SECONDS
            )
        )
        claimed = state == SNAPSHOT_DIRTY or lease_expired
        if claimed:
            conn.execute(
                'UPDATE incident_snapshot_state '
                'SET dirty = ?, refresh_claimed_at = ? WHERE id = 1',
                (SNAPSHOT_REFRESHING, now),
            )
        conn.commit()
    return claimed


def save_incidents(
    incidents: Iterable[Incident],
    path: str | Path | None = None,
) -> int:
    _ensure_schema(path)
    rows = _incident_rows(incidents)
    if not rows:
        return 0

    with connect(path) as conn:
        before = conn.total_changes
        conn.executemany(
            '''
            INSERT INTO incidents
            (incident_id, priority, status, owner, incident_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                priority=excluded.priority,
                status=excluded.status,
                owner=excluded.owner,
                incident_json=excluded.incident_json
            ''',
            rows,
        )
        conn.commit()
        return conn.total_changes - before


def replace_incidents(
    incidents: Iterable[Incident],
    path: str | Path | None = None,
) -> int:
    """Atomically replace snapshots and clear only a claimed refresh state."""
    _ensure_schema(path)
    rows = _incident_rows(incidents)
    with connect(path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('DELETE FROM incidents')
        if rows:
            conn.executemany(
                '''
                INSERT INTO incidents
                (incident_id, priority, status, owner, incident_json)
                VALUES (?, ?, ?, ?, ?)
                ''',
                rows,
            )
        conn.execute(
            'UPDATE incident_snapshot_state '
            'SET dirty = ?, refresh_claimed_at = NULL '
            'WHERE id = 1 AND dirty = ?',
            (SNAPSHOT_FRESH, SNAPSHOT_REFRESHING),
        )
        conn.commit()
    return len(rows)


def load_incident(
    incident_id: str,
    path: str | Path | None = None,
) -> Incident | None:
    _ensure_schema(path)
    with connect(path) as conn:
        row = conn.execute(
            'SELECT incident_json FROM incidents WHERE incident_id = ?',
            (incident_id,),
        ).fetchone()
    if row is None:
        return None
    return _incident_from_dict(json.loads(row['incident_json']))


def search_incidents(
    path: str | Path | None = None,
    *,
    status: str | None = None,
    priority: str | None = None,
    owner: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Incident], int]:
    _ensure_schema(path)
    clauses: list[str] = []
    params: list[object] = []

    for column, value in (
        ('status', status),
        ('priority', priority),
        ('owner', owner),
    ):
        if value:
            clauses.append(f'{column} = ?')
            params.append(value)

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ''
    count_sql = f'SELECT COUNT(*) FROM incidents{where}'
    data_sql = (
        f'SELECT incident_json FROM incidents{where} '
        'ORDER BY incident_id DESC LIMIT ? OFFSET ?'
    )

    with connect(path) as conn:
        total = int(conn.execute(count_sql, tuple(params)).fetchone()[0])
        rows = conn.execute(
            data_sql,
            tuple(params + [limit, max(offset, 0)]),
        )
        results = [
            _incident_from_dict(json.loads(row['incident_json']))
            for row in rows
        ]
    return results, total
