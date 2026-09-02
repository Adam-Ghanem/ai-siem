from __future__ import annotations

import json
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
    dirty INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO incident_snapshot_state (id, dirty) VALUES (1, 1);
'''

SNAPSHOT_FRESH = 0
SNAPSHOT_DIRTY = 1
SNAPSHOT_REFRESHING = 2


def _ensure_schema(path: str | Path | None = None) -> None:
    init_db(path)
    with connect(path) as conn:
        conn.executescript(INCIDENT_SCHEMA)
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
            'UPDATE incident_snapshot_state SET dirty = ? WHERE id = 1',
            (SNAPSHOT_DIRTY,),
        )
        conn.commit()


def incident_snapshots_dirty(path: str | Path | None = None) -> bool:
    """Return freshness and atomically claim a pending refresh when needed.

    The state machine is fresh -> dirty -> refreshing. A concurrent invalidation
    can move refreshing back to dirty; replace_incidents then preserves that
    newer dirty signal instead of accidentally marking stale materialized data
    fresh.
    """
    _ensure_schema(path)
    with connect(path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT dirty FROM incident_snapshot_state WHERE id = 1'
        ).fetchone()
        state = SNAPSHOT_DIRTY if row is None else int(row['dirty'])
        if state == SNAPSHOT_DIRTY:
            conn.execute(
                'UPDATE incident_snapshot_state SET dirty = ? WHERE id = 1',
                (SNAPSHOT_REFRESHING,),
            )
        conn.commit()
    return state != SNAPSHOT_FRESH


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
    """Atomically replace snapshots and clear only the refresh that produced them."""
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
            'UPDATE incident_snapshot_state SET dirty = ? '
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
