from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable, Protocol
from uuid import uuid4

from .models import Event
from .storage import (
    init_db,
    load_events as sqlite_load_events,
    load_ingest_batches as sqlite_load_ingest_batches,
    load_triage as sqlite_load_triage,
    save_events as sqlite_save_events,
    save_ingest_batch as sqlite_save_ingest_batch,
    save_triage as sqlite_save_triage,
    stats as sqlite_stats,
    load_alert_acknowledgements as sqlite_load_alert_acknowledgements,
    save_alert_acknowledgement as sqlite_save_alert_acknowledgement,
    load_analyst_notes as sqlite_load_analyst_notes,
    save_analyst_note as sqlite_save_analyst_note,
)


class StorageBackend(Protocol):
    name: str

    def load_events(self, limit: int | None = None, tenant_id: str | None = None) -> list[Event]: ...
    def save_events(self, events: Iterable[Event]) -> int: ...
    def load_ingest_batches(self, tenant_id: str | None = None, limit: int | None = None, offset: int = 0) -> list[dict]: ...
    def save_ingest_batch(self, record: dict) -> dict: ...
    def load_triage(self, limit: int | None = None, offset: int = 0, tenant_id: str | None = None) -> list[dict]: ...
    def save_triage(self, record: dict) -> dict: ...
    def stats(self, tenant_id: str | None = None) -> dict: ...
    def load_alert_acknowledgements(self, tenant_id: str | None = None, limit: int | None = None, offset: int = 0) -> list[dict]: ...
    def save_alert_acknowledgement(self, record: dict) -> dict: ...
    def load_analyst_notes(self, alert_id: str, tenant_id: str | None = None, limit: int | None = None, offset: int = 0) -> list[dict]: ...
    def save_analyst_note(self, record: dict) -> dict: ...


class MemoryBackend:
    name = 'memory'

    def __init__(self) -> None:
        self.events: list[Event] = []
        self.batches: list[dict] = []
        self.triage: list[dict] = []
        self.acknowledgements: dict[tuple[str, str], dict] = {}
        self.notes: list[dict] = []

    def load_events(self, limit: int | None = None, tenant_id: str | None = None) -> list[Event]:
        values = [event for event in self.events if not tenant_id or event.tenant_id == tenant_id]
        return values[:limit] if limit else values

    def save_events(self, events: Iterable[Event]) -> int:
        values = list(events)
        self.events.extend(values)
        return len(values)

    def load_ingest_batches(self, tenant_id: str | None = None, limit: int | None = None, offset: int = 0) -> list[dict]:
        values = [record for record in reversed(self.batches) if not tenant_id or record.get('tenant_id') == tenant_id]
        return values[offset:offset + limit] if limit is not None else values[offset:]

    def save_ingest_batch(self, record: dict) -> dict:
        self.batches.append(dict(record))
        return dict(record)

    def load_triage(self, limit: int | None = None, offset: int = 0, tenant_id: str | None = None) -> list[dict]:
        values = [record for record in reversed(self.triage) if not tenant_id or record.get('tenant_id') == tenant_id]
        return values[offset:offset + limit] if limit is not None else values[offset:]

    def save_triage(self, record: dict) -> dict:
        value = dict(record)
        value.setdefault('triage_id', len(self.triage) + 1)
        self.triage.append(value)
        return value

    def load_alert_acknowledgements(self, tenant_id=None, limit=None, offset=0):
        values = [record for (tenant, _), record in self.acknowledgements.items() if not tenant_id or tenant == tenant_id]
        values = list(reversed(values))
        return values[offset:offset + limit] if limit is not None else values[offset:]

    def save_alert_acknowledgement(self, record):
        value = dict(record)
        self.acknowledgements[(value['tenant_id'], value['alert_id'])] = value
        return value

    def load_analyst_notes(self, alert_id, tenant_id=None, limit=None, offset=0):
        values = [record for record in reversed(self.notes) if record.get('alert_id') == alert_id and (not tenant_id or record.get('tenant_id') == tenant_id)]
        return values[offset:offset + limit] if limit is not None else values[offset:]

    def save_analyst_note(self, record):
        value = {**record, 'note_id': len(self.notes) + 1}
        self.notes.append(value)
        return value

    def stats(self, tenant_id: str | None = None) -> dict:
        events = [event for event in self.events if not tenant_id or event.tenant_id == tenant_id]
        return {
            'backend': self.name,
            'tenant_id': tenant_id,
            'stored_events': len(events),
            'stored_triage_records': len([r for r in self.triage if not tenant_id or r.get('tenant_id') == tenant_id]),
            'stored_ingest_batches': len([r for r in self.batches if not tenant_id or r.get('tenant_id') == tenant_id]),
        }


class SQLiteBackend:
    name = 'sqlite'

    def __init__(self) -> None:
        init_db()

    def load_events(self, limit=None, tenant_id=None):
        return sqlite_load_events(limit=limit, tenant_id=tenant_id)

    def save_events(self, events):
        return sqlite_save_events(events)

    def load_ingest_batches(self, tenant_id=None, limit=None, offset=0):
        return sqlite_load_ingest_batches(tenant_id=tenant_id, limit=limit, offset=offset)

    def save_ingest_batch(self, record):
        return sqlite_save_ingest_batch(record)

    def load_triage(self, limit=None, offset=0, tenant_id=None):
        return sqlite_load_triage(limit=limit, offset=offset, tenant_id=tenant_id)

    def save_triage(self, record):
        return sqlite_save_triage(record)

    def stats(self, tenant_id=None):
        return sqlite_stats(tenant_id=tenant_id)

    def load_alert_acknowledgements(self, tenant_id=None, limit=None, offset=0):
        return sqlite_load_alert_acknowledgements(tenant_id=tenant_id, limit=limit, offset=offset)

    def save_alert_acknowledgement(self, record):
        return sqlite_save_alert_acknowledgement(record)

    def load_analyst_notes(self, alert_id, tenant_id=None, limit=None, offset=0):
        return sqlite_load_analyst_notes(alert_id, tenant_id=tenant_id, limit=limit, offset=offset)

    def save_analyst_note(self, record):
        return sqlite_save_analyst_note(record)


class PostgreSQLBackend:
    name = 'postgres'

    def __init__(self, dsn: str | None = None) -> None:
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError('PostgreSQL backend requires the optional psycopg package') from exc
        self.psycopg = psycopg
        self.dsn = dsn or os.getenv('AI_SIEM_POSTGRES_DSN', '').strip()
        if not self.dsn:
            raise RuntimeError('AI_SIEM_POSTGRES_DSN is required for PostgreSQL backend')
        self._init_schema()

    def _connect(self):
        return self.psycopg.connect(self.dsn)

    def _init_schema(self):
        with self._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ai_siem_events (
                    id TEXT PRIMARY KEY, timestamp TIMESTAMPTZ NOT NULL, tenant_id TEXT NOT NULL,
                    event_json JSONB NOT NULL
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_siem_events_tenant_ts ON ai_siem_events(tenant_id, timestamp)')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ai_siem_ingest_batches (
                    batch_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL,
                    received_at TIMESTAMPTZ NOT NULL, item_count INTEGER NOT NULL,
                    accepted_count INTEGER NOT NULL, rejected_count INTEGER NOT NULL,
                    unknown_count INTEGER NOT NULL, status TEXT NOT NULL, error TEXT
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_siem_batches_tenant_ts ON ai_siem_ingest_batches(tenant_id, received_at)')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ai_siem_triage (
                    id BIGSERIAL PRIMARY KEY, alert_id TEXT NOT NULL, action TEXT NOT NULL,
                    analyst TEXT NOT NULL, status TEXT NOT NULL, request_id TEXT,
                    created_at TIMESTAMPTZ NOT NULL, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_siem_triage_tenant_id ON ai_siem_triage(tenant_id, id DESC)')
            conn.execute('''CREATE TABLE IF NOT EXISTS ai_siem_alert_acknowledgements (
                alert_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL,
                acknowledged BOOLEAN NOT NULL, comment TEXT, request_id TEXT, updated_at TIMESTAMPTZ NOT NULL
            )''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_siem_ack_tenant_updated ON ai_siem_alert_acknowledgements(tenant_id, updated_at DESC)')
            conn.execute('''CREATE TABLE IF NOT EXISTS ai_siem_analyst_notes (
                id BIGSERIAL PRIMARY KEY, alert_id TEXT NOT NULL, note TEXT NOT NULL, analyst TEXT NOT NULL,
                tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, request_id TEXT, created_at TIMESTAMPTZ NOT NULL
            )''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_siem_notes_tenant_alert ON ai_siem_analyst_notes(tenant_id, alert_id, id DESC)')

    def load_events(self, limit=None, tenant_id=None):
        query = 'SELECT event_json FROM ai_siem_events'
        params = []
        if tenant_id:
            query += ' WHERE tenant_id = %s'
            params.append(tenant_id)
        query += ' ORDER BY timestamp ASC'
        if limit:
            query += ' LIMIT %s'
            params.append(limit)
        with self._connect() as conn:
            return [Event.from_dict(row[0] if isinstance(row[0], dict) else json.loads(row[0])) for row in conn.execute(query, params)]

    def save_events(self, events):
        values = []
        for event in events:
            event_id = event.id if event.tenant_id == 'default' else f'{event.tenant_id}:{event.id}'
            data = event.to_dict()
            data['id'] = event_id
            values.append((event_id, event.timestamp, event.tenant_id, json.dumps(data, ensure_ascii=False)))
        with self._connect() as conn:
            conn.executemany(
                'INSERT INTO ai_siem_events(id, timestamp, tenant_id, event_json) VALUES (%s, %s, %s, %s::jsonb) ON CONFLICT (id) DO NOTHING',
                values,
            )
        return len(values)

    def save_ingest_batch(self, record):
        value = {
            'batch_id': str(record['batch_id']), 'tenant_id': str(record.get('tenant_id') or 'default'),
            'principal_id': str(record.get('principal_id') or 'legacy-admin'),
            'received_at': record.get('received_at') or datetime.now(timezone.utc).isoformat(),
            'item_count': int(record.get('item_count') or 0), 'accepted_count': int(record.get('accepted_count') or 0),
            'rejected_count': int(record.get('rejected_count') or 0), 'unknown_count': int(record.get('unknown_count') or 0),
            'status': str(record.get('status') or 'accepted'), 'error': str(record.get('error') or '') or None,
        }
        with self._connect() as conn:
            conn.execute('''INSERT INTO ai_siem_ingest_batches
                (batch_id, tenant_id, principal_id, received_at, item_count, accepted_count, rejected_count, unknown_count, status, error)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (batch_id) DO UPDATE SET status=EXCLUDED.status, error=EXCLUDED.error''', tuple(value.values()))
        return value

    def load_ingest_batches(self, tenant_id=None, limit=None, offset=0):
        query = 'SELECT batch_id, tenant_id, principal_id, received_at, item_count, accepted_count, rejected_count, unknown_count, status, error FROM ai_siem_ingest_batches'
        params = []
        if tenant_id:
            query += ' WHERE tenant_id = %s'
            params.append(tenant_id)
        query += ' ORDER BY received_at DESC LIMIT %s OFFSET %s'
        params.extend([limit or 1000, max(offset, 0)])
        with self._connect() as conn:
            return [dict(zip(('batch_id', 'tenant_id', 'principal_id', 'received_at', 'item_count', 'accepted_count', 'rejected_count', 'unknown_count', 'status', 'error'), row)) for row in conn.execute(query, params)]

    def save_triage(self, record):
        with self._connect() as conn:
            row = conn.execute('''INSERT INTO ai_siem_triage(alert_id, action, analyst, status, request_id, created_at, tenant_id, principal_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id''',
                (str(record['alert_id']), str(record['action']), str(record.get('analyst') or 'unknown'), str(record.get('status') or 'recorded'), str(record.get('request_id') or '') or None, record.get('created_at') or datetime.now(timezone.utc), str(record.get('tenant_id') or 'default'), str(record.get('principal_id') or 'legacy-admin'))).fetchone()
        return {**record, 'triage_id': row[0]}

    def load_triage(self, limit=None, offset=0, tenant_id=None):
        query = 'SELECT id, alert_id, action, analyst, status, request_id, created_at, tenant_id, principal_id FROM ai_siem_triage'
        params = []
        if tenant_id:
            query += ' WHERE tenant_id = %s'
            params.append(tenant_id)
        query += ' ORDER BY id DESC LIMIT %s OFFSET %s'
        params.extend([limit or 1000, max(offset, 0)])
        with self._connect() as conn:
            return [dict(zip(('triage_id', 'alert_id', 'action', 'analyst', 'status', 'request_id', 'created_at', 'tenant_id', 'principal_id'), row)) for row in conn.execute(query, params)]

    def stats(self, tenant_id=None):
        with self._connect() as conn:
            clause = ' WHERE tenant_id = %s' if tenant_id else ''
            params = [tenant_id] if tenant_id else []
            return {
                'backend': self.name, 'tenant_id': tenant_id,
                'stored_events': conn.execute(f'SELECT COUNT(*) FROM ai_siem_events{clause}', params).fetchone()[0],
                'stored_triage_records': conn.execute(f'SELECT COUNT(*) FROM ai_siem_triage{clause}', params).fetchone()[0],
                'stored_ingest_batches': conn.execute(f'SELECT COUNT(*) FROM ai_siem_ingest_batches{clause}', params).fetchone()[0],
            }


    def load_alert_acknowledgements(self, tenant_id=None, limit=None, offset=0):
        query = 'SELECT alert_id, tenant_id, principal_id, acknowledged, comment, request_id, updated_at FROM ai_siem_alert_acknowledgements'
        params = []
        if tenant_id:
            query += ' WHERE tenant_id = %s'
            params.append(tenant_id)
        query += ' ORDER BY updated_at DESC LIMIT %s OFFSET %s'
        params.extend([limit or 1000, max(offset, 0)])
        with self._connect() as conn:
            return [dict(zip(('alert_id', 'tenant_id', 'principal_id', 'acknowledged', 'comment', 'request_id', 'updated_at'), row)) for row in conn.execute(query, params)]

    def save_alert_acknowledgement(self, record):
        value = {**record, 'acknowledged': bool(record.get('acknowledged'))}
        with self._connect() as conn:
            conn.execute('''INSERT INTO ai_siem_alert_acknowledgements(alert_id, tenant_id, principal_id, acknowledged, comment, request_id, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(alert_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, principal_id=EXCLUDED.principal_id,
                acknowledged=EXCLUDED.acknowledged, comment=EXCLUDED.comment, request_id=EXCLUDED.request_id, updated_at=EXCLUDED.updated_at''',
                (value['alert_id'], value['tenant_id'], value['principal_id'], value['acknowledged'], value.get('comment'), value.get('request_id'), value['updated_at']))
        return value

    def load_analyst_notes(self, alert_id, tenant_id=None, limit=None, offset=0):
        query = 'SELECT id, alert_id, note, analyst, tenant_id, principal_id, request_id, created_at FROM ai_siem_analyst_notes WHERE alert_id = %s'
        params = [alert_id]
        if tenant_id:
            query += ' AND tenant_id = %s'
            params.append(tenant_id)
        query += ' ORDER BY id DESC LIMIT %s OFFSET %s'
        params.extend([limit or 1000, max(offset, 0)])
        with self._connect() as conn:
            return [dict(zip(('note_id', 'alert_id', 'note', 'analyst', 'tenant_id', 'principal_id', 'request_id', 'created_at'), row)) for row in conn.execute(query, params)]

    def save_analyst_note(self, record):
        value = dict(record)
        with self._connect() as conn:
            row = conn.execute('''INSERT INTO ai_siem_analyst_notes(alert_id, note, analyst, tenant_id, principal_id, request_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id''',
                (value['alert_id'], value['note'], value['analyst'], value['tenant_id'], value['principal_id'], value.get('request_id'), value['created_at'])).fetchone()
        value['note_id'] = row[0]
        return value


class OpenSearchBackend:
    name = 'opensearch'
    EVENTS_INDEX = 'ai-siem-events'
    TRIAGE_INDEX = 'ai-siem-triage'
    BATCHES_INDEX = 'ai-siem-batches'
    ACK_INDEX = 'ai-siem-alert-acknowledgements'
    NOTES_INDEX = 'ai-siem-analyst-notes'

    def __init__(self, url: str | None = None) -> None:
        try:
            from opensearchpy import OpenSearch
        except ImportError as exc:
            raise RuntimeError('OpenSearch backend requires the optional opensearch-py package') from exc
        endpoint = url or os.getenv('AI_SIEM_OPENSEARCH_URL', '').strip()
        if not endpoint or not endpoint.startswith(('http://', 'https://')):
            raise RuntimeError('AI_SIEM_OPENSEARCH_URL must be an http(s) URL')
        self.client = OpenSearch(endpoint, verify_certs=os.getenv('AI_SIEM_OPENSEARCH_VERIFY_CERTS', 'true').lower() == 'true')

    def _search(self, index, tenant_id, limit, offset, sort):
        filters = [{'term': {'tenant_id.keyword': tenant_id}}] if tenant_id else []
        body = {'from': max(offset, 0), 'size': min(limit or 1000, 1000), 'sort': [{sort: 'asc'}], 'query': {'bool': {'filter': filters}} if filters else {'match_all': {}}}
        return self.client.search(index=index, body=body).get('hits', {}).get('hits', [])

    def load_events(self, limit=None, tenant_id=None):
        return [Event.from_dict(hit['_source']['event']) for hit in self._search(self.EVENTS_INDEX, tenant_id, limit, 0, 'timestamp')]

    def save_events(self, events):
        values = list(events)
        for event in values:
            event_id = event.id if event.tenant_id == 'default' else f'{event.tenant_id}:{event.id}'
            self.client.index(index=self.EVENTS_INDEX, id=event_id, body={'tenant_id': event.tenant_id, 'timestamp': event.timestamp.isoformat(), 'event': {**event.to_dict(), 'id': event_id}}, refresh=False)
        return len(values)

    def save_ingest_batch(self, record):
        value = dict(record)
        self.client.index(index=self.BATCHES_INDEX, id=str(value['batch_id']), body=value, refresh=False)
        return value

    def load_ingest_batches(self, tenant_id=None, limit=None, offset=0):
        return [hit['_source'] for hit in self._search(self.BATCHES_INDEX, tenant_id, limit, offset, 'received_at')]

    def save_triage(self, record):
        value = {**record, 'triage_id': record.get('triage_id') or uuid4().hex}
        self.client.index(index=self.TRIAGE_INDEX, id=str(value['triage_id']), body=value, refresh=False)
        return value

    def load_triage(self, limit=None, offset=0, tenant_id=None):
        return [hit['_source'] for hit in self._search(self.TRIAGE_INDEX, tenant_id, limit, offset, 'created_at')]

    def stats(self, tenant_id=None):
        def count(index):
            body = {'query': {'term': {'tenant_id.keyword': tenant_id}}} if tenant_id else {'query': {'match_all': {}}}
            return int(self.client.count(index=index, body=body).get('count', 0))
        return {'backend': self.name, 'tenant_id': tenant_id, 'stored_events': count(self.EVENTS_INDEX), 'stored_triage_records': count(self.TRIAGE_INDEX), 'stored_ingest_batches': count(self.BATCHES_INDEX)}

    def load_alert_acknowledgements(self, tenant_id=None, limit=None, offset=0):
        return [hit['_source'] for hit in self._search(self.ACK_INDEX, tenant_id, limit, offset, 'updated_at')]

    def save_alert_acknowledgement(self, record):
        value = {**record, 'acknowledged': bool(record.get('acknowledged'))}
        self.client.index(index=self.ACK_INDEX, id=f"{value['tenant_id']}:{value['alert_id']}", body=value, refresh=False)
        return value

    def load_analyst_notes(self, alert_id, tenant_id=None, limit=None, offset=0):
        filters = [{'term': {'alert_id.keyword': alert_id}}]
        if tenant_id:
            filters.append({'term': {'tenant_id.keyword': tenant_id}})
        body = {'from': max(offset, 0), 'size': min(limit or 1000, 1000), 'sort': [{'created_at': 'desc'}], 'query': {'bool': {'filter': filters}}}
        return [hit['_source'] for hit in self.client.search(index=self.NOTES_INDEX, body=body).get('hits', {}).get('hits', [])]

    def save_analyst_note(self, record):
        value = {**record, 'note_id': record.get('note_id') or uuid4().hex}
        self.client.index(index=self.NOTES_INDEX, id=str(value['note_id']), body=value, refresh=False)
        return value


def build_storage_backend(name: str | None = None) -> StorageBackend:
    backend_name = (name or os.getenv('AI_SIEM_STORAGE', 'sqlite')).strip().lower()
    if backend_name == 'sqlite':
        return SQLiteBackend()
    if backend_name == 'memory':
        return MemoryBackend()
    if backend_name in {'postgres', 'postgresql'}:
        return PostgreSQLBackend()
    if backend_name == 'opensearch':
        return OpenSearchBackend()
    raise RuntimeError(f'Unsupported AI_SIEM_STORAGE backend: {backend_name}')
