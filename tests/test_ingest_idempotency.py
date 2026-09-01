import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main, storage
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IngestIdempotencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()
        self.original_storage = main.AI_SIEM_STORAGE
        self.original_events = list(main.EVENTS)
        self.original_capacity = main.MAX_IN_MEMORY_EVENTS
        main.AI_SIEM_STORAGE = 'memory'

    def tearDown(self):
        main.EVENTS[:] = self.original_events
        main.AI_SIEM_STORAGE = self.original_storage
        main.MAX_IN_MEMORY_EVENTS = self.original_capacity

    def test_retry_with_same_event_id_is_idempotent(self):
        event = {
            'id': 'evt-idempotency-retry-001',
            'timestamp': '2026-08-31T22:00:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-retry-01',
            'raw_log': 'idempotent retry fixture',
        }

        first = self.client.post('/api/ingest', json=event, headers=AUTH)
        second = self.client.post('/api/ingest', json=event, headers=AUTH)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()['ingested'], 1)
        self.assertEqual(first.json()['duplicates_ignored'], 0)
        self.assertEqual(second.json()['ingested'], 0)
        self.assertEqual(second.json()['duplicates_ignored'], 1)
        self.assertEqual(
            sum(item.id == event['id'] for item in main.EVENTS),
            1,
        )

    def test_duplicate_ids_inside_one_batch_are_counted_once(self):
        event = {
            'id': 'evt-idempotency-batch-001',
            'timestamp': '2026-08-31T22:01:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-batch-01',
            'raw_log': 'batch duplicate fixture',
        }

        response = self.client.post(
            '/api/ingest',
            json=[event, deepcopy(event)],
            headers=AUTH,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['ingested'], 1)
        self.assertEqual(response.json()['duplicates_ignored'], 1)
        self.assertEqual(
            sum(item.id == event['id'] for item in main.EVENTS),
            1,
        )

    def test_duplicate_retry_does_not_consume_capacity(self):
        event = {
            'id': 'evt-idempotency-capacity-001',
            'timestamp': '2026-08-31T22:02:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-capacity-01',
            'raw_log': 'capacity replay fixture',
        }
        first = self.client.post('/api/ingest', json=event, headers=AUTH)
        self.assertEqual(first.status_code, 200)

        main.MAX_IN_MEMORY_EVENTS = len(main.EVENTS)
        retry = self.client.post('/api/ingest', json=event, headers=AUTH)

        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json()['ingested'], 0)
        self.assertEqual(retry.json()['duplicates_ignored'], 1)

    def test_sqlite_retry_checks_persisted_history_not_only_memory(self):
        event = {
            'id': 'evt-idempotency-persisted-001',
            'timestamp': '2026-08-31T22:03:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-persisted-01',
            'raw_log': 'persisted replay fixture',
        }

        with tempfile.TemporaryDirectory() as tmp:
            original_db_path = storage.DEFAULT_DB_PATH
            try:
                storage.DEFAULT_DB_PATH = Path(tmp) / 'idempotency.db'
                main.AI_SIEM_STORAGE = 'sqlite'
                main.EVENTS[:] = []
                persisted = main.parse_events([event])[0]
                self.assertEqual(storage.save_events([persisted]), 1)

                retry = self.client.post('/api/ingest', json=event, headers=AUTH)

                self.assertEqual(retry.status_code, 200)
                self.assertEqual(retry.json()['ingested'], 0)
                self.assertEqual(retry.json()['duplicates_ignored'], 1)
                self.assertEqual(len(main.EVENTS), 0)
                self.assertEqual(storage.stats()['stored_events'], 1)
            finally:
                storage.DEFAULT_DB_PATH = original_db_path

    def test_sqlite_ingest_rolls_hot_window_instead_of_rejecting_new_events(self):
        fixtures = [
            {
                'id': 'evt-hot-live-001',
                'timestamp': '2026-09-01T07:00:00+00:00',
                'source': 'unit-test-agent',
                'event_type': 'process_start',
                'asset': 'host-hot-01',
                'raw_log': 'oldest hot event',
            },
            {
                'id': 'evt-hot-live-002',
                'timestamp': '2026-09-01T07:05:00+00:00',
                'source': 'unit-test-agent',
                'event_type': 'process_start',
                'asset': 'host-hot-02',
                'raw_log': 'newer hot event',
            },
        ]
        incoming = {
            'id': 'evt-hot-live-003',
            'timestamp': '2026-09-01T07:10:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-hot-03',
            'raw_log': 'incoming hot event',
        }

        with tempfile.TemporaryDirectory() as tmp:
            original_db_path = storage.DEFAULT_DB_PATH
            try:
                storage.DEFAULT_DB_PATH = Path(tmp) / 'rolling-hot-window.db'
                main.AI_SIEM_STORAGE = 'sqlite'
                main.MAX_IN_MEMORY_EVENTS = 2
                main.EVENTS[:] = main.parse_events(fixtures)
                self.assertEqual(storage.save_events(main.EVENTS), 2)

                response = self.client.post('/api/ingest', json=incoming, headers=AUTH)

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['ingested'], 1)
                self.assertEqual(response.json()['hot_events'], 2)
                self.assertEqual(
                    [event.id for event in main.EVENTS],
                    ['evt-hot-live-002', 'evt-hot-live-003'],
                )
                self.assertEqual(storage.stats()['stored_events'], 3)
            finally:
                storage.DEFAULT_DB_PATH = original_db_path


if __name__ == '__main__':
    unittest.main()
