import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main, storage
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IngestIdCollisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()
        self.original_storage = main.AI_SIEM_STORAGE
        self.original_events = list(main.EVENTS)
        main.AI_SIEM_STORAGE = 'memory'

    def tearDown(self):
        main.EVENTS[:] = self.original_events
        main.AI_SIEM_STORAGE = self.original_storage

    def _event(self, raw_log: str):
        return {
            'id': 'evt-collision-001',
            'timestamp': '2026-09-04T15:00:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-collision-01',
            'raw_log': raw_log,
        }

    def test_memory_rejects_reused_event_id_with_different_content(self):
        first = self.client.post(
            '/api/ingest',
            json=self._event('original telemetry'),
            headers=AUTH,
        )
        collision = self.client.post(
            '/api/ingest',
            json=self._event('different telemetry'),
            headers=AUTH,
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(collision.status_code, 409)
        self.assertEqual(collision.json()['detail'], 'Event ID conflicts with existing telemetry')
        stored = [event for event in main.EVENTS if event.id == 'evt-collision-001']
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].raw_log, 'original telemetry')

    def test_identical_retry_without_client_timestamp_remains_idempotent(self):
        event = {
            'id': 'evt-idempotent-no-time-001',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-collision-02',
            'raw_log': 'timestamp supplied by collector gateway',
        }

        first = self.client.post('/api/ingest', json=event, headers=AUTH)
        retry = self.client.post('/api/ingest', json=event, headers=AUTH)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json()['ingested'], 0)
        self.assertEqual(retry.json()['duplicates_ignored'], 1)
        self.assertEqual(
            sum(item.id == event['id'] for item in main.EVENTS),
            1,
        )

    def test_sqlite_rejects_collision_against_persisted_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_db_path = storage.DEFAULT_DB_PATH
            try:
                storage.DEFAULT_DB_PATH = Path(tmp) / 'collision.db'
                main.AI_SIEM_STORAGE = 'sqlite'
                main.EVENTS[:] = []
                original = main.parse_events([self._event('persisted telemetry')])[0]
                self.assertEqual(storage.save_events([original]), 1)

                collision = self.client.post(
                    '/api/ingest',
                    json=self._event('different telemetry'),
                    headers=AUTH,
                )

                self.assertEqual(collision.status_code, 409)
                self.assertEqual(
                    collision.json()['detail'],
                    'Event ID conflicts with existing telemetry',
                )
                persisted = storage.load_events(limit=10)
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].raw_log, 'persisted telemetry')
            finally:
                storage.DEFAULT_DB_PATH = original_db_path


if __name__ == '__main__':
    unittest.main()
