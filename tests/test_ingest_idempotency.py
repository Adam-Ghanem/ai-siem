import os
import unittest
from copy import deepcopy

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
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
        main.AI_SIEM_STORAGE = 'memory'

    def tearDown(self):
        main.EVENTS[:] = self.original_events
        main.AI_SIEM_STORAGE = self.original_storage

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


if __name__ == '__main__':
    unittest.main()
