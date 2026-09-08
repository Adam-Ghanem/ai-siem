import os
import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.models import Event
from backend.security import reset_rate_limit_state
from backend.storage import save_events
from backend.storage import stats as storage_stats


AUTH = {'Authorization': 'Bearer test-token'}


class DurableMetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_metrics_include_events_outside_hot_window(self):
        event = Event(
            id='evt-durable-metrics-only',
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source='durable-metrics-source',
            event_type='durable-metrics-type',
            raw_log='historical durable metrics event',
        )
        self.assertFalse(any(item.id == event.id for item in main.EVENTS))
        save_events([event])
        persisted = storage_stats()

        response = self.client.get('/api/metrics', headers=AUTH)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['total_events'], persisted['stored_events'])
        self.assertEqual(body['source_distribution']['durable-metrics-source'], 1)
        self.assertEqual(body['event_type_distribution']['durable-metrics-type'], 1)


if __name__ == '__main__':
    unittest.main()
