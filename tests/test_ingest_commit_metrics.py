import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.parser import parser_stats, reset_parser_stats
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IngestCommitMetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()
        reset_parser_stats()

    def test_memory_capacity_rejection_does_not_commit_parser_metrics(self):
        original_storage = main.AI_SIEM_STORAGE
        original_limit = main.MAX_IN_MEMORY_EVENTS
        original_events = list(main.EVENTS)
        main.AI_SIEM_STORAGE = 'memory'
        main.MAX_IN_MEMORY_EVENTS = len(main.EVENTS)
        before = parser_stats()
        try:
            response = self.client.post(
                '/api/ingest',
                headers=AUTH,
                json={
                    'id': 'evt-capacity-rejected-metrics',
                    'timestamp': '2026-09-05T04:00:00+00:00',
                    'source': 'unit-test',
                    'event_type': 'process_execution',
                    'asset': 'host-capacity-test',
                    'raw_log': 'capacity rejection should not count as accepted parsing',
                },
            )
        finally:
            main.AI_SIEM_STORAGE = original_storage
            main.MAX_IN_MEMORY_EVENTS = original_limit
            main.EVENTS[:] = original_events

        self.assertEqual(response.status_code, 413)
        self.assertEqual(parser_stats(), before)


if __name__ == '__main__':
    unittest.main()
