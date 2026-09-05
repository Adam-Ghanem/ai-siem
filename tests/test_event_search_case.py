import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.models import Event
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class EventSearchCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()
        self.original_storage = main.AI_SIEM_STORAGE
        self.original_events = list(main.EVENTS)
        main.AI_SIEM_STORAGE = 'memory'
        main.EVENTS[:] = [
            Event.from_dict({
                'id': 'evt-case-memory-1',
                'timestamp': '2026-09-05T07:00:00+00:00',
                'source': 'windows',
                'event_type': 'powershell_execution',
                'asset': 'host-a',
                'raw_log': 'PowerShell -EncodedCommand AAAA',
            }),
        ]

    def tearDown(self):
        main.EVENTS[:] = self.original_events
        main.AI_SIEM_STORAGE = self.original_storage

    def test_memory_event_search_query_is_case_insensitive(self):
        response = self.client.get('/api/search/events?q=powershell', headers=AUTH)

        self.assertEqual(response.status_code, 200)
        self.assertEqual([event['id'] for event in response.json()], ['evt-case-memory-1'])
        self.assertEqual(response.headers['x-total-count'], '1')


if __name__ == '__main__':
    unittest.main()
