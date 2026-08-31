import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class SearchValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_search_rejects_oversized_query(self):
        response = self.client.get(
            '/api/search/events',
            params={'q': 'x' * 513},
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 400)

    def test_search_rejects_reversed_time_window(self):
        response = self.client.get(
            '/api/search/events',
            params={
                'start': '2026-08-31T12:00:00+00:00',
                'end': '2026-08-31T11:00:00+00:00',
            },
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
