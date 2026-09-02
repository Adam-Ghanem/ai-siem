import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend.main import app
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IngestValidationTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_malformed_explicit_timestamp_is_rejected_as_client_error(self):
        response = self.client.post(
            '/api/ingest',
            headers=AUTH,
            json={
                'events': [
                    {
                        'id': 'evt-invalid-ingest-time-001',
                        'timestamp': 'not-a-timestamp',
                        'source': 'unit-test',
                        'event_type': 'authentication',
                    }
                ]
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('invalid event timestamp', response.json()['detail'])


if __name__ == '__main__':
    unittest.main()
