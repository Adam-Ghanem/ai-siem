import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend.main import app
from backend.parser import parser_stats, reset_parser_stats
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IngestValidationTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        reset_parser_stats()
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

    def test_rejected_batch_does_not_mutate_parser_statistics(self):
        response = self.client.post(
            '/api/ingest',
            headers=AUTH,
            json={
                'events': [
                    {
                        'id': 'evt-valid-before-invalid-001',
                        'timestamp': '2026-09-04T10:00:00Z',
                        'source': 'unit-test',
                        'event_type': 'authentication',
                    },
                    {
                        'id': 'evt-invalid-after-valid-001',
                        'timestamp': 'not-a-timestamp',
                        'source': 'unit-test',
                        'event_type': 'authentication',
                    },
                ]
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            parser_stats(),
            {
                'parsed_events': 0,
                'parsing_failed_events': 0,
                'unknown_events': 0,
                'unknown_samples': [],
            },
        )


if __name__ == '__main__':
    unittest.main()
