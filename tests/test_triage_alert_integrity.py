import os
import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class TriageAlertIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_triage_rejects_unknown_alert_id(self):
        unknown_alert_id = f'AL-NOT-FOUND-{uuid4().hex}'

        response = self.client.post(
            '/api/triage',
            headers=AUTH,
            json={'alert_id': unknown_alert_id, 'action': 'reviewed'},
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['detail'], 'Alert not found')


if __name__ == '__main__':
    unittest.main()
