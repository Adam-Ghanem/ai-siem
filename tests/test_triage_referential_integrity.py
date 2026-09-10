import os
import unittest
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

from backend import main as main_module
from backend.security import reset_rate_limit_state


AUTH = {'Authorization': 'Bearer test-token'}


class TriageReferentialIntegrityTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        main_module.EVENTS.clear()
        main_module.TRIAGE.clear()
        self.client = TestClient(main_module.app)

    def tearDown(self):
        main_module.EVENTS.clear()
        main_module.TRIAGE.clear()
        reset_rate_limit_state()

    def test_triage_rejects_unknown_alert_id(self):
        with patch.object(main_module, 'AI_SIEM_STORAGE', 'memory'):
            response = self.client.post(
                '/api/triage',
                headers=AUTH,
                json={'alert_id': 'AL-DOES-NOT-EXIST', 'action': 'reviewed'},
            )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['detail'], 'Alert not found')
        self.assertEqual(main_module.TRIAGE, [])


if __name__ == '__main__':
    unittest.main()
