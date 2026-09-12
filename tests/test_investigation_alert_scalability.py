import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class InvestigationAlertScalabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_sqlite_investigation_does_not_materialize_full_alert_history(self):
        incidents_response = self.client.get('/api/incidents', headers=AUTH)
        self.assertEqual(incidents_response.status_code, 200)
        incidents = incidents_response.json()
        self.assertTrue(incidents)
        incident_id = incidents[0]['incident_id']

        original_alerts = main.alerts

        def fail_if_full_history_is_loaded():
            raise AssertionError('investigation must not load the full alert history')

        main.alerts = fail_if_full_history_is_loaded
        try:
            response = self.client.get(
                f'/api/incidents/{incident_id}/investigation',
                headers=AUTH,
            )
        finally:
            main.alerts = original_alerts

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['incident_id'], incident_id)
        self.assertTrue(response.json()['related_alert_ids'])


if __name__ == '__main__':
    unittest.main()
