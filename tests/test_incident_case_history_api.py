import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IncidentCaseHistoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_incident_case_history_returns_chronological_audit_records(self):
        incident = self.client.get('/api/incidents', headers=AUTH).json()[0]
        history = [
            {
                'incident_id': incident['incident_id'],
                'status': 'investigating',
                'owner': 'alice',
                'disposition': 'undetermined',
                'note': 'Initial review',
                'updated_by': 'alice@example.com',
                'request_id': 'req-1',
                'updated_at': '2026-09-10T10:00:00+00:00',
            },
            {
                'incident_id': incident['incident_id'],
                'status': 'contained',
                'owner': 'bob',
                'disposition': 'true_positive',
                'note': 'Endpoint isolated',
                'updated_by': 'bob@example.com',
                'request_id': 'req-2',
                'updated_at': '2026-09-10T10:05:00+00:00',
            },
        ]

        with patch.object(main, 'load_incident_case_history', return_value=history):
            response = self.client.get(
                f"/api/incidents/{incident['incident_id']}/case/history",
                headers=AUTH,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), history)

    def test_incident_case_history_rejects_unknown_incident(self):
        response = self.client.get(
            '/api/incidents/INC-NOT-FOUND/case/history',
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()['detail'], 'Incident not found')


if __name__ == '__main__':
    unittest.main()
