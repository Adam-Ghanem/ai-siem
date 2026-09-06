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


class IncidentCaseConcurrencyApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_case_update_maps_stale_version_to_conflict(self):
        incident = self.client.get('/api/incidents', headers=AUTH).json()[0]

        def reject_stale(record, *, expected_updated_at=None):
            if expected_updated_at == 'stale-version':
                raise ValueError('Incident case was modified by another request')
            return dict(record)

        with patch.object(main, 'save_incident_case', side_effect=reject_stale):
            response = self.client.post(
                f"/api/incidents/{incident['incident_id']}/case",
                headers=AUTH,
                json={
                    'status': 'investigating',
                    'expected_updated_at': 'stale-version',
                },
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['detail'], 'Incident case was modified by another request')


if __name__ == '__main__':
    unittest.main()
