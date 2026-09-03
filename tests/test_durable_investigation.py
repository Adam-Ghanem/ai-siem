import os
import re
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class DurableInvestigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_historical_incident_investigation_loads_supporting_events_from_storage(self):
        incidents = self.client.get('/api/incidents', headers=AUTH).json()
        self.assertTrue(incidents)
        incident_id = incidents[0]['incident_id']

        original_events = main.EVENTS
        main.EVENTS = []
        try:
            response = self.client.get(
                f'/api/incidents/{incident_id}/investigation',
                headers=AUTH,
            )
        finally:
            main.EVENTS = original_events

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['related_event_ids'])
        match = re.search(r', (\d+) supporting event\(s\),', body['summary'])
        self.assertIsNotNone(match)
        self.assertGreater(int(match.group(1)), 0)


if __name__ == '__main__':
    unittest.main()
