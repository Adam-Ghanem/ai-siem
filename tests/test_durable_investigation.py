import os
import re
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.evidence_storage import load_events_by_ids
from backend.security import reset_rate_limit_state
from backend.threat_intel import ThreatIntelIndex

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

    def test_historical_incident_investigation_enriches_durable_event_threat_intel(self):
        incidents = self.client.get('/api/incidents', headers=AUTH).json()
        self.assertTrue(incidents)

        incident_id = None
        event = None
        for incident in incidents:
            candidate_id = incident['incident_id']
            baseline = self.client.get(
                f'/api/incidents/{candidate_id}/investigation',
                headers=AUTH,
            )
            self.assertEqual(baseline.status_code, 200)
            durable_events = load_events_by_ids(baseline.json()['related_event_ids'])
            candidate_event = next(
                (item for item in durable_events if item.src_ip or item.dst_ip),
                None,
            )
            if candidate_event is not None:
                incident_id = candidate_id
                event = candidate_event
                break

        self.assertIsNotNone(incident_id)
        self.assertIsNotNone(event)
        indicator = event.src_ip or event.dst_ip

        original_events = main.EVENTS
        original_threat_intel = main.THREAT_INTEL
        main.EVENTS = []
        main.THREAT_INTEL = ThreatIntelIndex(
            [
                {
                    'indicator': indicator,
                    'type': 'ip',
                    'source': 'unit-feed',
                    'confidence': 93,
                    'severity': 'critical',
                    'tags': ['durable-investigation-ioc'],
                }
            ]
        )
        try:
            response = self.client.get(
                f'/api/incidents/{incident_id}/investigation',
                headers=AUTH,
            )
        finally:
            main.EVENTS = original_events
            main.THREAT_INTEL = original_threat_intel

        self.assertEqual(response.status_code, 200)
        matches = response.json()['threat_intelligence']
        self.assertTrue(matches)
        self.assertEqual(matches[0]['indicator'], indicator)
        self.assertIn('unit-feed', matches[0]['sources'])


if __name__ == '__main__':
    unittest.main()
