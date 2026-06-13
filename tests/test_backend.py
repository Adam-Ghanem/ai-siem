import os
import unittest
from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}

class BackendApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
    def setUp(self):
        reset_rate_limit_state()

    def test_health_returns_status_ok(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'ok')

    def test_events_returns_non_empty_list(self):
        response = self.client.get('/api/events', headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json()), 0)

    def test_metrics_total_events_matches_loaded_events(self):
        events = self.client.get('/api/events', headers=AUTH).json()
        metrics_response = self.client.get('/api/metrics', headers=AUTH)
        self.assertEqual(metrics_response.status_code, 200)
        self.assertEqual(metrics_response.json()['total_events'], len(events))
        self.assertIn('unknown_event_rate_pct', metrics_response.json())

    def test_attack_coverage_reports_rule_metadata(self):
        response = self.client.get('/api/coverage/attack', headers=AUTH)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['total_rules'], len(main.RULES))
        self.assertTrue(any(t['tactic'] == 'Credential Access' for t in body['tactics']))
        self.assertTrue(any(t['technique'] == 'T1110' for t in body['techniques']))
        self.assertEqual(body['unmapped_rules'], [])

if __name__ == '__main__':
    unittest.main()