import unittest
from fastapi.testclient import TestClient

from backend import main


class BackendApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def test_health_returns_status_ok(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'ok')

    def test_events_returns_non_empty_list(self):
        response = self.client.get('/api/events')
        self.assertEqual(response.status_code, 200)
        events = response.json()
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)

    def test_metrics_total_events_matches_loaded_events(self):
        events = self.client.get('/api/events').json()
        metrics_response = self.client.get('/api/metrics')
        self.assertEqual(metrics_response.status_code, 200)
        self.assertEqual(metrics_response.json()['total_events'], len(events))

    def test_alerts_use_real_detection_logic(self):
        response = self.client.get('/api/alerts')
        self.assertEqual(response.status_code, 200)
        alerts = response.json()
        self.assertIsInstance(alerts, list)
        self.assertTrue(any(a.get('rule_id') == 'DET-SSH-001' for a in alerts))
        self.assertTrue(all('severity' in a and 'confidence' in a for a in alerts))

    def test_anomalies_have_score_and_reason(self):
        response = self.client.get('/api/anomalies')
        self.assertEqual(response.status_code, 200)
        anomalies = response.json()
        self.assertIsInstance(anomalies, list)
        self.assertGreater(len(anomalies), 0)
        self.assertTrue(all('anomaly_score' in a and 'reason' in a for a in anomalies))

    def test_incidents_have_related_alerts_and_timeline(self):
        response = self.client.get('/api/incidents')
        self.assertEqual(response.status_code, 200)
        incidents = response.json()
        self.assertIsInstance(incidents, list)
        self.assertGreater(len(incidents), 0)
        self.assertTrue(all('related_alert_ids' in i and 'timeline' in i for i in incidents))

    def test_get_incident_by_id(self):
        incidents = self.client.get('/api/incidents').json()
        self.assertGreater(len(incidents), 0)
        incident_id = incidents[0]['incident_id']
        response = self.client.get(f'/api/incidents/{incident_id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['incident_id'], incident_id)

    def test_ingest_accepts_one_json_event_and_increases_total_events(self):
        before = self.client.get('/api/metrics').json()['total_events']
        payload = {
            'source': 'linux_auth',
            'event_type': 'ssh_login',
            'asset': 'jumpbox-test',
            'user': 'qa',
            'src_ip': '192.0.2.50',
            'status': 'success',
            'message': 'unit test ingest event',
        }
        response = self.client.post('/api/ingest', json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['ingested'], 1)
        after = self.client.get('/api/metrics').json()['total_events']
        self.assertEqual(after, before + 1)

    def test_ingest_rejects_invalid_json(self):
        response = self.client.post('/api/ingest', content='{bad json', headers={'content-type': 'application/json'})
        self.assertEqual(response.status_code, 400)

    def test_ingest_rejects_invalid_event_format(self):
        response = self.client.post('/api/ingest', json={'source': 'linux_auth'})
        self.assertEqual(response.status_code, 400)

    def test_triage_requires_target_and_action(self):
        no_target = self.client.post('/api/triage', json={'action': 'acknowledge'})
        self.assertEqual(no_target.status_code, 400)
        no_action = self.client.post('/api/triage', json={'alert_id': 'AL-1'})
        self.assertEqual(no_action.status_code, 400)
        valid = self.client.post('/api/triage', json={'alert_id': 'AL-1', 'action': 'acknowledge'})
        self.assertEqual(valid.status_code, 200)
        self.assertEqual(valid.json()['status'], 'recorded')


if __name__ == '__main__':
    unittest.main()
