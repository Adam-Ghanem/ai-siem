import os
import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.models import Event
from backend.security import reset_rate_limit_state
from backend.storage import save_events
from backend.threat_intel import ThreatIntelIndex

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

    def test_event_search_exposes_storage_native_filters_and_pagination(self):
        sample = next(event for event in main.EVENTS if event.raw_log)
        query = sample.raw_log[:20]
        timestamp = sample.timestamp.isoformat()
        response = self.client.get(
            '/api/search/events',
            params={
                'source': sample.source,
                'q': query,
                'start': timestamp,
                'end': timestamp,
                'limit': 1,
                'offset': 0,
            },
            headers=AUTH,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]['source'], sample.source)
        self.assertIn(query, response.json()[0]['raw_log'])
        self.assertEqual(response.json()[0]['timestamp'], timestamp)
        self.assertGreaterEqual(int(response.headers['X-Total-Count']), 1)
        self.assertEqual(response.headers['X-Page-Limit'], '1')
        self.assertEqual(response.headers['X-Page-Offset'], '0')

    def test_alerts_support_storage_native_rule_and_time_filters(self):
        sample = main.alerts()[0]
        timestamp = sample.timestamp.isoformat()
        response = self.client.get(
            '/api/alerts',
            params={
                'rule_id': sample.rule_id,
                'start': timestamp,
                'end': timestamp,
                'limit': 1,
                'offset': 0,
            },
            headers=AUTH,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]['rule_id'], sample.rule_id)
        self.assertEqual(response.json()[0]['timestamp'], timestamp)
        self.assertGreaterEqual(int(response.headers['X-Total-Count']), 1)
        self.assertEqual(response.headers['X-Page-Limit'], '1')
        self.assertEqual(response.headers['X-Page-Offset'], '0')

    def test_alerts_reject_reversed_time_window(self):
        response = self.client.get(
            '/api/alerts',
            params={
                'start': '2026-09-01T11:00:00+00:00',
                'end': '2026-09-01T10:00:00+00:00',
            },
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 400)

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

    def test_list_endpoints_are_bounded_and_return_request_metadata(self):
        response = self.client.get('/api/events?limit=2&offset=1', headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.json()), 2)
        self.assertEqual(response.headers['X-Page-Limit'], '2')
        self.assertEqual(response.headers['X-Page-Offset'], '1')
        self.assertTrue(response.headers.get('X-Request-ID'))

    def test_invalid_pagination_is_rejected(self):
        response = self.client.get('/api/events?limit=0', headers=AUTH)
        self.assertEqual(response.status_code, 400)

    def test_incident_investigation_returns_evidence_grounded_analysis(self):
        incidents = self.client.get('/api/incidents', headers=AUTH).json()
        self.assertGreater(len(incidents), 0)
        incident_id = incidents[0]['incident_id']

        response = self.client.get(
            f'/api/incidents/{incident_id}/investigation',
            headers=AUTH,
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['incident_id'], incident_id)
        self.assertIn(body['risk_level'], {'critical', 'high', 'medium', 'low'})
        self.assertGreaterEqual(body['risk_score'], 0)
        self.assertLessEqual(body['risk_score'], 100)
        self.assertTrue(body['summary'])
        self.assertTrue(body['key_evidence'])
        self.assertTrue(body['recommended_actions'])
        self.assertIn('confidence', body)
        self.assertIn('mitre_techniques', body)

    def test_threat_intel_lookup_endpoint_returns_aggregated_context(self):
        original = main.THREAT_INTEL
        main.THREAT_INTEL = ThreatIntelIndex(
            [
                {
                    'indicator': '203.0.113.55',
                    'type': 'ip',
                    'source': 'unit-feed',
                    'confidence': 91,
                    'severity': 'critical',
                    'tags': ['c2'],
                }
            ]
        )
        try:
            response = self.client.get(
                '/api/threat-intel/lookup?indicator=203.0.113.55',
                headers=AUTH,
            )
        finally:
            main.THREAT_INTEL = original

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['indicator'], '203.0.113.55')
        self.assertEqual(body['match_count'], 1)
        self.assertEqual(body['max_confidence'], 91)
        self.assertEqual(body['max_severity'], 'critical')

    def test_event_threat_intel_endpoint_enriches_event_observables(self):
        event = next((item for item in main.EVENTS if item.src_ip or item.dst_ip), None)
        self.assertIsNotNone(event)
        indicator = event.src_ip or event.dst_ip
        original = main.THREAT_INTEL
        main.THREAT_INTEL = ThreatIntelIndex(
            [
                {
                    'indicator': indicator,
                    'type': 'ip',
                    'source': 'unit-feed',
                    'confidence': 84,
                    'severity': 'high',
                    'tags': ['malicious-infrastructure'],
                }
            ]
        )
        try:
            response = self.client.get(
                f'/api/events/{event.id}/threat-intel',
                headers=AUTH,
            )
        finally:
            main.THREAT_INTEL = original

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['event_id'], event.id)
        self.assertEqual(len(body['matches']), 1)
        self.assertEqual(body['matches'][0]['indicator'], indicator)

    def test_event_threat_intel_loads_durable_event_outside_hot_window(self):
        event = Event(
            id='evt-durable-threat-intel-only',
            timestamp=datetime(2026, 9, 1, tzinfo=timezone.utc),
            source='unit-test',
            event_type='network',
            src_ip='198.51.100.77',
            raw_log='durable historical event',
        )
        self.assertFalse(any(item.id == event.id for item in main.EVENTS))
        save_events([event])

        original = main.THREAT_INTEL
        main.THREAT_INTEL = ThreatIntelIndex(
            [
                {
                    'indicator': event.src_ip,
                    'type': 'ip',
                    'source': 'unit-feed',
                    'confidence': 88,
                    'severity': 'high',
                    'tags': ['historical-ioc'],
                }
            ]
        )
        try:
            response = self.client.get(
                f'/api/events/{event.id}/threat-intel',
                headers=AUTH,
            )
        finally:
            main.THREAT_INTEL = original

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['event_id'], event.id)
        self.assertEqual(body['matches'][0]['indicator'], event.src_ip)

if __name__ == '__main__':
    unittest.main()