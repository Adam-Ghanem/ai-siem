import os
import unittest
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

from backend import main
from backend.threat_intel import ThreatIntelEnricher


class ThreatIntelTests(unittest.TestCase):
    def test_abuseipdb_and_otx_are_normalized_and_cached(self):
        calls = []

        def fake_request(url, headers, params=None, timeout=3):
            calls.append((url, headers, params))
            if 'abuseipdb' in url:
                return 200, {'data': {'abuseConfidenceScore': 80, 'countryCode': 'US', 'totalReports': 4}}
            return 200, {'pulse_info': {'count': 3}, 'reputation': {'adversary': True}, 'sections': ['general']}

        enricher = ThreatIntelEnricher(
            abuseipdb_key='abuse-secret',
            otx_key='otx-secret',
            request_json=fake_request,
        )
        first = enricher.enrich(['8.8.8.8', '10.0.0.1', '8.8.8.8'])
        second = enricher.enrich(['8.8.8.8'])
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 2)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all('abuse-secret' not in str(result) for result in first))
        self.assertTrue(all('otx-secret' not in str(result) for result in first))
        self.assertTrue(any(result['malicious'] for result in first))

    def test_provider_failure_is_safe_fallback(self):
        def failing_request(*args, **kwargs):
            raise TimeoutError('provider timed out')

        enricher = ThreatIntelEnricher(abuseipdb_key='secret', request_json=failing_request)
        results = enricher.enrich(['8.8.8.8'])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['status'], 'error')
        self.assertIsNone(results[0]['malicious'])
        self.assertNotIn('secret', str(results[0]))

    def test_api_filters_private_indicators_and_returns_tenant(self):
        class FakeEnricher:
            def enrich(self, indicators):
                return [{'provider': 'mock', 'indicator': indicators[0], 'status': 'hit'}]

        client = TestClient(main.app)
        with patch.object(main, 'THREAT_INTEL', FakeEnricher()):
            response = client.post(
                '/api/threat-intel/enrich',
                headers={'Authorization': 'Bearer test-token'},
                json={'indicators': ['10.0.0.1', '8.8.8.8']},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['tenant_id'], 'default')
        self.assertEqual(response.json()['results'][0]['indicator'], '8.8.8.8')

    def test_api_status_does_not_expose_provider_keys(self):
        client = TestClient(main.app)
        response = client.get('/api/threat-intel/status', headers={'Authorization': 'Bearer test-token'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('API_KEY', response.text)
        self.assertNotIn('secret', response.text.lower())


if __name__ == '__main__':
    unittest.main()
