import os
import unittest

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_AUDIT_LOG', 'logs/test-audit.log')

from fastapi.testclient import TestClient

from backend import main as main_module
import backend.security as security


class IdentityAwareRateLimitTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main_module.app)
        self.original_limit = security.GLOBAL_RATE_LIMIT_PER_MINUTE
        self.original_keys = security.API_KEYS
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = 2
        security.reset_rate_limit_state()

    def tearDown(self):
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = self.original_limit
        security.API_KEYS = self.original_keys
        security.reset_rate_limit_state()

    def test_unauthenticated_traffic_cannot_exhaust_authenticated_budget(self):
        self.assertEqual(self.client.get('/api/events').status_code, 401)
        self.assertEqual(self.client.get('/api/events').status_code, 401)

        response = self.client.get(
            '/api/events',
            headers={'Authorization': 'Bearer test-token'},
        )
        self.assertEqual(response.status_code, 200)

    def test_authenticated_identities_do_not_share_ip_budget(self):
        security.API_KEYS = {
            'analyst-one-token': {'role': 'analyst', 'principal': 'analyst-one'},
            'analyst-two-token': {'role': 'analyst', 'principal': 'analyst-two'},
        }
        analyst_one = {'Authorization': 'Bearer analyst-one-token'}
        analyst_two = {'Authorization': 'Bearer analyst-two-token'}

        self.assertEqual(self.client.get('/api/events', headers=analyst_one).status_code, 200)
        self.assertEqual(self.client.get('/api/events', headers=analyst_one).status_code, 200)
        self.assertEqual(self.client.get('/api/events', headers=analyst_two).status_code, 200)


if __name__ == '__main__':
    unittest.main()
