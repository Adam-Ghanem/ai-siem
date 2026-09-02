import os
import unittest
from pathlib import Path

os.environ['AI_SIEM_API_KEY'] = 'test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_AUDIT_LOG'] = 'logs/test-identity-audit.log'

from fastapi.testclient import TestClient

from backend import main as main_module
import backend.security as security


AUDIT_PATH = Path('logs/test-identity-audit.log')


class AuthIdentityTests(unittest.TestCase):
    def setUp(self):
        security.reset_rate_limit_state()
        security.AUDIT_LOG_PATH = AUDIT_PATH
        AUDIT_PATH.unlink(missing_ok=True)
        self.client = TestClient(main_module.app)

    def test_structured_api_key_records_principal_in_audit_and_triage(self):
        original_keys = security.API_KEYS
        security.API_KEYS = security._load_api_keys(
            '{"soc-token":{"role":"analyst","principal":"alice@example.com"}}'
        )
        try:
            response = self.client.post(
                '/api/triage',
                headers={'Authorization': 'Bearer soc-token'},
                json={
                    'alert_id': 'AL-IDENTITY',
                    'action': 'reviewed',
                    'analyst': 'mallory@example.com',
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['analyst'], 'alice@example.com')
            audit_text = AUDIT_PATH.read_text(encoding='utf-8')
            self.assertIn('role=analyst', audit_text)
            self.assertIn('principal=alice@example.com', audit_text)
            self.assertNotIn('mallory@example.com', audit_text)
            self.assertNotIn('soc-token', audit_text)
        finally:
            security.API_KEYS = original_keys


if __name__ == '__main__':
    unittest.main()
