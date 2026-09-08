import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main
import backend.security as security


class AuditIntegrityEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        security.reset_rate_limit_state()

    def test_admin_endpoint_reports_valid_chain_and_detects_tampering(self):
        original_api_key = security.API_KEY
        original_keys = security.API_KEYS
        original_path = security.AUDIT_LOG_PATH
        security.API_KEY = 'admin-token'
        security.API_KEYS = {'viewer-token': 'viewer'}
        admin = {'Authorization': 'Bearer admin-token'}
        viewer = {'Authorization': 'Bearer viewer-token'}
        try:
            with tempfile.TemporaryDirectory() as directory:
                security.AUDIT_LOG_PATH = Path(directory) / 'audit.log'

                forbidden = self.client.get('/api/audit/integrity', headers=viewer)
                self.assertEqual(forbidden.status_code, 403)

                healthy = self.client.get('/api/audit/integrity', headers=admin)
                self.assertEqual(healthy.status_code, 200)
                self.assertEqual(healthy.json(), {'valid': True})

                security.AUDIT_LOG_PATH.write_text(
                    'tampered audit record\n',
                    encoding='utf-8',
                )
                tampered = self.client.get('/api/audit/integrity', headers=admin)
                self.assertEqual(tampered.status_code, 503)
                self.assertEqual(
                    tampered.json()['detail'],
                    'Audit log integrity check failed',
                )
        finally:
            security.API_KEY = original_api_key
            security.API_KEYS = original_keys
            security.AUDIT_LOG_PATH = original_path


if __name__ == '__main__':
    unittest.main()
