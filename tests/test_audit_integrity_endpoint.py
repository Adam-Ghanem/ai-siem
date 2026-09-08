import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
import backend.security as security
from backend.security import reset_rate_limit_state


ADMIN = {'Authorization': 'Bearer test-token'}


class AuditIntegrityEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_audit_integrity_endpoint_is_admin_only_and_reports_tampering(self):
        original_keys = security.API_KEYS
        original_path = security.AUDIT_LOG_PATH
        security.API_KEYS = {'viewer-token': 'viewer'}
        viewer = {'Authorization': 'Bearer viewer-token'}
        try:
            with tempfile.TemporaryDirectory() as directory:
                security.AUDIT_LOG_PATH = Path(directory) / 'audit.log'

                self.assertEqual(
                    self.client.get('/api/audit/integrity', headers=viewer).status_code,
                    403,
                )

                healthy = self.client.get('/api/audit/integrity', headers=ADMIN)
                self.assertEqual(healthy.status_code, 200)
                self.assertEqual(healthy.json(), {'valid': True})

                security.AUDIT_LOG_PATH.write_text('tampered audit record\n', encoding='utf-8')
                tampered = self.client.get('/api/audit/integrity', headers=ADMIN)
                self.assertEqual(tampered.status_code, 503)
                self.assertEqual(tampered.json()['detail'], 'Audit log integrity check failed')
        finally:
            security.API_KEYS = original_keys
            security.AUDIT_LOG_PATH = original_path


if __name__ == '__main__':
    unittest.main()
