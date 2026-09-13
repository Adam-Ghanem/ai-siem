import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class ReadinessProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_readiness_reports_ready_when_durable_dependencies_are_healthy(self):
        with (
            patch.object(main, 'storage_stats', return_value={'stored_events': 1}),
            patch.object(main, 'verify_audit_log', return_value=True),
        ):
            response = self.client.get('/api/ready', headers=AUTH)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'ready')

    def test_readiness_fails_closed_when_audit_integrity_fails(self):
        with (
            patch.object(main, 'storage_stats', return_value={'stored_events': 1}),
            patch.object(main, 'verify_audit_log', return_value=False),
        ):
            response = self.client.get('/api/ready', headers=AUTH)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()['status'], 'not_ready')
        self.assertEqual(response.json()['checks']['audit_log'], 'failed')

    def test_readiness_fails_closed_when_storage_check_raises(self):
        with (
            patch.object(main, 'storage_stats', side_effect=RuntimeError('db unavailable')),
            patch.object(main, 'verify_audit_log', return_value=True),
        ):
            response = self.client.get('/api/ready', headers=AUTH)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()['status'], 'not_ready')
        self.assertEqual(response.json()['checks']['storage'], 'failed')


if __name__ == '__main__':
    unittest.main()
