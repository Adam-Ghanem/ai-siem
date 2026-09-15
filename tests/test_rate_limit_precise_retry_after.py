import os
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ['AI_SIEM_API_KEY'] = 'test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_AUDIT_LOG'] = 'logs/test-rate-limit-precise-retry-after-audit.log'

from fastapi.testclient import TestClient

from backend import main as main_module
import backend.security as security


AUDIT_PATH = Path('logs/test-rate-limit-precise-retry-after-audit.log')


class PreciseRateLimitRetryAfterTests(unittest.TestCase):
    def setUp(self):
        self.original_limit = security.GLOBAL_RATE_LIMIT_PER_MINUTE
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = 1
        security.reset_rate_limit_state()
        security.AUDIT_LOG_PATH = AUDIT_PATH
        AUDIT_PATH.unlink(missing_ok=True)
        self.client = TestClient(main_module.app)

    def tearDown(self):
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = self.original_limit
        security.reset_rate_limit_state()
        AUDIT_PATH.unlink(missing_ok=True)

    def test_retry_after_reports_remaining_window(self):
        with patch('backend.security.time.time', side_effect=[100.0, 130.0]):
            self.assertEqual(self.client.get('/api/health').status_code, 200)
            response = self.client.get('/api/health')

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers.get('retry-after'), '30')


if __name__ == '__main__':
    unittest.main()
