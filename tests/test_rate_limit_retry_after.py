import os
import unittest
from pathlib import Path

os.environ['AI_SIEM_API_KEY'] = 'test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_AUDIT_LOG'] = 'logs/test-rate-limit-retry-after-audit.log'

from fastapi.testclient import TestClient

from backend import main as main_module
import backend.security as security


AUDIT_PATH = Path('logs/test-rate-limit-retry-after-audit.log')


class RateLimitRetryAfterTests(unittest.TestCase):
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

    def test_rate_limit_response_includes_retry_after(self):
        self.assertEqual(self.client.get('/api/health').status_code, 200)

        response = self.client.get('/api/health')

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers.get('retry-after'), '60')


if __name__ == '__main__':
    unittest.main()
