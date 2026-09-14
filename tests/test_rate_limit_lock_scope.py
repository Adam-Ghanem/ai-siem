import os
import unittest
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_AUDIT_LOG', 'logs/test-rate-limit-lock-audit.log')

from fastapi.testclient import TestClient

from backend import main as main_module
import backend.security as security


class RateLimitLockScopeTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main_module.app)
        self.original_limit = security.GLOBAL_RATE_LIMIT_PER_MINUTE
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = 1
        security.reset_rate_limit_state()

    def tearDown(self):
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = self.original_limit
        security.reset_rate_limit_state()

    def test_rate_limit_audit_happens_after_bucket_lock_is_released(self):
        headers = {'Authorization': 'Bearer test-token'}
        self.assertEqual(self.client.get('/api/events', headers=headers).status_code, 200)

        lock_states = []

        def capture_audit(*_args, **_kwargs):
            lock_states.append(security._BUCKET_LOCK.locked())

        with patch.object(security, 'audit_log', side_effect=capture_audit):
            response = self.client.get('/api/events', headers=headers)

        self.assertEqual(response.status_code, 429)
        self.assertEqual(lock_states, [False])


if __name__ == '__main__':
    unittest.main()
