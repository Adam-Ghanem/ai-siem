import os
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ['AI_SIEM_API_KEY'] = 'test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_AUDIT_LOG'] = 'logs/test-rate-limit-precise-retry-after-audit.log'

from fastapi import HTTPException
from starlette.requests import Request

import backend.security as security


AUDIT_PATH = Path('logs/test-rate-limit-precise-retry-after-audit.log')


class PreciseRateLimitRetryAfterTests(unittest.TestCase):
    def setUp(self):
        self.original_limit = security.GLOBAL_RATE_LIMIT_PER_MINUTE
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = 1
        security.reset_rate_limit_state()
        security.AUDIT_LOG_PATH = AUDIT_PATH
        AUDIT_PATH.unlink(missing_ok=True)

    def tearDown(self):
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = self.original_limit
        security.reset_rate_limit_state()
        AUDIT_PATH.unlink(missing_ok=True)

    def test_retry_after_reports_remaining_window(self):
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/api/health',
            'headers': [],
            'client': ('198.51.100.10', 12345),
            'scheme': 'http',
            'server': ('testserver', 80),
            'query_string': b'',
        }
        request = Request(scope)

        with patch('backend.security.time.time', return_value=100.0):
            security.enforce_rate_limit(request)

        with patch('backend.security.time.time', return_value=130.0):
            with self.assertRaises(HTTPException) as raised:
                security.enforce_rate_limit(request)

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.headers.get('Retry-After'), '30')


if __name__ == '__main__':
    unittest.main()
