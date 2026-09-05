import os
import unittest
from pathlib import Path

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_AUDIT_LOG', 'logs/test-audit-integrity.log')

from starlette.requests import Request

import backend.security as security


AUDIT_PATH = Path('logs/test-audit-integrity.log')


class AuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        security.AUDIT_LOG_PATH = AUDIT_PATH
        AUDIT_PATH.unlink(missing_ok=True)

    def test_untrusted_detail_cannot_inject_additional_audit_fields(self):
        scope = {
            'type': 'http',
            'method': 'POST',
            'path': '/api/triage',
            'raw_path': b'/api/triage',
            'query_string': b'',
            'headers': [],
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('198.51.100.10', 12345),
        }
        request = Request(scope)
        request.state.request_id = 'req-1'
        request.state.authz_role = 'analyst'

        security.audit_log(
            request,
            'triage',
            'success',
            'alert_id=AL-1 forged=true role=admin',
        )

        text = AUDIT_PATH.read_text(encoding='utf-8').strip()
        fields = text.split()
        self.assertIn('result=success', fields)
        self.assertNotIn('forged=true', fields)
        self.assertEqual(fields.count('role=admin'), 0)
        self.assertIn(
            'detail=alert_id%3DAL-1%20forged%3Dtrue%20role%3Dadmin',
            text,
        )


if __name__ == '__main__':
    unittest.main()
