import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main
import backend.security as security


AUDIT_PATH = Path('logs/test-audit-search.log')


class AuditSearchTests(unittest.TestCase):
    def setUp(self):
        self.original_keys = security.API_KEYS
        self.original_audit_path = security.AUDIT_LOG_PATH
        security.API_KEYS = security._load_api_keys(
            '{"admin-token":{"role":"admin","principal":"secops@example.com"},'
            '"viewer-token":{"role":"viewer","principal":"viewer@example.com"}}'
        )
        security.AUDIT_LOG_PATH = AUDIT_PATH
        security.reset_rate_limit_state()
        security._AUDIT_HEAD_CACHE.clear()
        AUDIT_PATH.unlink(missing_ok=True)
        AUDIT_PATH.with_name(f'.{AUDIT_PATH.name}.lock').unlink(missing_ok=True)
        self.client = TestClient(main.app)

    def tearDown(self):
        security.API_KEYS = self.original_keys
        security.AUDIT_LOG_PATH = self.original_audit_path
        security.reset_rate_limit_state()
        security._AUDIT_HEAD_CACHE.clear()
        AUDIT_PATH.unlink(missing_ok=True)
        AUDIT_PATH.with_name(f'.{AUDIT_PATH.name}.lock').unlink(missing_ok=True)

    def test_admin_can_search_paginated_structured_audit_records(self):
        viewer_headers = {'Authorization': 'Bearer viewer-token'}
        forbidden = self.client.post('/api/ingest', headers=viewer_headers, json={'logs': []})
        self.assertEqual(forbidden.status_code, 403)

        response = self.client.get(
            '/api/audit',
            headers={'Authorization': 'Bearer admin-token'},
            params={
                'principal': 'viewer@example.com',
                'action': 'authz',
                'result': 'forbidden',
                'limit': 1,
                'offset': 0,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Total-Count'], '1')
        self.assertEqual(response.headers['X-Page-Limit'], '1')
        self.assertEqual(response.headers['X-Page-Offset'], '0')
        self.assertEqual(response.headers['X-Next-Offset'], '')
        self.assertEqual(len(response.json()), 1)
        record = response.json()[0]
        self.assertEqual(record['endpoint'], '/api/ingest')
        self.assertEqual(record['action'], 'authz')
        self.assertEqual(record['result'], 'forbidden')
        self.assertEqual(record['role'], 'viewer')
        self.assertEqual(record['principal'], 'viewer@example.com')
        self.assertTrue(record['timestamp'].endswith('Z'))

    def test_audit_search_rejects_tampered_log(self):
        forbidden = self.client.post(
            '/api/ingest',
            headers={'Authorization': 'Bearer viewer-token'},
            json={'logs': []},
        )
        self.assertEqual(forbidden.status_code, 403)
        self.assertTrue(AUDIT_PATH.exists())

        original = AUDIT_PATH.read_text(encoding='utf-8')
        tampered = original.replace('result=forbidden', 'result=success', 1)
        self.assertNotEqual(tampered, original)
        AUDIT_PATH.write_text(tampered, encoding='utf-8')
        security._AUDIT_HEAD_CACHE.clear()

        response = self.client.get(
            '/api/audit',
            headers={'Authorization': 'Bearer admin-token'},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()['detail'], 'Audit log integrity check failed')

    def test_audit_search_requires_admin_role(self):
        response = self.client.get(
            '/api/audit',
            headers={'Authorization': 'Bearer viewer-token'},
        )
        self.assertEqual(response.status_code, 403)


if __name__ == '__main__':
    unittest.main()
