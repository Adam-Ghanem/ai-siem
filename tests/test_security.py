import os
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

os.environ['AI_SIEM_API_KEY'] = 'test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_AUDIT_LOG'] = 'logs/test-audit.log'

from fastapi.testclient import TestClient

import backend.security as security
from backend import main as main_module
from backend.detection import run_detections
from backend.parser import parse_event, parser_stats
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}
AUDIT_PATH = Path('logs/test-audit.log')


class SecurityTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        security.AUDIT_LOG_PATH = AUDIT_PATH
        AUDIT_PATH.unlink(missing_ok=True)
        self.client = TestClient(main_module.app)

    def test_health_public_but_events_require_auth(self):
        self.assertEqual(self.client.get('/api/health').status_code, 200)
        self.assertEqual(self.client.get('/api/events').status_code, 401)
        self.assertEqual(self.client.get('/api/events', headers=AUTH).status_code, 200)

    def test_ingest_limits(self):
        self.assertEqual(
            self.client.post(
                '/api/ingest', headers=AUTH, json={'logs': ['x'] * 101}
            ).status_code,
            413,
        )
        self.assertEqual(
            self.client.post(
                '/api/ingest', headers=AUTH, json={'logs': ['A' * (10 * 1024 + 1)]}
            ).status_code,
            413,
        )

    def test_rate_limiting(self):
        original = security.GLOBAL_RATE_LIMIT_PER_MINUTE
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = 2
        reset_rate_limit_state()
        try:
            self.assertEqual(self.client.get('/api/health').status_code, 200)
            self.assertEqual(self.client.get('/api/health').status_code, 200)
            self.assertEqual(self.client.get('/api/health').status_code, 429)
        finally:
            security.GLOBAL_RATE_LIMIT_PER_MINUTE = original
            reset_rate_limit_state()

    def test_audit_logging(self):
        alert_id = self.client.get('/api/alerts', headers=AUTH).json()[0]['alert_id']
        r = self.client.post(
            '/api/triage',
            headers=AUTH,
            json={'alert_id': alert_id, 'action': 'acknowledged'},
        )
        self.assertEqual(r.status_code, 200)
        text = AUDIT_PATH.read_text(encoding='utf-8')
        self.assertIn('action=triage', text)
        self.assertNotIn('Bearer', text)

    def test_auth_uses_constant_time_secret_comparison(self):
        with patch.object(
            security.hmac,
            'compare_digest',
            wraps=security.hmac.compare_digest,
        ) as compare:
            response = self.client.get('/api/events', headers=AUTH)
        self.assertEqual(response.status_code, 200)
        compare.assert_called_with('test-token', 'test-token')

    def test_untrusted_forwarded_header_cannot_bypass_rate_limit(self):
        original_limit = security.GLOBAL_RATE_LIMIT_PER_MINUTE
        original_trust = security.TRUST_PROXY_HEADERS
        security.GLOBAL_RATE_LIMIT_PER_MINUTE = 2
        security.TRUST_PROXY_HEADERS = False
        reset_rate_limit_state()
        try:
            for index in range(2):
                response = self.client.get(
                    '/api/health', headers={'X-Forwarded-For': f'198.51.100.{index+1}'}
                )
                self.assertEqual(response.status_code, 200)
            blocked = self.client.get(
                '/api/health', headers={'X-Forwarded-For': '203.0.113.99'}
            )
            self.assertEqual(blocked.status_code, 429)
        finally:
            security.GLOBAL_RATE_LIMIT_PER_MINUTE = original_limit
            security.TRUST_PROXY_HEADERS = original_trust
            reset_rate_limit_state()

    def test_security_headers_are_present_on_success_and_auth_failure(self):
        for response in (
            self.client.get('/api/health'),
            self.client.get('/api/events'),
        ):
            self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
            self.assertEqual(response.headers['x-frame-options'], 'DENY')
            self.assertEqual(response.headers['cache-control'], 'no-store')

    def test_ingest_rejects_invalid_collection_shapes(self):
        self.assertEqual(
            self.client.post(
                '/api/ingest', headers=AUTH, json={'logs': 'one log'}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                '/api/ingest', headers=AUTH, json={'logs': [], 'events': []}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post('/api/ingest', headers=AUTH, json=[123]).status_code,
            400,
        )

    def test_request_body_limit_is_enforced_before_json_parsing(self):
        original = main_module.MAX_REQUEST_BYTES
        main_module.MAX_REQUEST_BYTES = 32
        try:
            response = self.client.post(
                '/api/ingest',
                headers={**AUTH, 'Content-Type': 'application/json'},
                content='{"logs":["' + ('x' * 64) + '"]}',
            )
            self.assertEqual(response.status_code, 413)
        finally:
            main_module.MAX_REQUEST_BYTES = original

    def test_duplicate_event_ids_are_ignored(self):
        event_id = f'evt-{uuid4().hex}'
        payload = {
            'events': [{'id': event_id, 'source': 'edr', 'event_type': 'process_start'}]
        }
        first = self.client.post('/api/ingest', headers=AUTH, json=payload)
        second = self.client.post('/api/ingest', headers=AUTH, json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()['ingested'], 1)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()['ingested'], 0)
        self.assertEqual(second.json()['duplicates_ignored'], 1)

    def test_triage_requires_real_alert_and_persists_record(self):
        missing = self.client.post(
            '/api/triage',
            headers=AUTH,
            json={'alert_id': 'AL-NOT-REAL', 'action': 'acknowledged'},
        )
        self.assertEqual(missing.status_code, 404)
        alert_id = self.client.get('/api/alerts', headers=AUTH).json()[0]['alert_id']
        created = self.client.post(
            '/api/triage',
            headers=AUTH,
            json={
                'alert_id': alert_id,
                'action': 'investigating',
                'analyst': 'soc-test',
            },
        )
        self.assertEqual(created.status_code, 200)
        records = self.client.get('/api/triage?limit=10', headers=AUTH)
        self.assertEqual(records.status_code, 200)
        self.assertTrue(
            any(
                record['record_id'] == created.json()['record_id']
                for record in records.json()
            )
        )

    def test_parser_stats_unknown_format(self):
        parse_event('this format is not supported')
        self.assertGreaterEqual(parser_stats()['unknown_events'], 1)

    def test_alert_suppression(self):
        logs = [
            f'Jun 11 10:00:0{i} host1 sshd[1{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2'
            for i in range(6)
        ]
        logs += [
            f'Jun 11 10:05:0{i} host1 sshd[2{i}]: Failed password for invalid user root from 8.8.8.8 port 66{i} ssh2'
            for i in range(6)
        ]
        events = [parse_event(x) for x in logs]
        alerts = [a for a in run_detections(events) if a.rule_id == 'DET-SSH-001']
        self.assertEqual(len(alerts), 1)


if __name__ == '__main__':
    unittest.main()
