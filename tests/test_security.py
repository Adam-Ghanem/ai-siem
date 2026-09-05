import os
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch

os.environ['AI_SIEM_API_KEY']='test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE']='1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE']='1000'
os.environ['AI_SIEM_AUDIT_LOG']='logs/test-audit.log'

from fastapi.testclient import TestClient
from starlette.requests import Request
from backend import main as main_module
from backend.parser import parse_event, parser_stats
from backend.detection import run_detections
from backend.security import reset_rate_limit_state
import backend.security as security

AUTH={'Authorization':'Bearer test-token'}
AUDIT_PATH=Path('logs/test-audit.log')

class SecurityTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        security.AUDIT_LOG_PATH=AUDIT_PATH
        AUDIT_PATH.unlink(missing_ok=True)
        self.client=TestClient(main_module.app)

    def test_health_public_but_events_require_auth(self):
        self.assertEqual(self.client.get('/api/health').status_code,200)
        self.assertEqual(self.client.get('/api/events').status_code,401)
        self.assertEqual(self.client.get('/api/events',headers=AUTH).status_code,200)

    def test_ingest_limits(self):
        self.assertEqual(self.client.post('/api/ingest',headers=AUTH,json={'logs':['x']*101}).status_code,413)
        self.assertEqual(self.client.post('/api/ingest',headers=AUTH,json={'logs':['A'*(10*1024+1)]}).status_code,413)

    def test_rate_limiting(self):
        original=security.GLOBAL_RATE_LIMIT_PER_MINUTE
        security.GLOBAL_RATE_LIMIT_PER_MINUTE=2
        reset_rate_limit_state()
        try:
            self.assertEqual(self.client.get('/api/health').status_code,200)
            self.assertEqual(self.client.get('/api/health').status_code,200)
            self.assertEqual(self.client.get('/api/health').status_code,429)
        finally:
            security.GLOBAL_RATE_LIMIT_PER_MINUTE=original
            reset_rate_limit_state()

    def test_stale_rate_limit_keys_are_evicted_before_capacity_check(self):
        original_capacity = security.MAX_RATE_LIMIT_KEYS
        security.MAX_RATE_LIMIT_KEYS = 1
        reset_rate_limit_state()
        security._GLOBAL_BUCKETS['198.51.100.1'] = deque([0.0])
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/api/events',
            'raw_path': b'/api/events',
            'query_string': b'',
            'headers': [],
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('198.51.100.2', 12345),
        }
        try:
            with patch('backend.security.time.time', return_value=61.0):
                security.enforce_rate_limit(Request(scope))
            self.assertNotIn('198.51.100.1', security._GLOBAL_BUCKETS)
            self.assertIn('198.51.100.2', security._GLOBAL_BUCKETS)
        finally:
            security.MAX_RATE_LIMIT_KEYS = original_capacity
            reset_rate_limit_state()

    def test_audit_logging(self):
        r=self.client.post('/api/triage',headers=AUTH,json={'alert_id':'AL-1','action':'reviewed'})
        self.assertEqual(r.status_code,200)
        text=AUDIT_PATH.read_text(encoding='utf-8')
        self.assertIn('action=triage',text)
        self.assertIn('role=admin',text)
        self.assertNotIn('Bearer',text)
        self.assertEqual(len(text.splitlines()), 1)
        self.assertTrue(r.json().get('request_id'))

    def test_audit_detail_cannot_inject_a_new_log_line(self):
        r=self.client.post(
            '/api/triage',
            headers=AUTH,
            json={'alert_id':'AL-\nforged=1', 'action':'reviewed'},
        )
        self.assertEqual(r.status_code, 200)
        text=AUDIT_PATH.read_text(encoding='utf-8')
        self.assertEqual(len(text.splitlines()), 1)
        self.assertFalse(any(line.startswith('forged=1') for line in text.splitlines()))

    def test_triage_is_readable_from_api(self):
        self.client.post('/api/triage', headers=AUTH, json={'alert_id':'AL-2','action':'closed'})
        response = self.client.get('/api/triage?limit=1', headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)

    def test_role_based_access_separates_read_ingest_and_triage(self):
        original_keys = security.API_KEYS
        security.API_KEYS = {
            'viewer-token': 'viewer',
            'ingestor-token': 'ingestor',
            'analyst-token': 'analyst',
        }
        viewer={'Authorization':'Bearer viewer-token'}
        ingestor={'Authorization':'Bearer ingestor-token'}
        analyst={'Authorization':'Bearer analyst-token'}
        try:
            self.assertEqual(self.client.get('/api/events', headers=viewer).status_code, 200)
            self.assertEqual(
                self.client.post('/api/ingest', headers=viewer, json={'logs':['x']}).status_code,
                403,
            )
            self.assertEqual(
                self.client.post('/api/triage', headers=viewer, json={'alert_id':'AL-RBAC','action':'reviewed'}).status_code,
                403,
            )
            self.assertEqual(
                self.client.post('/api/ingest', headers=ingestor, json={'logs':['x']}).status_code,
                200,
            )
            self.assertEqual(self.client.get('/api/events', headers=ingestor).status_code, 403)
            self.assertEqual(
                self.client.post('/api/triage', headers=ingestor, json={'alert_id':'AL-RBAC','action':'reviewed'}).status_code,
                403,
            )
            self.assertEqual(
                self.client.post('/api/triage', headers=analyst, json={'alert_id':'AL-RBAC','action':'reviewed'}).status_code,
                200,
            )
        finally:
            security.API_KEYS = original_keys

    def test_unmapped_mutating_route_requires_admin(self):
        original_keys = security.API_KEYS
        security.API_KEYS = {
            'viewer-token': 'viewer',
            'analyst-token': 'analyst',
            'admin-token': 'admin',
        }
        try:
            viewer = {'Authorization': 'Bearer viewer-token'}
            analyst = {'Authorization': 'Bearer analyst-token'}
            admin = {'Authorization': 'Bearer admin-token'}
            self.assertEqual(self.client.post('/api/future-write', headers=viewer).status_code, 403)
            self.assertEqual(self.client.post('/api/future-write', headers=analyst).status_code, 403)
            self.assertEqual(self.client.post('/api/future-write', headers=admin).status_code, 404)
        finally:
            security.API_KEYS = original_keys

    def test_api_key_role_configuration_validation(self):
        self.assertEqual(
            security._load_api_keys('{"read-token":"viewer","soc-token":"analyst"}'),
            {'read-token':'viewer','soc-token':'analyst'},
        )
        with self.assertRaises(RuntimeError):
            security._load_api_keys('{"token":"superuser"}')
        with self.assertRaises(RuntimeError):
            security._load_api_keys('[]')

    def test_parser_stats_unknown_format(self):
        parse_event('this format is not supported')
        self.assertGreaterEqual(parser_stats()['unknown_events'],1)

    def test_alert_suppression(self):
        logs=[f'Jun 11 10:00:0{i} host1 sshd[1{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)]
        logs += [f'Jun 11 10:05:0{i} host1 sshd[2{i}]: Failed password for invalid user root from 8.8.8.8 port 66{i} ssh2' for i in range(6)]
        events=[parse_event(x) for x in logs]
        alerts=[a for a in run_detections(events) if a.rule_id=='DET-SSH-001']
        self.assertEqual(len(alerts),1)

if __name__=='__main__': unittest.main()