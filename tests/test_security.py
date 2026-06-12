import os
import unittest
from pathlib import Path

os.environ['AI_SIEM_API_KEY']='test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE']='1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE']='1000'
os.environ['AI_SIEM_AUDIT_LOG']='logs/test-audit.log'

from fastapi.testclient import TestClient
from backend import main as main_module
from backend.parser import parse_event, parser_stats
from backend.detection import run_detections
from backend.security import reset_rate_limit_state
import backend.security as security

AUTH={'Authorization':'Bearer test-token'}

class SecurityTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        Path('logs/test-audit.log').unlink(missing_ok=True)
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

    def test_audit_logging(self):
        r=self.client.post('/api/triage',headers=AUTH,json={'alert_id':'AL-1','action':'reviewed'})
        self.assertEqual(r.status_code,200)
        text=Path('logs/test-audit.log').read_text(encoding='utf-8')
        self.assertIn('action=triage',text)
        self.assertNotIn('Bearer',text)

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
