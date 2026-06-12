import os
import unittest
from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY','test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE','1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE','1000')

from backend.main import app, EVENTS
from backend.parser import parse_event, parse_events
from backend.detection import run_detections
from backend.correlation import correlate
from backend.anomaly import detect_anomalies
from backend.metrics import calculate_metrics
from backend.security import reset_rate_limit_state

AUTH={'Authorization':'Bearer test-token'}

class ParserTests(unittest.TestCase):
    def test_linux_auth_normalization(self):
        e=parse_event('Jun 11 10:00:00 host1 sshd[1]: Failed password for invalid user root from 8.8.8.8 port 55 ssh2')
        self.assertEqual(e.source,'linux_auth'); self.assertEqual(e.event_type,'ssh_login'); self.assertEqual(e.user,'root'); self.assertEqual(e.src_ip,'8.8.8.8')
    def test_json_event_normalization(self):
        e=parse_event({'source':'edr','event_type':'process_start','asset':'win01','raw_log':'x'})
        self.assertEqual(e.source,'edr'); self.assertEqual(e.asset,'win01')

class DetectionTests(unittest.TestCase):
    def test_ssh_bruteforce(self):
        ev=parse_events([f'Jun 11 10:00:0{i} host1 sshd[1{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)])
        self.assertTrue(any(a.rule_id=='DET-SSH-001' for a in run_detections(ev)))
    def test_success_after_failures(self):
        logs=[f'Jun 11 10:00:0{i} host1 sshd[1{i}]: Failed password for invalid user root from 8.8.4.4 port 55{i} ssh2' for i in range(5)]
        logs.append('Jun 11 10:01:00 host1 sshd[99]: Accepted password for root from 8.8.4.4 port 5599 ssh2')
        self.assertTrue(any(a.rule_id=='DET-SSH-002' for a in run_detections(parse_events(logs))))
    def test_powershell_detection(self):
        e=parse_event('WinEvent Time=2026-06-11T12:06:00Z Host=win01 EventID=4104 User=adam Process=powershell.exe CommandLine="powershell -NoP -enc AAA"')
        self.assertTrue(any(a.rule_id=='DET-PS-001' for a in run_detections([e])))
    def test_port_scan_detection(self):
        logs=[f'2026-06-11T14:00:0{i}Z fw01 FW action=DENY src=10.0.0.5 dst=10.0.1.{i} dpt=445 proto=TCP msg="scan"' for i in range(9)]
        self.assertTrue(any(a.rule_id=='DET-NET-001' for a in run_detections(parse_events(logs))))

class SocLogicTests(unittest.TestCase):
    def test_correlation_metrics_anomaly(self):
        ev=parse_events([f'Jun 11 10:00:0{i} host1 sshd[1{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)])
        al=run_detections(ev); inc=correlate(al); m=calculate_metrics(ev,al,inc); an=detect_anomalies(ev)
        self.assertEqual(m['total_events'],6); self.assertGreaterEqual(len(inc),1); self.assertGreaterEqual(len(an),1)

class ApiTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
    def test_ingest_and_triage(self):
        c=TestClient(app); before=len(EVENTS)
        r=c.post('/api/ingest',headers=AUTH,json={'logs':['Jun 11 12:00:00 host1 sshd[1]: Accepted password for adam from 10.0.0.9 port 22 ssh2']})
        self.assertEqual(r.status_code,200); self.assertEqual(r.json()['ingested'],1); self.assertEqual(len(EVENTS),before+1)
        t=c.post('/api/triage',headers=AUTH,json={'alert_id':'AL-test','action':'false_positive','analyst':'adam'}); self.assertEqual(t.status_code,200); self.assertEqual(t.json()['status'],'recorded')

if __name__=='__main__': unittest.main()
