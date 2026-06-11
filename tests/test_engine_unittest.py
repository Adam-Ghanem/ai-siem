import unittest
from fastapi.testclient import TestClient

from backend.app.main import app, store
from backend.engine.parser_v2 import parse_event, parse_events
from backend.engine.detection import run_detections
from backend.engine.correlation import correlate_alerts
from backend.engine.metrics import calculate_metrics
from backend.engine.anomaly import detect_anomalies

class ParserTests(unittest.TestCase):
    def test_linux_parser_normalizes_auth_log(self):
        event = parse_event('Jun 11 10:00:00 host1 sshd[123]: Failed password for invalid user root from 8.8.8.8 port 55123 ssh2')
        self.assertEqual(event.source, 'linux_auth')
        self.assertEqual(event.event_type, 'ssh_login')
        self.assertEqual(event.status, 'failure')
        self.assertEqual(event.user, 'root')
        self.assertEqual(event.src_ip, '8.8.8.8')

    def test_json_parser_accepts_normalized_event(self):
        event = parse_event({'source':'edr','event_type':'process_start','asset':'win01','user':'adam','raw_log':'x'})
        self.assertEqual(event.source, 'edr')
        self.assertEqual(event.asset, 'win01')

class DetectionTests(unittest.TestCase):
    def test_ssh_bruteforce_detection(self):
        events = parse_events([f'Jun 11 10:00:0{i} host1 sshd[12{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)])
        alerts = run_detections(events)
        self.assertTrue(any(a.rule_id == 'DET-SSH-001' for a in alerts))

    def test_success_after_failures_detection(self):
        logs = [f'Jun 11 10:00:0{i} host1 sshd[12{i}]: Failed password for invalid user root from 8.8.4.4 port 55{i} ssh2' for i in range(5)]
        logs.append('Jun 11 10:01:00 host1 sshd[999]: Accepted password for root from 8.8.4.4 port 5599 ssh2')
        alerts = run_detections(parse_events(logs))
        self.assertTrue(any(a.rule_id == 'DET-SSH-002' for a in alerts))

    def test_powershell_detection(self):
        event = parse_event('WinEvent Time=2026-06-11T12:06:00Z Host=win01 EventID=4104 User=adam Process=powershell.exe CommandLine="powershell -NoP -enc AAA"')
        alerts = run_detections([event])
        self.assertTrue(any(a.rule_id == 'DET-PS-001' for a in alerts))

    def test_port_scan_detection(self):
        logs = [f'2026-06-11T14:00:0{i}Z fw01 FW action=DENY src=10.0.0.5 dst=10.0.1.{i} dpt=445 proto=TCP msg="scan"' for i in range(9)]
        alerts = run_detections(parse_events(logs))
        self.assertTrue(any(a.rule_id == 'DET-NET-001' for a in alerts))

class CorrelationMetricsAnomalyTests(unittest.TestCase):
    def test_correlation_generates_real_incident_relationships(self):
        logs = [f'Jun 11 10:00:0{i} host1 sshd[12{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)]
        alerts = run_detections(parse_events(logs))
        incidents = correlate_alerts(alerts)
        self.assertGreaterEqual(len(incidents), 1)
        self.assertGreaterEqual(len(incidents[0].related_alert_ids), 1)

    def test_metrics_are_calculated_not_fake(self):
        events = parse_events([f'Jun 11 10:00:0{i} host1 sshd[12{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)])
        alerts = run_detections(events)
        incidents = correlate_alerts(alerts)
        metrics = calculate_metrics(events, alerts, incidents)
        self.assertEqual(metrics['total_events'], 6)
        self.assertEqual(metrics['total_alerts'], len(alerts))
        self.assertIn('source_distribution', metrics)

    def test_anomaly_generation(self):
        logs = [f'Jun 11 10:00:0{i} host1 sshd[12{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)]
        anomalies = detect_anomalies(parse_events(logs))
        self.assertTrue(any('failed-login' in a.reason for a in anomalies))

class ApiTests(unittest.TestCase):
    def test_ingest_endpoint(self):
        client = TestClient(app)
        before = len(store.events)
        response = client.post('/api/ingest', json={'logs':['Jun 11 12:00:00 host1 sshd[1]: Accepted password for adam from 10.0.0.9 port 22 ssh2']})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['ingested'], 1)
        self.assertEqual(len(store.events), before + 1)

    def test_triage_output(self):
        client = TestClient(app)
        response = client.post('/api/triage', json={'alert_id':'AL-test','action':'false_positive','analyst':'adam','notes':'lab test'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'recorded')

if __name__ == '__main__':
    unittest.main()
