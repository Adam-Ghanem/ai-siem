import unittest
from tests.helpers import event
from backend.detection import run_detections

class DetectionTests(unittest.TestCase):
    def test_ssh_brute_force_detection(self):
        events = [event(i, status='failure', src_ip='203.0.113.10', user='root') for i in range(5)]
        alerts = run_detections(events)
        self.assertTrue(any(a.rule_id == 'DET-SSH-001' and a.severity == 'high' for a in alerts))

    def test_successful_login_after_failures(self):
        events = [event(i, status='failure', src_ip='203.0.113.10', user='oracle') for i in range(4)]
        events.append(event(60, status='success', src_ip='203.0.113.10', user='oracle'))
        alerts = run_detections(events)
        self.assertTrue(any(a.rule_id == 'DET-SSH-002' for a in alerts))

    def test_password_spraying_across_users(self):
        events = [
            event(i, status='failure', src_ip='203.0.113.20', user=f'user{i}')
            for i in range(5)
        ]
        alerts = run_detections(events)
        self.assertTrue(any(a.rule_id == 'DET-SSH-003' and a.severity == 'high' for a in alerts))

    def test_encoded_powershell_critical(self):
        alerts = run_detections([event(1, source='windows', event_type='powershell_execution', process_name='powershell.exe', command_line='powershell -NoP -enc SQBFAFgA')])
        self.assertTrue(any(a.rule_id == 'DET-PS-001' and a.severity == 'critical' for a in alerts))

    def test_port_scan_to_multiple_destinations(self):
        events = [event(i, source='firewall', event_type='network_connection', status='deny', src_ip='10.10.9.99', dst_ip=f'10.10.2.{i}') for i in range(1, 9)]
        alerts = run_detections(events)
        self.assertTrue(any(a.rule_id == 'DET-NET-001' for a in alerts))

    def test_sql_injection_path(self):
        alerts = run_detections([event(1, source='waf', event_type='http_request', src_ip='198.51.100.25', message='GET /search?q=1 UNION SELECT password FROM users user_agent=sqlmap')])
        self.assertTrue(any(a.rule_id == 'DET-WAF-001' and a.severity == 'high' for a in alerts))

    def test_benign_events_no_high_or_critical_alerts(self):
        events = [event(i, status='success', src_ip=f'10.0.0.{i}', user=f'user{i}') for i in range(1, 4)]
        alerts = run_detections(events)
        self.assertFalse(any(a.severity in {'high', 'critical'} for a in alerts))

if __name__ == '__main__':
    unittest.main()
