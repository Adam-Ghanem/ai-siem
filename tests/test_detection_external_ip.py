import unittest

from backend.detection import run_detections
from tests.helpers import event


class RareExternalSourceTests(unittest.TestCase):
    def _baseline(self):
        return [
            event(1, status='success', src_ip='10.0.0.10', user='alice'),
            event(2, status='success', src_ip='10.0.0.11', user='alice'),
            event(3, status='success', src_ip='10.0.0.12', user='alice'),
        ]

    def test_special_use_address_does_not_trigger_rare_external_alert(self):
        events = self._baseline() + [
            event(4, status='success', src_ip='203.0.113.25', user='alice')
        ]
        alerts = run_detections(events)
        self.assertFalse(any(alert.rule_id == 'DET-AI-001' for alert in alerts))

    def test_global_ipv4_still_triggers_rare_external_alert(self):
        events = self._baseline() + [
            event(4, status='success', src_ip='172.200.10.25', user='alice')
        ]
        alerts = run_detections(events)
        self.assertTrue(any(alert.rule_id == 'DET-AI-001' for alert in alerts))

    def test_global_ipv6_triggers_rare_external_alert(self):
        events = self._baseline() + [
            event(4, status='success', src_ip='2606:4700:4700::1111', user='alice')
        ]
        alerts = run_detections(events)
        self.assertTrue(any(alert.rule_id == 'DET-AI-001' for alert in alerts))

    def test_private_ipv6_does_not_trigger_rare_external_alert(self):
        events = self._baseline() + [
            event(4, status='success', src_ip='fd00::25', user='alice')
        ]
        alerts = run_detections(events)
        self.assertFalse(any(alert.rule_id == 'DET-AI-001' for alert in alerts))


if __name__ == '__main__':
    unittest.main()
