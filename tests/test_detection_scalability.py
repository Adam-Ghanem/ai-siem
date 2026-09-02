import unittest
from unittest.mock import patch

import backend.detection as detection
from backend.rules import RULES
from tests.helpers import event


class DetectionScalabilityTests(unittest.TestCase):
    def test_static_rule_matching_is_linear_in_events_times_rules(self):
        events = [
            event(
                i,
                event_type='network_connection',
                source='firewall',
                src_ip='10.10.10.5',
                dst_ip=f'10.20.0.{(i % 200) + 1}',
                user=None,
                status=None,
            )
            for i in range(120)
        ]

        with patch('backend.detection._static', wraps=detection._static) as static_match:
            alerts = detection.run_detections(events)

        self.assertTrue(any(item.rule_id == 'DET-NET-001' for item in alerts))
        self.assertLessEqual(static_match.call_count, len(events) * len(RULES))


if __name__ == '__main__':
    unittest.main()
