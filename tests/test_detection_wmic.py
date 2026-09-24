import unittest

from backend.detection import run_detections
from tests.helpers import event


class WmicDetectionTests(unittest.TestCase):
    def test_remote_wmic_process_creation_is_high(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='wmic.exe',
                command_line=(
                    'wmic.exe /node:"server-02" process call create '
                    '"cmd.exe /c whoami > C:\\Temp\\diag.txt"'
                ),
            )
        ])

        self.assertTrue(
            any(
                alert.rule_id == 'DET-WIN-007'
                and alert.severity == 'high'
                and alert.technique == 'T1047'
                for alert in alerts
            )
        )

    def test_local_wmic_process_creation_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='wmic.exe',
                command_line='wmic.exe process call create "notepad.exe"',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-007' for alert in alerts))

    def test_remote_wmic_query_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='wmic.exe',
                command_line='wmic.exe /node:server-02 os get Caption,Version',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-007' for alert in alerts))

    def test_explicit_localhost_node_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='wmic.exe',
                command_line='wmic.exe /node:localhost process call create "notepad.exe"',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-007' for alert in alerts))


if __name__ == '__main__':
    unittest.main()
