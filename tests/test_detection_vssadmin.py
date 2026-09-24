import unittest

from backend.detection import run_detections
from tests.helpers import event


class VssadminShadowDeletionDetectionTests(unittest.TestCase):
    def test_delete_shadows_is_critical(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='vssadmin.exe',
                command_line='vssadmin.exe delete shadows /all /quiet',
            )
        ])

        self.assertTrue(
            any(
                alert.rule_id == 'DET-WIN-009'
                and alert.severity == 'critical'
                and alert.technique == 'T1490'
                for alert in alerts
            )
        )

    def test_case_insensitive_delete_shadows_is_detected(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='VSSADMIN.EXE',
                command_line='VSSADMIN Delete Shadows /For=C: /Quiet',
            )
        ])

        self.assertTrue(any(alert.rule_id == 'DET-WIN-009' for alert in alerts))

    def test_vssadmin_list_shadows_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='vssadmin.exe',
                command_line='vssadmin.exe list shadows',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-009' for alert in alerts))

    def test_unrelated_delete_command_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='cmd.exe',
                command_line='cmd.exe /c del C:\\Temp\\shadows.txt',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-009' for alert in alerts))


if __name__ == '__main__':
    unittest.main()
