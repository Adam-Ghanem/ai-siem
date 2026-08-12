import unittest

from backend.parser import parse_event


class WindowsAndSysmonParserTests(unittest.TestCase):
    def test_windows_4624_successful_logon(self):
        event = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4624 '
            'User=adam IpAddress=203.0.113.10'
        )
        self.assertEqual(event.source, 'windows')
        self.assertEqual(event.event_id, '4624')
        self.assertEqual(event.event_type, 'windows_logon')
        self.assertEqual(event.status, 'success')
        self.assertEqual(event.src_ip, '203.0.113.10')

    def test_windows_4625_failed_logon(self):
        event = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4625 '
            'User=adam IpAddress=203.0.113.11'
        )
        self.assertEqual(event.event_id, '4625')
        self.assertEqual(event.event_type, 'windows_logon')
        self.assertEqual(event.status, 'failure')

    def test_windows_4688_process_creation(self):
        event = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4688 '
            'User=adam Process="powershell.exe" CommandLine="powershell -NoProfile"'
        )
        self.assertEqual(event.event_id, '4688')
        self.assertEqual(event.event_type, 'process_creation')
        self.assertEqual(event.process_name, 'powershell.exe')
        self.assertIn('NoProfile', event.command_line)

    def test_windows_4104_powershell_scriptblock(self):
        event = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4104 '
            'User=adam ScriptBlockText="Get-Process"'
        )
        self.assertEqual(event.event_id, '4104')
        self.assertEqual(event.event_type, 'powershell_execution')
        self.assertEqual(event.command_line, 'Get-Process')

    def test_windows_4720_and_4732_admin_changes(self):
        account = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4720 '
            'User=administrator TargetUserName=backdoor'
        )
        group = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4732 '
            'User=administrator TargetUserName=backdoor'
        )
        self.assertEqual(account.event_type, 'admin_account_change')
        self.assertEqual(account.event_id, '4720')
        self.assertEqual(group.event_type, 'admin_account_change')
        self.assertEqual(group.event_id, '4732')

    def test_sysmon_process_creation(self):
        event = parse_event(
            'Sysmon Time=2026-06-11T10:00:00Z Host=win01 EventID=1 '
            'User=adam Image="C:\\Windows\\System32\\cmd.exe" '
            'CommandLine="cmd.exe /c whoami"'
        )
        self.assertEqual(event.source, 'sysmon')
        self.assertEqual(event.event_id, '1')
        self.assertEqual(event.event_type, 'process_creation')
        self.assertEqual(event.process_name, 'C:\\Windows\\System32\\cmd.exe')
        self.assertIn('whoami', event.command_line)

    def test_unknown_windows_event_is_observed_not_executed(self):
        event = parse_event(
            'WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=9999 '
            'User=adam Message="vendor extension"'
        )
        self.assertEqual(event.event_type, 'windows_event')
        self.assertEqual(event.status, 'observed')
        self.assertEqual(event.event_id, '9999')


if __name__ == '__main__':
    unittest.main()
