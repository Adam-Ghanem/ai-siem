import unittest
from backend.parser import parse_event

class ParserTests(unittest.TestCase):
    def test_linux_auth_failed_ssh_line(self):
        e = parse_event('Jun 11 10:00:00 linux-app01 sshd[3000]: Failed password for invalid user oracle from 185.199.88.10 port 55000 ssh2')
        self.assertEqual(e.source, 'linux_auth')
        self.assertEqual(e.event_type, 'ssh_login')
        self.assertEqual(e.status, 'failure')
        self.assertEqual(e.user, 'oracle')
        self.assertEqual(e.src_ip, '185.199.88.10')

    def test_linux_auth_accepted_ssh_line(self):
        e = parse_event('Jun 11 10:01:00 linux-app01 sshd[3010]: Accepted password for oracle from 185.199.88.10 port 55100 ssh2')
        self.assertEqual(e.event_type, 'ssh_login')
        self.assertEqual(e.status, 'success')

    def test_linux_auth_accepted_publickey_line(self):
        e = parse_event('Jun 11 10:02:00 linux-app01 sshd[3020]: Accepted publickey for adam from 203.0.113.44 port 55200 ssh2: RSA SHA256:demo')
        self.assertEqual(e.event_type, 'ssh_login')
        self.assertEqual(e.status, 'success')
        self.assertEqual(e.user, 'adam')
        self.assertEqual(e.src_ip, '203.0.113.44')

    def test_windows_powershell_4104(self):
        e = parse_event('WinEvent Time=2026-06-11T12:06:00Z Host=win10-fin01 EventID=4104 User=adam Process=powershell.exe CommandLine="powershell.exe -NoP -enc SQBFAFgA" Message="PowerShell ScriptBlock"')
        self.assertEqual(e.source, 'windows')
        self.assertEqual(e.event_type, 'powershell_execution')
        self.assertIn('-enc', e.command_line)

    def test_firewall_line(self):
        e = parse_event('2026-06-11T13:00:00Z edge-fw01 FW action=ALLOW src=10.10.1.20 dst=10.10.2.10 dpt=443 proto=TCP msg="normal outbound web"')
        self.assertEqual(e.event_type, 'network_connection')
        self.assertEqual(e.src_ip, '10.10.1.20')
        self.assertEqual(e.dst_ip, '10.10.2.10')

    def test_waf_line(self):
        e = parse_event('198.51.100.25 - - [11/Jun/2026:15:00:00 +0000] "GET /login HTTP/1.1" 200 123 "Mozilla"')
        self.assertEqual(e.source, 'waf')
        self.assertEqual(e.event_type, 'http_request')
        self.assertEqual(e.src_ip, '198.51.100.25')

    def test_empty_line_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_event('   ')

if __name__ == '__main__':
    unittest.main()
