import unittest

from backend.models import Event


class EventNormalizationTests(unittest.TestCase):
    def test_required_taxonomy_fields_are_trimmed(self):
        event = Event.from_dict({
            'source': '  windows-security  ',
            'event_type': ' authentication_failure\t',
        })

        self.assertEqual(event.source, 'windows-security')
        self.assertEqual(event.event_type, 'authentication_failure')

    def test_optional_text_fields_are_trimmed(self):
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'asset': '  host-01  ',
            'user': ' alice ',
            'src_ip': ' 10.0.0.7 ',
            'dst_ip': ' 10.0.0.8 ',
            'process_name': ' sshd ',
            'command_line': ' ssh alice@host-01 ',
            'status': ' success ',
            'message': ' accepted ',
        })

        self.assertEqual(event.asset, 'host-01')
        self.assertEqual(event.user, 'alice')
        self.assertEqual(event.src_ip, '10.0.0.7')
        self.assertEqual(event.dst_ip, '10.0.0.8')
        self.assertEqual(event.process_name, 'sshd')
        self.assertEqual(event.command_line, 'ssh alice@host-01')
        self.assertEqual(event.status, 'success')
        self.assertEqual(event.message, 'accepted')

    def test_blank_optional_entity_fields_become_none(self):
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'asset': '   ',
            'user': '\t',
            'src_ip': '\n',
            'dst_ip': '',
        })

        self.assertIsNone(event.asset)
        self.assertIsNone(event.user)
        self.assertIsNone(event.src_ip)
        self.assertIsNone(event.dst_ip)

    def test_non_string_optional_fields_remain_invalid(self):
        with self.assertRaisesRegex(ValueError, 'asset must be a string'):
            Event.from_dict({
                'source': 'network',
                'event_type': 'connection',
                'asset': 123,
            })


if __name__ == '__main__':
    unittest.main()
