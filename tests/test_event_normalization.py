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

    def test_explicit_event_id_is_trimmed(self):
        event = Event.from_dict({
            'id': '  evt-collector-001  ',
            'source': 'network',
            'event_type': 'connection',
        })

        self.assertEqual(event.id, 'evt-collector-001')

    def test_event_identity_fields_reject_oversized_values(self):
        cases = (
            ('id', 'x' * 257, 'id exceeds 256 characters'),
            ('source', 'x' * 129, 'source exceeds 128 characters'),
            ('event_type', 'x' * 129, 'event_type exceeds 128 characters'),
        )
        for field_name, value, error in cases:
            with self.subTest(field_name=field_name):
                payload = {
                    'source': 'network',
                    'event_type': 'connection',
                    field_name: value,
                }
                with self.assertRaisesRegex(ValueError, error):
                    Event.from_dict(payload)

    def test_event_identity_fields_accept_boundary_lengths(self):
        event = Event.from_dict({
            'id': 'i' * 256,
            'source': 's' * 128,
            'event_type': 't' * 128,
        })

        self.assertEqual(len(event.id), 256)
        self.assertEqual(len(event.source), 128)
        self.assertEqual(len(event.event_type), 128)

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

    def test_optional_fields_reject_oversized_values_after_trimming(self):
        cases = (
            ('asset', 'a' * 257, 'asset exceeds 256 characters'),
            ('user', 'u' * 257, 'user exceeds 256 characters'),
            ('src_ip', '1' * 257, 'src_ip exceeds 256 characters'),
            ('dst_ip', '2' * 257, 'dst_ip exceeds 256 characters'),
            ('status', 's' * 257, 'status exceeds 256 characters'),
            ('process_name', 'p' * 513, 'process_name exceeds 512 characters'),
            ('command_line', 'c' * 4097, 'command_line exceeds 4096 characters'),
            ('message', 'm' * 4097, 'message exceeds 4096 characters'),
        )
        for field_name, value, error in cases:
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, error):
                    Event.from_dict({
                        'source': 'network',
                        'event_type': 'connection',
                        field_name: f' {value} ',
                    })

    def test_optional_fields_accept_boundary_lengths(self):
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'asset': 'a' * 256,
            'process_name': 'p' * 512,
            'command_line': 'c' * 4096,
            'message': 'm' * 4096,
        })

        self.assertEqual(len(event.asset or ''), 256)
        self.assertEqual(len(event.process_name or ''), 512)
        self.assertEqual(len(event.command_line or ''), 4096)
        self.assertEqual(len(event.message or ''), 4096)

    def test_raw_log_enforces_utf8_byte_limit(self):
        boundary = 'é' * 5120
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'raw_log': boundary,
        })
        self.assertEqual(event.raw_log, boundary)

        with self.assertRaisesRegex(ValueError, 'raw_log exceeds 10240 bytes'):
            Event.from_dict({
                'source': 'network',
                'event_type': 'connection',
                'raw_log': boundary + 'é',
            })

    def test_synthesized_raw_log_is_also_bounded(self):
        with self.assertRaisesRegex(ValueError, 'raw_log exceeds 10240 bytes'):
            Event.from_dict({
                'source': 'network',
                'event_type': 'connection',
                'collector_extension': 'x' * 11000,
            })


if __name__ == '__main__':
    unittest.main()
