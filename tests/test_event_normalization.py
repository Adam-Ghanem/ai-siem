import unittest

from backend.models import Event


class EventNormalizationTests(unittest.TestCase):
    def test_required_taxonomy_fields_are_trimmed(self):
        event = Event.from_dict({'source': '  windows-security  ', 'event_type': ' authentication_failure\t'})
        self.assertEqual(event.source, 'windows-security')
        self.assertEqual(event.event_type, 'authentication_failure')

    def test_explicit_event_id_is_trimmed(self):
        event = Event.from_dict({'id': '  evt-collector-001  ', 'source': 'network', 'event_type': 'connection'})
        self.assertEqual(event.id, 'evt-collector-001')

    def test_event_identity_fields_reject_oversized_values(self):
        cases = (('id', 'x' * 257, 'id exceeds 256 characters'), ('source', 'x' * 129, 'source exceeds 128 characters'), ('event_type', 'x' * 129, 'event_type exceeds 128 characters'))
        for field_name, value, error in cases:
            with self.subTest(field_name=field_name):
                payload = {'source': 'network', 'event_type': 'connection', field_name: value}
                with self.assertRaisesRegex(ValueError, error): Event.from_dict(payload)

    def test_event_identity_fields_accept_boundary_lengths(self):
        event = Event.from_dict({'id': 'i' * 256, 'source': 's' * 128, 'event_type': 't' * 128})
        self.assertEqual(len(event.id), 256); self.assertEqual(len(event.source), 128); self.assertEqual(len(event.event_type), 128)

    def test_optional_text_fields_are_trimmed(self):
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'asset': '  host-01  ', 'user': ' alice ', 'src_ip': ' 10.0.0.7 ', 'dst_ip': ' 10.0.0.8 ', 'process_name': ' sshd ', 'command_line': ' ssh alice@host-01 ', 'status': ' success ', 'message': ' accepted '})
        self.assertEqual(event.asset, 'host-01'); self.assertEqual(event.user, 'alice'); self.assertEqual(event.src_ip, '10.0.0.7'); self.assertEqual(event.dst_ip, '10.0.0.8'); self.assertEqual(event.process_name, 'sshd'); self.assertEqual(event.command_line, 'ssh alice@host-01'); self.assertEqual(event.status, 'success'); self.assertEqual(event.message, 'accepted')

    def test_ip_fields_are_canonicalized(self):
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'src_ip': ' 2001:0db8:0000:0000:0000:0000:0000:0001 ', 'dst_ip': '192.0.2.10'})
        self.assertEqual(event.src_ip, '2001:db8::1'); self.assertEqual(event.dst_ip, '192.0.2.10')

    def test_invalid_ip_fields_are_rejected(self):
        for field_name in ('src_ip', 'dst_ip'):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, f'{field_name} must be a valid IP address'):
                    Event.from_dict({'source': 'network', 'event_type': 'connection', field_name: 'not-an-ip-address'})

    def test_network_transport_fields_are_normalized(self):
        event = Event.from_dict({'source': 'firewall', 'event_type': 'network_connection', 'src_port': ' 00443 ', 'dst_port': 65535, 'protocol': ' TCP '})
        self.assertEqual(event.src_port, 443)
        self.assertEqual(event.dst_port, 65535)
        self.assertEqual(event.protocol, 'tcp')
        self.assertEqual(event.to_dict()['src_port'], 443)

    def test_network_ports_reject_invalid_values(self):
        invalid_values = (-1, 65536, 1.5, True, '443/tcp', '１２３')
        for field_name in ('src_port', 'dst_port'):
            for value in invalid_values:
                with self.subTest(field_name=field_name, value=value):
                    with self.assertRaisesRegex(ValueError, f'{field_name} must be an integer between 0 and 65535'):
                        Event.from_dict({'source': 'network', 'event_type': 'connection', field_name: value})

    def test_blank_transport_fields_become_none(self):
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'src_port': ' ', 'dst_port': '', 'protocol': '\t'})
        self.assertIsNone(event.src_port); self.assertIsNone(event.dst_port); self.assertIsNone(event.protocol)

    def test_protocol_is_bounded_after_normalization(self):
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'protocol': ' TCP '})
        self.assertEqual(event.protocol, 'tcp')
        with self.assertRaisesRegex(ValueError, 'protocol exceeds 32 characters'):
            Event.from_dict({'source': 'network', 'event_type': 'connection', 'protocol': f" {'x' * 33} "})

    def test_blank_optional_entity_fields_become_none(self):
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'asset': '   ', 'user': '\t', 'src_ip': '\n', 'dst_ip': ''})
        self.assertIsNone(event.asset); self.assertIsNone(event.user); self.assertIsNone(event.src_ip); self.assertIsNone(event.dst_ip)

    def test_non_string_optional_fields_remain_invalid(self):
        with self.assertRaisesRegex(ValueError, 'asset must be a string'):
            Event.from_dict({'source': 'network', 'event_type': 'connection', 'asset': 123})

    def test_optional_fields_reject_oversized_values_after_trimming(self):
        cases = (('asset', 'a' * 257, 'asset exceeds 256 characters'), ('user', 'u' * 257, 'user exceeds 256 characters'), ('src_ip', '1' * 257, 'src_ip exceeds 256 characters'), ('dst_ip', '2' * 257, 'dst_ip exceeds 256 characters'), ('status', 's' * 257, 'status exceeds 256 characters'), ('process_name', 'p' * 513, 'process_name exceeds 512 characters'), ('command_line', 'c' * 4097, 'command_line exceeds 4096 characters'), ('message', 'm' * 4097, 'message exceeds 4096 characters'))
        for field_name, value, error in cases:
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, error): Event.from_dict({'source': 'network', 'event_type': 'connection', field_name: f' {value} '})

    def test_optional_fields_accept_boundary_lengths(self):
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'asset': 'a' * 256, 'process_name': 'p' * 512, 'command_line': 'c' * 4096, 'message': 'm' * 4096})
        self.assertEqual(len(event.asset or ''), 256); self.assertEqual(len(event.process_name or ''), 512); self.assertEqual(len(event.command_line or ''), 4096); self.assertEqual(len(event.message or ''), 4096)

    def test_raw_log_enforces_utf8_byte_limit(self):
        boundary = 'é' * 5120
        event = Event.from_dict({'source': 'network', 'event_type': 'connection', 'raw_log': boundary})
        self.assertEqual(event.raw_log, boundary)
        with self.assertRaisesRegex(ValueError, 'raw_log exceeds 10240 bytes'):
            Event.from_dict({'source': 'network', 'event_type': 'connection', 'raw_log': boundary + 'é'})

    def test_synthesized_raw_log_is_also_bounded(self):
        with self.assertRaisesRegex(ValueError, 'raw_log exceeds 10240 bytes'):
            Event.from_dict({'source': 'network', 'event_type': 'connection', 'collector_extension': 'x' * 11000})


if __name__ == '__main__': unittest.main()
