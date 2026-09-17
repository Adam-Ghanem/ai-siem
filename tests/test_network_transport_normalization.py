import unittest

from backend.models import Event


class NetworkTransportNormalizationTests(unittest.TestCase):
    def test_network_transport_fields_are_normalized(self):
        event = Event.from_dict({
            'source': 'firewall',
            'event_type': 'network_connection',
            'src_port': ' 00443 ',
            'dst_port': 65535,
            'protocol': ' TCP ',
        })

        self.assertEqual(event.src_port, 443)
        self.assertEqual(event.dst_port, 65535)
        self.assertEqual(event.protocol, 'tcp')
        self.assertEqual(event.to_dict()['src_port'], 443)

    def test_network_ports_reject_invalid_values(self):
        invalid_values = (-1, 65536, 1.5, True, '443/tcp', '１２３')
        for field_name in ('src_port', 'dst_port'):
            for value in invalid_values:
                with self.subTest(field_name=field_name, value=value):
                    with self.assertRaisesRegex(
                        ValueError,
                        f'{field_name} must be an integer between 0 and 65535',
                    ):
                        Event.from_dict({
                            'source': 'network',
                            'event_type': 'connection',
                            field_name: value,
                        })

    def test_blank_transport_fields_become_none(self):
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'src_port': ' ',
            'dst_port': '',
            'protocol': '\t',
        })

        self.assertIsNone(event.src_port)
        self.assertIsNone(event.dst_port)
        self.assertIsNone(event.protocol)

    def test_protocol_is_bounded_after_normalization(self):
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'protocol': ' TCP ',
        })
        self.assertEqual(event.protocol, 'tcp')

        with self.assertRaisesRegex(ValueError, 'protocol exceeds 32 characters'):
            Event.from_dict({
                'source': 'network',
                'event_type': 'connection',
                'protocol': f" {'x' * 33} ",
            })


if __name__ == '__main__':
    unittest.main()
