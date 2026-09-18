import unittest

from backend.models import Event


class IPScopeNormalizationTests(unittest.TestCase):
    def test_scoped_ipv6_addresses_are_rejected(self):
        for field_name in ('src_ip', 'dst_ip'):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(
                    ValueError,
                    f'{field_name} must be a valid IP address without a scope identifier',
                ):
                    Event.from_dict({
                        'source': 'network',
                        'event_type': 'connection',
                        field_name: 'fe80::1%eth0',
                    })

    def test_unscoped_ipv6_addresses_remain_canonical(self):
        event = Event.from_dict({
            'source': 'network',
            'event_type': 'connection',
            'src_ip': '2001:0db8:0:0:0:0:0:1',
        })
        self.assertEqual(event.src_ip, '2001:db8::1')


if __name__ == '__main__':
    unittest.main()
