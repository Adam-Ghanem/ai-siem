import unittest

from backend.threat_intel import ThreatIntelIndex


class _ExplodingIterable:
    def __iter__(self):
        raise AssertionError('lookup must not linearly scan the legacy CIDR list')


class ThreatIntelNetworkIndexTests(unittest.TestCase):
    def test_lookup_uses_bounded_network_index_for_ipv4_and_ipv6(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '10.20.0.0/16',
                    'type': 'cidr',
                    'source': 'feed-a',
                    'confidence': 80,
                    'severity': 'high',
                },
                {
                    'indicator': '10.20.30.0/24',
                    'type': 'cidr',
                    'source': 'feed-b',
                    'confidence': 95,
                    'severity': 'critical',
                },
                {
                    'indicator': '2001:db8:1234::/48',
                    'type': 'cidr',
                    'source': 'feed-v6',
                    'confidence': 88,
                    'severity': 'high',
                },
            ]
        )

        index._networks[4] = _ExplodingIterable()
        index._networks[6] = _ExplodingIterable()

        ipv4 = index.lookup('10.20.30.99')
        self.assertTrue(ipv4['matched'])
        self.assertEqual(ipv4['match_count'], 2)
        self.assertEqual(ipv4['max_confidence'], 95)
        self.assertEqual(
            ipv4['matched_indicators'],
            ['10.20.0.0/16', '10.20.30.0/24'],
        )

        ipv6 = index.lookup('2001:db8:1234::42')
        self.assertTrue(ipv6['matched'])
        self.assertEqual(ipv6['match_count'], 1)
        self.assertEqual(ipv6['matched_indicators'], ['2001:db8:1234::/48'])

    def test_exact_ip_and_cidr_matches_are_both_preserved(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '203.0.113.9',
                    'type': 'ip',
                    'source': 'exact-feed',
                    'confidence': 70,
                },
                {
                    'indicator': '203.0.113.0/24',
                    'type': 'cidr',
                    'source': 'network-feed',
                    'confidence': 90,
                },
            ]
        )

        result = index.lookup('203.0.113.9')

        self.assertEqual(result['match_count'], 2)
        self.assertEqual(result['max_confidence'], 90)
        self.assertEqual(result['sources'], ['exact-feed', 'network-feed'])


if __name__ == '__main__':
    unittest.main()
