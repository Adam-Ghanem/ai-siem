import unittest

from backend.models import Event
from backend.threat_intel import ThreatIntelIndex


class ThreatIntelIndexTests(unittest.TestCase):
    def test_lookup_normalizes_indicator_and_returns_highest_confidence_match(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '203.0.113.7',
                    'type': 'ip',
                    'source': 'feed-a',
                    'confidence': 55,
                    'severity': 'medium',
                    'tags': ['scanner'],
                },
                {
                    'indicator': '203.0.113.7',
                    'type': 'ip',
                    'source': 'feed-b',
                    'confidence': 92,
                    'severity': 'high',
                    'tags': ['c2'],
                },
            ]
        )

        result = index.lookup(' 203.0.113.7 ')

        self.assertEqual(result['indicator'], '203.0.113.7')
        self.assertEqual(result['match_count'], 2)
        self.assertEqual(result['max_confidence'], 92)
        self.assertEqual(result['max_severity'], 'high')
        self.assertEqual(result['sources'], ['feed-a', 'feed-b'])
        self.assertEqual(result['tags'], ['c2', 'scanner'])

    def test_lookup_matches_ipv4_cidr_and_exact_indicator(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '203.0.113.0/24',
                    'type': 'cidr',
                    'source': 'network-feed',
                    'confidence': 80,
                    'severity': 'high',
                    'tags': ['scanner-range'],
                },
                {
                    'indicator': '203.0.113.7',
                    'type': 'ip',
                    'source': 'exact-feed',
                    'confidence': 95,
                    'severity': 'critical',
                    'tags': ['c2'],
                },
            ]
        )

        result = index.lookup('203.0.113.7')

        self.assertTrue(result['matched'])
        self.assertEqual(result['match_count'], 2)
        self.assertEqual(result['max_confidence'], 95)
        self.assertEqual(result['max_severity'], 'critical')
        self.assertEqual(
            result['matched_indicators'],
            ['203.0.113.0/24', '203.0.113.7'],
        )
        self.assertEqual(index.stats()['network_indicators'], 1)

    def test_lookup_matches_ipv6_cidr(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '2001:db8:abcd::/48',
                    'type': 'cidr',
                    'source': 'ipv6-feed',
                    'confidence': 77,
                    'severity': 'medium',
                }
            ]
        )

        result = index.lookup('2001:db8:abcd::42')

        self.assertTrue(result['matched'])
        self.assertEqual(result['matched_indicators'], ['2001:db8:abcd::/48'])
        self.assertEqual(result['sources'], ['ipv6-feed'])

    def test_enrich_events_returns_only_matching_observables(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '198.51.100.9',
                    'type': 'ip',
                    'source': 'trusted-feed',
                    'confidence': 88,
                    'severity': 'high',
                    'tags': ['botnet'],
                }
            ]
        )
        events = [
            Event.from_dict(
                {
                    'id': 'evt-1',
                    'timestamp': '2026-08-31T07:00:00Z',
                    'source': 'firewall',
                    'event_type': 'network_connection',
                    'src_ip': '198.51.100.9',
                    'dst_ip': '10.0.0.4',
                }
            ),
            Event.from_dict(
                {
                    'id': 'evt-2',
                    'timestamp': '2026-08-31T07:01:00Z',
                    'source': 'firewall',
                    'event_type': 'network_connection',
                    'src_ip': '192.0.2.44',
                    'dst_ip': '10.0.0.5',
                }
            ),
        ]

        enriched = index.enrich_events(events)

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]['indicator'], '198.51.100.9')
        self.assertEqual(enriched[0]['event_ids'], ['evt-1'])
        self.assertEqual(enriched[0]['max_confidence'], 88)

    def test_enrich_events_matches_network_indicators(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '198.51.100.0/24',
                    'type': 'cidr',
                    'source': 'range-feed',
                    'confidence': 83,
                    'severity': 'high',
                }
            ]
        )
        event = Event.from_dict(
            {
                'id': 'evt-cidr-1',
                'timestamp': '2026-09-02T07:00:00Z',
                'source': 'firewall',
                'event_type': 'network_connection',
                'src_ip': '198.51.100.27',
                'dst_ip': '10.0.0.4',
            }
        )

        enriched = index.enrich_events([event])

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]['indicator'], '198.51.100.27')
        self.assertEqual(enriched[0]['matched_indicators'], ['198.51.100.0/24'])
        self.assertEqual(enriched[0]['event_ids'], ['evt-cidr-1'])

    def test_invalid_feed_entries_are_ignored(self):
        index = ThreatIntelIndex(
            [
                {'indicator': '', 'source': 'broken'},
                {'indicator': 'example.com', 'source': '', 'confidence': 90},
                {'indicator': '203.0.113.0/99', 'source': 'broken-network'},
                {'indicator': 'example.com', 'source': 'valid', 'confidence': 150},
            ]
        )

        result = index.lookup('example.com')

        self.assertEqual(result['match_count'], 1)
        self.assertEqual(result['max_confidence'], 100)
        self.assertEqual(result['sources'], ['valid'])
        self.assertEqual(index.stats()['network_indicators'], 0)


if __name__ == '__main__':
    unittest.main()
