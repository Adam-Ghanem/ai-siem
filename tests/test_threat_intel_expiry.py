import unittest

from backend.threat_intel import ThreatIntelIndex


class ThreatIntelExpiryTests(unittest.TestCase):
    def test_expired_indicator_is_not_indexed_or_matched(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '203.0.113.77',
                    'type': 'ip',
                    'source': 'expiring-feed',
                    'confidence': 95,
                    'severity': 'critical',
                    'expires_at': '2000-01-01T00:00:00Z',
                }
            ]
        )

        result = index.lookup('203.0.113.77')

        self.assertFalse(result['matched'])
        self.assertEqual(result['match_count'], 0)
        self.assertEqual(index.stats()['entries'], 0)


if __name__ == '__main__':
    unittest.main()
