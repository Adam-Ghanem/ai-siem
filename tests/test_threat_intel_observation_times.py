import unittest

from backend.threat_intel import ThreatIntelIndex


class ThreatIntelObservationTimeTests(unittest.TestCase):
    def test_rejects_invalid_or_reversed_observation_times(self):
        index = ThreatIntelIndex()

        self.assertFalse(
            index.add(
                {
                    'indicator': '203.0.113.20',
                    'source': 'feed-a',
                    'first_seen': 'not-a-time',
                    'last_seen': '2026-09-08T07:00:00Z',
                }
            )
        )
        self.assertFalse(
            index.add(
                {
                    'indicator': '203.0.113.21',
                    'source': 'feed-a',
                    'first_seen': '2026-09-08T08:00:00Z',
                    'last_seen': '2026-09-08T07:00:00Z',
                }
            )
        )
        self.assertEqual(index.stats()['entries'], 0)

    def test_observation_times_are_canonicalized_to_utc(self):
        index = ThreatIntelIndex()

        self.assertTrue(
            index.add(
                {
                    'indicator': '203.0.113.22',
                    'source': 'feed-a',
                    'first_seen': '2026-09-08T09:00:00+02:00',
                    'last_seen': '2026-09-08T10:30:00+02:00',
                }
            )
        )
        match = index.lookup('203.0.113.22')['matches'][0]
        self.assertEqual(match['first_seen'], '2026-09-08T07:00:00+00:00')
        self.assertEqual(match['last_seen'], '2026-09-08T08:30:00+00:00')


if __name__ == '__main__':
    unittest.main()
