import unittest

from backend.threat_intel import ThreatIntelIndex


class ThreatIntelValidationTests(unittest.TestCase):
    def test_container_valued_indicator_and_source_are_rejected(self):
        index = ThreatIntelIndex()

        self.assertFalse(index.add({'indicator': {'ip': '203.0.113.10'}, 'source': 'feed-a'}))
        self.assertFalse(index.add({'indicator': ['203.0.113.10'], 'source': 'feed-a'}))
        self.assertFalse(index.add({'indicator': '203.0.113.10', 'source': {'name': 'feed-a'}}))
        self.assertFalse(index.add({'indicator': '203.0.113.10', 'source': ['feed-a']}))
        self.assertEqual(index.stats()['entries'], 0)

    def test_non_text_indicator_and_source_are_rejected(self):
        index = ThreatIntelIndex()

        self.assertFalse(index.add({'indicator': 203011310, 'source': 'feed-a'}))
        self.assertFalse(index.add({'indicator': True, 'source': 'feed-a'}))
        self.assertFalse(index.add({'indicator': '203.0.113.10', 'source': 42}))
        self.assertFalse(index.add({'indicator': '203.0.113.10', 'source': False}))
        self.assertEqual(index.stats()['entries'], 0)

    def test_non_finite_confidence_does_not_crash_feed_ingestion(self):
        for confidence in (float('nan'), float('inf'), float('-inf')):
            with self.subTest(confidence=confidence):
                index = ThreatIntelIndex()
                self.assertTrue(index.add({
                    'indicator': '8.8.8.8',
                    'source': 'feed-a',
                    'confidence': confidence,
                }))
                result = index.lookup('8.8.8.8')
                self.assertTrue(result['matched'])
                self.assertEqual(result['max_confidence'], 0)


if __name__ == '__main__':
    unittest.main()
