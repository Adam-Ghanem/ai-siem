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


if __name__ == '__main__':
    unittest.main()
