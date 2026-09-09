import unittest

from backend.threat_intel import ThreatIntelIndex


class ThreatIntelMetadataIntegrityTests(unittest.TestCase):
    def test_container_metadata_is_rejected_instead_of_stringified(self):
        malformed_entries = [
            {'indicator': '203.0.113.10', 'source': 'feed-a', 'type': {'name': 'ip'}},
            {'indicator': '203.0.113.11', 'source': 'feed-a', 'severity': ['high']},
            {'indicator': '203.0.113.12', 'source': 'feed-a', 'description': {'text': 'c2'}},
            {'indicator': '203.0.113.13', 'source': 'feed-a', 'tags': {'c2': True}},
            {'indicator': '203.0.113.14', 'source': 'feed-a', 'tags': ['c2', {'family': 'x'}]},
        ]

        index = ThreatIntelIndex(malformed_entries)

        self.assertEqual(index.stats()['entries'], 0)
        for entry in malformed_entries:
            self.assertFalse(index.lookup(entry['indicator'])['matched'])

    def test_scalar_tag_remains_backward_compatible(self):
        index = ThreatIntelIndex(
            [
                {
                    'indicator': '203.0.113.20',
                    'source': 'feed-a',
                    'type': 'ip',
                    'severity': 'high',
                    'tags': 'c2',
                }
            ]
        )

        result = index.lookup('203.0.113.20')

        self.assertTrue(result['matched'])
        self.assertEqual(result['tags'], ['c2'])


if __name__ == '__main__':
    unittest.main()
