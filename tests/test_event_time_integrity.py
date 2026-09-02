import unittest
from datetime import timezone

from backend.models import Event


class EventTimeIntegrityTests(unittest.TestCase):
    def test_rejects_malformed_explicit_timestamp(self):
        with self.assertRaisesRegex(ValueError, 'invalid event timestamp'):
            Event.from_dict({
                'id': 'evt-invalid-time-001',
                'timestamp': 'not-a-timestamp',
                'source': 'unit-test',
                'event_type': 'authentication',
            })

    def test_missing_timestamp_uses_current_utc_time(self):
        event = Event.from_dict({
            'id': 'evt-ingest-time-001',
            'source': 'unit-test',
            'event_type': 'authentication',
        })
        self.assertIsNotNone(event.timestamp.tzinfo)
        self.assertEqual(event.timestamp.utcoffset(), timezone.utc.utcoffset(event.timestamp))

    def test_naive_iso_timestamp_is_normalized_to_utc(self):
        event = Event.from_dict({
            'id': 'evt-naive-time-001',
            'timestamp': '2026-09-02T04:30:00',
            'source': 'unit-test',
            'event_type': 'authentication',
        })
        self.assertEqual(event.timestamp.isoformat(), '2026-09-02T04:30:00+00:00')


if __name__ == '__main__':
    unittest.main()
