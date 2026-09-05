import tempfile
import unittest
from pathlib import Path

from backend.models import Event
from backend.storage import init_db, save_events, search_events


class EventSearchFilterTests(unittest.TestCase):
    def test_search_events_supports_normalized_field_filters_and_stable_ordering(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            init_db(db)
            events = [
                Event.from_dict({
                    'id': 'evt-filter-1',
                    'timestamp': '2026-09-03T10:00:00+00:00',
                    'source': 'network',
                    'event_type': 'connection',
                    'asset': 'host-a',
                    'user': 'alice',
                    'src_ip': '10.0.0.10',
                    'dst_ip': '203.0.113.50',
                    'raw_log': 'connection one',
                }),
                Event.from_dict({
                    'id': 'evt-filter-2',
                    'timestamp': '2026-09-03T10:00:00+00:00',
                    'source': 'network',
                    'event_type': 'connection',
                    'asset': 'host-a',
                    'user': 'alice',
                    'src_ip': '10.0.0.10',
                    'dst_ip': '203.0.113.50',
                    'raw_log': 'connection two',
                }),
                Event.from_dict({
                    'id': 'evt-filter-3',
                    'timestamp': '2026-09-03T10:00:00+00:00',
                    'source': 'network',
                    'event_type': 'dns_query',
                    'asset': 'host-b',
                    'user': 'bob',
                    'src_ip': '10.0.0.11',
                    'dst_ip': '203.0.113.53',
                    'raw_log': 'dns query',
                }),
            ]
            self.assertEqual(save_events(events, db), 3)

            results, total = search_events(
                db,
                event_type='connection',
                asset='host-a',
                user='alice',
                src_ip='10.0.0.10',
                dst_ip='203.0.113.50',
                limit=10,
                offset=0,
            )

            self.assertEqual(total, 2)
            self.assertEqual(
                [event.id for event in results],
                ['evt-filter-2', 'evt-filter-1'],
            )

    def test_search_events_query_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            init_db(db)
            self.assertEqual(
                save_events([
                    Event.from_dict({
                        'id': 'evt-case-1',
                        'timestamp': '2026-09-03T11:00:00+00:00',
                        'source': 'windows',
                        'event_type': 'powershell_execution',
                        'asset': 'host-a',
                        'raw_log': 'PowerShell -EncodedCommand AAAA',
                    }),
                ], db),
                1,
            )

            results, total = search_events(db, query='powershell', limit=10, offset=0)

            self.assertEqual(total, 1)
            self.assertEqual([event.id for event in results], ['evt-case-1'])


if __name__ == '__main__':
    unittest.main()
