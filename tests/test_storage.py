import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.models import Event
from backend.storage import (
    init_db,
    load_events,
    load_triage,
    save_events,
    save_triage,
    search_events,
    stats,
)


class StorageTests(unittest.TestCase):
    def test_sqlite_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            init_db(db)
            event = Event.from_dict({
                'id': 'evt-storage-1',
                'source': 'linux_auth',
                'event_type': 'ssh_login',
                'asset': 'lab-host',
                'user': 'adam',
                'src_ip': '203.0.113.10',
                'status': 'failure',
                'message': 'real test event',
                'raw_log': 'real test event',
            })
            self.assertEqual(save_events([event], db), 1)
            self.assertEqual(save_events([event], db), 0)
            loaded = load_events(db)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].id, 'evt-storage-1')
            self.assertEqual(loaded[0].source, 'linux_auth')
            storage_stats = stats(db)
            self.assertEqual(storage_stats['backend'], 'sqlite')
            self.assertEqual(storage_stats['stored_events'], 1)
            self.assertEqual(storage_stats['source_distribution']['linux_auth'], 1)

    def test_search_events_filters_orders_and_counts_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'search.db'
            init_db(db)
            events = [
                Event.from_dict({
                    'id': 'evt-search-1',
                    'timestamp': '2026-08-31T10:00:00+00:00',
                    'source': 'linux_auth',
                    'event_type': 'ssh_login',
                    'asset': 'host-a',
                    'src_ip': '203.0.113.10',
                    'message': 'failed password for root',
                    'raw_log': 'sshd failed password for root',
                }),
                Event.from_dict({
                    'id': 'evt-search-2',
                    'timestamp': '2026-08-31T10:05:00+00:00',
                    'source': 'linux_auth',
                    'event_type': 'ssh_login',
                    'asset': 'host-a',
                    'src_ip': '203.0.113.11',
                    'message': 'failed password for admin',
                    'raw_log': 'sshd failed password for admin',
                }),
                Event.from_dict({
                    'id': 'evt-search-3',
                    'timestamp': '2026-08-31T10:10:00+00:00',
                    'source': 'windows_security',
                    'event_type': 'logon_success',
                    'asset': 'host-b',
                    'src_ip': '203.0.113.12',
                    'message': 'interactive logon',
                    'raw_log': 'successful interactive logon',
                }),
            ]
            self.assertEqual(save_events(events, db), 3)

            results, total = search_events(
                db,
                source='linux_auth',
                query='failed password',
                start=datetime(2026, 8, 31, 10, 1, tzinfo=timezone.utc),
                end=datetime(2026, 8, 31, 10, 6, tzinfo=timezone.utc),
                limit=10,
                offset=0,
            )

            self.assertEqual(total, 1)
            self.assertEqual([event.id for event in results], ['evt-search-2'])

            all_results, all_total = search_events(db, limit=2, offset=0)
            self.assertEqual(all_total, 3)
            self.assertEqual(
                [event.id for event in all_results],
                ['evt-search-3', 'evt-search-2'],
            )

    def test_triage_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'triage.db'
            init_db(db)
            saved = save_triage({
                'alert_id': 'AL-42',
                'action': 'contain',
                'analyst': 'soc-user',
                'status': 'recorded',
                'request_id': 'req-1',
            }, db)
            self.assertEqual(saved['alert_id'], 'AL-42')
            loaded = load_triage(db)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]['action'], 'contain')
            self.assertEqual(loaded[0]['request_id'], 'req-1')
            self.assertEqual(stats(db)['stored_triage_records'], 1)


if __name__ == '__main__':
    unittest.main()
