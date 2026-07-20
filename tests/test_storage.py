import tempfile
import unittest
from pathlib import Path

from backend.models import Event
from backend.storage import (
    init_db,
    load_events,
    load_triage_records,
    save_events,
    save_triage_record,
    stats,
)


class StorageTests(unittest.TestCase):
    def test_sqlite_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            init_db(db)
            event = Event.from_dict(
                {
                    'id': 'evt-storage-1',
                    'source': 'linux_auth',
                    'event_type': 'ssh_login',
                    'asset': 'lab-host',
                    'user': 'adam',
                    'src_ip': '203.0.113.10',
                    'status': 'failure',
                    'message': 'real test event',
                    'raw_log': 'real test event',
                }
            )
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

    def test_limited_load_returns_most_recent_events_in_time_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            events = [
                Event.from_dict(
                    {
                        'id': f'evt-{index}',
                        'timestamp': f'2026-06-11T10:0{index}:00+00:00',
                        'source': 'edr',
                        'event_type': 'process_start',
                    }
                )
                for index in range(3)
            ]
            save_events(events, db)
            loaded = load_events(db, limit=2)
            self.assertEqual([event.id for event in loaded], ['evt-1', 'evt-2'])

    def test_triage_record_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'events.db'
            record = {
                'record_id': 'TRG-1',
                'alert_id': 'AL-1',
                'action': 'investigating',
                'analyst': 'soc-test',
                'note': 'validated',
                'created_at': '2026-06-11T10:00:00+00:00',
            }
            save_triage_record(record, db)
            loaded = load_triage_records(db, limit=10)
            self.assertEqual(loaded[0]['record_id'], 'TRG-1')
            self.assertEqual(loaded[0]['status'], 'recorded')


if __name__ == '__main__':
    unittest.main()
