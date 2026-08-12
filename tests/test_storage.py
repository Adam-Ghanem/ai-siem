import tempfile
import unittest
from pathlib import Path

from backend.models import Event
from backend.storage import (
    init_db,
    load_events,
    load_triage,
    save_events,
    save_triage,
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
