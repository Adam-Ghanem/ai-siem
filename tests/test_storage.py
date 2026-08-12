import tempfile
import unittest
from pathlib import Path

from backend.models import Event
from backend.storage import (
    init_db,
    load_events,
    load_ingest_batches,
    load_triage,
    save_events,
    save_ingest_batch,
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

    def test_same_event_id_is_namespaced_per_tenant(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'multi-tenant.db'
            init_db(db)
            event_a = Event.from_dict({
                'id': 'same-id',
                'source': 'tenant-a',
                'event_type': 'test',
                'tenant_id': 'tenant-a',
            })
            event_b = Event.from_dict({
                'id': 'same-id',
                'source': 'tenant-b',
                'event_type': 'test',
                'tenant_id': 'tenant-b',
            })
            self.assertEqual(save_events([event_a, event_b], db), 2)
            self.assertEqual(len(load_events(db, tenant_id='tenant-a')), 1)
            self.assertEqual(len(load_events(db, tenant_id='tenant-b')), 1)
            self.assertEqual(load_events(db, tenant_id='tenant-a')[0].id, 'tenant-a:same-id')
            self.assertEqual(load_events(db, tenant_id='tenant-b')[0].id, 'tenant-b:same-id')

    def test_ingest_batch_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'batches.db'
            init_db(db)
            saved = save_ingest_batch({
                'batch_id': 'batch-1',
                'tenant_id': 'tenant-a',
                'principal_id': 'soc-a',
                'item_count': 3,
                'accepted_count': 2,
                'rejected_count': 1,
                'unknown_count': 1,
                'status': 'accepted_with_unknowns',
                'error': None,
            }, db)
            self.assertEqual(saved['tenant_id'], 'tenant-a')
            batches = load_ingest_batches(db, tenant_id='tenant-a')
            self.assertEqual(len(batches), 1)
            self.assertEqual(batches[0]['status'], 'accepted_with_unknowns')
            self.assertEqual(stats(db, tenant_id='tenant-a')['stored_ingest_batches'], 1)

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
