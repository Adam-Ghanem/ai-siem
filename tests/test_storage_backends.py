import os
import unittest
from unittest.mock import patch

from backend.models import Event
from backend.storage_backends import MemoryBackend, OpenSearchBackend, build_storage_backend


class StorageBackendOptionTests(unittest.TestCase):
    def test_memory_backend_round_trip_is_tenant_scoped(self):
        backend = MemoryBackend()
        event_a = Event('same-id', __import__('datetime').datetime.now(__import__('datetime').timezone.utc), 'test', 'test', tenant_id='tenant-a')
        event_b = Event('same-id', __import__('datetime').datetime.now(__import__('datetime').timezone.utc), 'test', 'test', tenant_id='tenant-b')
        backend.save_events([event_a, event_b])
        self.assertEqual(len(backend.load_events(tenant_id='tenant-a')), 1)
        self.assertEqual(len(backend.load_events(tenant_id='tenant-b')), 1)
        backend.save_ingest_batch({'batch_id': 'b-a', 'tenant_id': 'tenant-a', 'status': 'accepted'})
        backend.save_triage({'alert_id': 'a-1', 'action': 'review', 'tenant_id': 'tenant-a'})
        stats = backend.stats('tenant-a')
        self.assertEqual(stats['stored_events'], 1)
        self.assertEqual(stats['stored_ingest_batches'], 1)
        self.assertEqual(stats['stored_triage_records'], 1)

    def test_unknown_backend_fails_closed(self):
        with self.assertRaises(RuntimeError):
            build_storage_backend('unknown')

    def test_postgres_missing_optional_dependency_or_dsn_fails_closed(self):
        with patch.dict(os.environ, {'AI_SIEM_POSTGRES_DSN': ''}, clear=False):
            with self.assertRaises(RuntimeError):
                build_storage_backend('postgres')

    def test_opensearch_missing_optional_dependency_or_url_fails_closed(self):
        with patch.dict(os.environ, {'AI_SIEM_OPENSEARCH_URL': ''}, clear=False):
            with self.assertRaises(RuntimeError):
                build_storage_backend('opensearch')

    def test_opensearch_uses_fixed_index_names(self):
        self.assertEqual(OpenSearchBackend.EVENTS_INDEX, 'ai-siem-events')
        self.assertEqual(OpenSearchBackend.TRIAGE_INDEX, 'ai-siem-triage')
        self.assertEqual(OpenSearchBackend.BATCHES_INDEX, 'ai-siem-batches')


if __name__ == '__main__':
    unittest.main()
