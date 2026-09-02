import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main
from backend.incident_storage import (
    incident_snapshots_dirty,
    mark_incident_snapshots_dirty,
    replace_incidents,
)
from backend.security import reset_rate_limit_state

AUTH = {'Authorization': 'Bearer test-token'}


class IncidentSnapshotReadPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()
        main.mark_incident_snapshots_dirty()

    def test_repeated_incident_reads_reuse_materialized_snapshots(self):
        with patch.object(main, 'correlate', wraps=main.correlate) as correlate_spy:
            first = self.client.get('/api/incidents', headers=AUTH)
            second = self.client.get('/api/incidents', headers=AUTH)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertGreater(len(first.json()), 0)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(correlate_spy.call_count, 1)

    def test_incident_filters_and_pagination_execute_on_snapshot_store(self):
        warm = self.client.get('/api/incidents', headers=AUTH)
        self.assertEqual(warm.status_code, 200)
        incident = warm.json()[0]

        response = self.client.get(
            '/api/incidents',
            params={
                'status': incident['status'],
                'priority': incident['priority'],
                'owner': incident['owner'],
                'limit': 1,
                'offset': 0,
            },
            headers=AUTH,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]['incident_id'], incident['incident_id'])
        self.assertGreaterEqual(int(response.headers['X-Total-Count']), 1)
        self.assertEqual(response.headers['X-Page-Limit'], '1')
        self.assertEqual(response.headers['X-Page-Offset'], '0')

    def test_empty_snapshot_set_can_be_fresh_without_recorrelation_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'incidents.db'
            mark_incident_snapshots_dirty(path)
            self.assertTrue(incident_snapshots_dirty(path))
            saved = replace_incidents([], path)
            self.assertEqual(saved, 0)
            self.assertFalse(incident_snapshots_dirty(path))

    def test_refresh_cannot_clear_dirty_signal_from_concurrent_update(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'incidents.db'
            mark_incident_snapshots_dirty(path)

            # First read starts/claims a refresh of the current dirty state.
            self.assertTrue(incident_snapshots_dirty(path))

            # Simulate telemetry or a case update arriving while correlation runs.
            mark_incident_snapshots_dirty(path)
            replace_incidents([], path)

            # The newer invalidation must survive the stale refresh completion.
            self.assertTrue(incident_snapshots_dirty(path))

            # A refresh claimed after that invalidation is allowed to mark fresh.
            replace_incidents([], path)
            self.assertFalse(incident_snapshots_dirty(path))


if __name__ == '__main__':
    unittest.main()
