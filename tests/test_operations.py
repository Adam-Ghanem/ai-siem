import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.correlation import correlate
from backend.operations import OperationsStore
from tests.helpers import alert


class OperationsStoreTests(unittest.TestCase):
    def test_memory_alert_lifecycle_and_sla(self):
        current = [datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)]
        store = OperationsStore(persistent=False, clock=lambda: current[0])
        detected = alert(1, severity='high')

        self.assertEqual(store.sync_alerts([detected]), ['AL-1'])
        self.assertEqual(store.sync_alerts([detected]), [])
        initial = store.alert_views([detected])[0]
        self.assertEqual(initial['status'], 'open')
        self.assertEqual(initial['assigned_to'], 'unassigned')
        self.assertFalse(initial['sla_breached'])

        updated = store.update_alert(
            'AL-1',
            status='investigating',
            assigned_to='adam',
            resolution_note=None,
            actor='adam',
        )
        self.assertEqual(updated['status'], 'investigating')
        self.assertEqual(updated['assigned_to'], 'adam')

        with self.assertRaisesRegex(ValueError, 'resolution_note'):
            store.update_alert(
                'AL-1',
                status='resolved',
                assigned_to=None,
                resolution_note=None,
                actor='adam',
            )

        current[0] += timedelta(minutes=61)
        self.assertTrue(store.alert_views([detected])[0]['sla_breached'])
        self.assertGreaterEqual(len(store.history(object_id='AL-1')), 2)

    def test_sqlite_incident_state_survives_store_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'operations.db'
            now = datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)
            incident = correlate([alert(3)])[0]
            store = OperationsStore(
                persistent=True,
                path=path,
                clock=lambda: now,
            )
            store.sync_incidents([incident])
            store.update_incident(
                incident.incident_id,
                status='investigating',
                assigned_to='soc-one',
                resolution_note='Validation in progress',
                actor='soc-one',
            )

            restarted = OperationsStore(
                persistent=True,
                path=path,
                clock=lambda: now,
            )
            view = restarted.incident_views([incident])[0]
            self.assertEqual(view['status'], 'investigating')
            self.assertEqual(view['owner'], 'soc-one')
            self.assertTrue(
                any(
                    entry['action'] == 'status:open->investigating'
                    for entry in restarted.history(object_id=incident.incident_id)
                )
            )


if __name__ == '__main__':
    unittest.main()
