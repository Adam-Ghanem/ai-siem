import tempfile
import unittest
from pathlib import Path

from backend.correlation import correlate
from backend.incident_storage import load_incident, save_incidents, search_incidents
from tests.helpers import alert


class IncidentDurabilityTests(unittest.TestCase):
    def test_incident_snapshots_are_persisted_and_queryable_without_alert_recorrelation(self):
        incidents = correlate([alert(0), alert(1), alert(2)])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'incidents.db'
            saved = save_incidents(incidents, path=path)
            results, total = search_incidents(priority='P1', limit=10, path=path)
            loaded = load_incident(incidents[0].incident_id, path=path)

        self.assertEqual(saved, 1)
        self.assertEqual(total, 1)
        self.assertEqual([item.incident_id for item in results], [incidents[0].incident_id])
        self.assertEqual(loaded.to_dict(), incidents[0].to_dict())

    def test_incident_upsert_refreshes_snapshot_for_stable_incident_id(self):
        incident = correlate([alert(0), alert(1), alert(2)])[0]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'incidents.db'
            save_incidents([incident], path=path)
            incident.priority = 'P2'
            save_incidents([incident], path=path)
            loaded = load_incident(incident.incident_id, path=path)

        self.assertEqual(loaded.priority, 'P2')


if __name__ == '__main__':
    unittest.main()
