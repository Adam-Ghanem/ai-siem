import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.ingest_storage import save_ingest_batch
from backend.models import Alert, Event
from backend.storage import load_alerts, load_events, save_events


class IngestRaceIntegrityTests(unittest.TestCase):
    def test_storage_rejects_event_id_that_appears_before_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'ingest-race.db'
            timestamp = datetime(2026, 9, 5, 15, 0, tzinfo=timezone.utc)
            persisted = Event(
                id='evt-race-001',
                timestamp=timestamp,
                source='collector-a',
                event_type='process_start',
                asset='host-race-01',
                raw_log='authoritative telemetry',
            )
            racing = Event(
                id='evt-race-001',
                timestamp=timestamp,
                source='collector-b',
                event_type='process_start',
                asset='host-race-01',
                raw_log='conflicting telemetry',
            )
            derived_alert = Alert(
                alert_id='al-race-001',
                rule_id='DET-TEST-RACE',
                title='Race integrity fixture',
                severity='high',
                confidence=0.95,
                tactic='Execution',
                technique='T1059',
                timestamp=timestamp,
                asset=racing.asset,
                event_ids=[racing.id],
            )

            self.assertEqual(save_events([persisted], db_path), 1)

            with self.assertRaises(ValueError):
                save_ingest_batch([racing], [derived_alert], db_path)

            stored = load_events(db_path)
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].raw_log, 'authoritative telemetry')
            self.assertEqual(load_alerts(db_path), [])


if __name__ == '__main__':
    unittest.main()
