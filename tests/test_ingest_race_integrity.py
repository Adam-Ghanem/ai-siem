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

    def test_exact_event_replay_after_race_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'ingest-replay.db'
            timestamp = datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
            event = Event(
                id='evt-replay-001',
                timestamp=timestamp,
                source='collector-a',
                event_type='process_start',
                asset='host-replay-01',
                raw_log='same authoritative telemetry',
            )
            derived_alert = Alert(
                alert_id='al-replay-001',
                rule_id='DET-TEST-REPLAY',
                title='Replay integrity fixture',
                severity='medium',
                confidence=0.8,
                tactic='Execution',
                technique='T1059',
                timestamp=timestamp,
                asset=event.asset,
                event_ids=[event.id],
            )

            # Simulate another ingest worker winning the event insert race.
            self.assertEqual(save_events([event], db_path), 1)

            saved_events, saved_alerts = save_ingest_batch(
                [event], [derived_alert], db_path
            )

            self.assertEqual(saved_events, 0)
            self.assertEqual(saved_alerts, 1)
            stored_events = load_events(db_path)
            self.assertEqual(len(stored_events), 1)
            self.assertEqual(stored_events[0].raw_log, event.raw_log)
            stored_alerts = load_alerts(db_path)
            self.assertEqual(len(stored_alerts), 1)
            self.assertEqual(stored_alerts[0].alert_id, derived_alert.alert_id)


if __name__ == '__main__':
    unittest.main()
