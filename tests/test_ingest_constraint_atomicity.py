import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.ingest_storage import IngestCommitRace, save_ingest_batch
from backend.models import Alert, Event
from backend.storage import connect, init_db, load_alerts, load_events


class IngestConstraintAtomicityTests(unittest.TestCase):
    def fixtures(self):
        event = Event(
            id='evt-constraint-001',
            timestamp=datetime(2026, 9, 3, tzinfo=timezone.utc),
            source='test-agent',
            event_type='process_start',
            raw_log='constraint regression',
        )
        alert = Alert(
            alert_id='al-constraint-001',
            rule_id='DET-TEST',
            title='Constraint regression',
            severity='medium',
            confidence=0.9,
            tactic='Execution',
            technique='T1059',
            timestamp=event.timestamp,
            event_ids=[event.id],
        )
        return event, alert

    def test_alert_not_null_failure_rolls_back_valid_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'constraints.db'
            event, alert = self.fixtures()
            alert.rule_id = None
            with self.assertRaises(sqlite3.IntegrityError):
                save_ingest_batch([event], [alert], db)
            self.assertEqual(load_events(db), [])
            self.assertEqual(load_alerts(db), [])

    def test_silently_ignored_alert_insert_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'ignored.db'
            init_db(db)
            with connect(db) as conn:
                conn.executescript("""
                    CREATE TRIGGER silently_ignore_alert
                    BEFORE INSERT ON alerts
                    BEGIN SELECT RAISE(IGNORE); END;
                """)
                conn.commit()
            event, alert = self.fixtures()
            with self.assertRaises(IngestCommitRace):
                save_ingest_batch([event], [alert], db)
            self.assertEqual(load_events(db), [])
            self.assertEqual(load_alerts(db), [])

    def test_event_not_null_failure_rolls_back_prior_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'event-constraints.db'
            event, _ = self.fixtures()
            invalid = Event(
                id='evt-constraint-invalid',
                timestamp=event.timestamp,
                source=None,
                event_type='process_start',
                raw_log='invalid fixture',
            )
            with self.assertRaises(sqlite3.IntegrityError):
                save_ingest_batch([event, invalid], [], db)
            self.assertEqual(load_events(db), [])

    def test_exact_id_replay_is_still_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'replay.db'
            event, alert = self.fixtures()
            self.assertEqual(save_ingest_batch([event], [alert], db), (1, 1))
            self.assertEqual(save_ingest_batch([event], [alert], db), (0, 0))
            self.assertEqual(len(load_events(db)), 1)
            self.assertEqual(len(load_alerts(db)), 1)


if __name__ == '__main__':
    unittest.main()
