import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.models import Alert, Event
from backend.storage import connect, init_db, load_alerts, load_events, save_ingest_batch


class IngestAtomicityTests(unittest.TestCase):
    def test_event_and_alert_writes_commit_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'atomic-ingest.db'
            event = Event(
                id='evt-atomic-001',
                timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=timezone.utc),
                source='unit-test-agent',
                event_type='process_start',
                asset='host-atomic-01',
                raw_log='atomic ingest fixture',
            )
            alert = Alert(
                alert_id='al-atomic-001',
                rule_id='DET-TEST-001',
                title='Atomic ingest fixture',
                severity='medium',
                confidence=0.9,
                tactic='Execution',
                technique='T1059',
                timestamp=event.timestamp,
                asset=event.asset,
                event_ids=[event.id],
            )

            saved_events, saved_alerts = save_ingest_batch([event], [alert], db_path)

            self.assertEqual((saved_events, saved_alerts), (1, 1))
            self.assertEqual([item.id for item in load_events(db_path)], [event.id])
            self.assertEqual([item.alert_id for item in load_alerts(db_path)], [alert.alert_id])

    def test_alert_failure_rolls_back_event_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'atomic-ingest-rollback.db'
            init_db(db_path)
            with connect(db_path) as conn:
                conn.execute(
                    """
                    CREATE TRIGGER fail_alert_insert
                    BEFORE INSERT ON alerts
                    BEGIN
                        SELECT RAISE(ABORT, 'forced alert failure');
                    END;
                    """
                )
                conn.commit()

            event = Event(
                id='evt-atomic-rollback-001',
                timestamp=datetime(2026, 9, 3, 1, 5, tzinfo=timezone.utc),
                source='unit-test-agent',
                event_type='process_start',
                asset='host-atomic-02',
                raw_log='atomic rollback fixture',
            )
            alert = Alert(
                alert_id='al-atomic-rollback-001',
                rule_id='DET-TEST-002',
                title='Atomic rollback fixture',
                severity='high',
                confidence=0.95,
                tactic='Execution',
                technique='T1059',
                timestamp=event.timestamp,
                asset=event.asset,
                event_ids=[event.id],
            )

            with self.assertRaises(sqlite3.IntegrityError):
                save_ingest_batch([event], [alert], db_path)

            self.assertEqual(load_events(db_path), [])
            self.assertEqual(load_alerts(db_path), [])


if __name__ == '__main__':
    unittest.main()
