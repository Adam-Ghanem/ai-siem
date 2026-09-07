import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.ingest_storage import IngestCommitRace, save_ingest_batch
from backend.models import Alert, Event
from backend.storage import connect, init_db


class IngestAlertAtomicityTests(unittest.TestCase):
    def test_conflicting_alert_ids_inside_batch_reject_before_event_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'atomic-ingest.db'
            init_db(db)
            event = Event.from_dict(
                {
                    'id': 'evt-atomic-alert-1',
                    'timestamp': '2026-09-07T18:01:00Z',
                    'source': 'test',
                    'event_type': 'process_start',
                }
            )
            first = Alert(
                alert_id='AL-COLLISION-1',
                rule_id='DET-FIRST',
                title='First detection',
                severity='high',
                confidence=0.9,
                tactic='Execution',
                technique='T1059',
                timestamp=datetime(2026, 9, 7, 18, 1, tzinfo=timezone.utc),
                event_ids=[event.id],
            )
            second = Alert(
                alert_id='AL-COLLISION-1',
                rule_id='DET-SECOND',
                title='Conflicting detection',
                severity='critical',
                confidence=0.99,
                tactic='Credential Access',
                technique='T1003',
                timestamp=datetime(2026, 9, 7, 18, 1, tzinfo=timezone.utc),
                event_ids=[event.id],
            )

            with self.assertRaises(IngestCommitRace):
                save_ingest_batch([event], [first, second], db)

            with connect(db) as conn:
                event_count = conn.execute(
                    'SELECT COUNT(*) FROM events WHERE id = ?', (event.id,)
                ).fetchone()[0]
                alert_count = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]

            self.assertEqual(event_count, 0)
            self.assertEqual(alert_count, 0)

    def test_exact_duplicate_alert_inside_batch_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'duplicate-alert.db'
            alert = Alert(
                alert_id='AL-DUPLICATE-1',
                rule_id='DET-DUPLICATE',
                title='Duplicate detection',
                severity='high',
                confidence=0.9,
                tactic='Execution',
                technique='T1059',
                timestamp=datetime(2026, 9, 7, 18, 2, tzinfo=timezone.utc),
            )

            saved_events, saved_alerts = save_ingest_batch([], [alert, alert], db)

            self.assertEqual(saved_events, 0)
            self.assertEqual(saved_alerts, 1)


if __name__ == '__main__':
    unittest.main()
