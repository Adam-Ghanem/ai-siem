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

    def test_existing_conflicting_alert_id_rolls_back_new_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'existing-alert-collision.db'
            existing = Alert(
                alert_id='AL-PERSISTED-COLLISION-1',
                rule_id='DET-ORIGINAL',
                title='Original detection',
                severity='medium',
                confidence=0.7,
                tactic='Discovery',
                technique='T1087',
                timestamp=datetime(2026, 9, 9, 1, 0, tzinfo=timezone.utc),
            )
            save_ingest_batch([], [existing], db)

            event = Event.from_dict(
                {
                    'id': 'evt-existing-alert-collision-1',
                    'timestamp': '2026-09-09T01:01:00Z',
                    'source': 'test',
                    'event_type': 'process_start',
                }
            )
            conflicting = Alert(
                alert_id=existing.alert_id,
                rule_id='DET-CHANGED',
                title='Changed detection',
                severity='critical',
                confidence=0.99,
                tactic='Credential Access',
                technique='T1003',
                timestamp=datetime(2026, 9, 9, 1, 1, tzinfo=timezone.utc),
                event_ids=[event.id],
            )

            with self.assertRaises(IngestCommitRace):
                save_ingest_batch([event], [conflicting], db)

            with connect(db) as conn:
                event_count = conn.execute(
                    'SELECT COUNT(*) FROM events WHERE id = ?', (event.id,)
                ).fetchone()[0]
                persisted = conn.execute(
                    'SELECT rule_id, alert_json FROM alerts WHERE alert_id = ?',
                    (existing.alert_id,),
                ).fetchone()

            self.assertEqual(event_count, 0)
            self.assertEqual(persisted[0], 'DET-ORIGINAL')
            self.assertIn('Original detection', persisted[1])

    def test_existing_exact_alert_replay_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'existing-alert-replay.db'
            alert = Alert(
                alert_id='AL-PERSISTED-REPLAY-1',
                rule_id='DET-REPLAY',
                title='Replay-safe detection',
                severity='high',
                confidence=0.9,
                tactic='Execution',
                technique='T1059',
                timestamp=datetime(2026, 9, 9, 1, 2, tzinfo=timezone.utc),
            )
            first = save_ingest_batch([], [alert], db)
            second = save_ingest_batch([], [alert], db)

            self.assertEqual(first, (0, 1))
            self.assertEqual(second, (0, 0))

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
