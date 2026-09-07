import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.ingest_storage import IngestCommitRace, save_ingest_batch
from backend.models import Alert, Event
from backend.storage import connect, init_db


class IngestAlertAtomicityTests(unittest.TestCase):
    def test_alert_id_collision_rolls_back_the_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'atomic-ingest.db'
            init_db(db)
            existing_alert = Alert(
                alert_id='AL-COLLISION-1',
                rule_id='DET-EXISTING',
                title='Existing alert',
                severity='high',
                confidence=0.9,
                tactic='Execution',
                technique='T1059',
                timestamp=datetime(2026, 9, 7, 18, 0, tzinfo=timezone.utc),
            )
            with connect(db) as conn:
                conn.execute(
                    '''
                    INSERT INTO alerts
                    (alert_id, timestamp, rule_id, severity, tactic, asset, user, src_ip, alert_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        existing_alert.alert_id,
                        existing_alert.timestamp.isoformat(),
                        existing_alert.rule_id,
                        existing_alert.severity,
                        existing_alert.tactic,
                        None,
                        None,
                        None,
                        '{}',
                    ),
                )
                conn.commit()

            event = Event.from_dict(
                {
                    'id': 'evt-atomic-alert-1',
                    'timestamp': '2026-09-07T18:01:00Z',
                    'source': 'test',
                    'event_type': 'process_start',
                }
            )
            colliding_alert = Alert(
                alert_id=existing_alert.alert_id,
                rule_id='DET-NEW',
                title='New detection',
                severity='critical',
                confidence=0.99,
                tactic='Execution',
                technique='T1059',
                timestamp=event.timestamp,
                event_ids=[event.id],
            )

            with self.assertRaises(IngestCommitRace):
                save_ingest_batch([event], [colliding_alert], db)

            with connect(db) as conn:
                event_count = conn.execute(
                    'SELECT COUNT(*) FROM events WHERE id = ?', (event.id,)
                ).fetchone()[0]
                alert_count = conn.execute(
                    'SELECT COUNT(*) FROM alerts WHERE alert_id = ?',
                    (existing_alert.alert_id,),
                ).fetchone()[0]

            self.assertEqual(event_count, 0)
            self.assertEqual(alert_count, 1)


if __name__ == '__main__':
    unittest.main()
