import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import main, storage
from backend.ingest_storage import save_ingest_batch
from backend.models import Alert, Event
from backend.security import reset_rate_limit_state
from backend.storage import connect, init_db, load_alerts, load_events

AUTH = {'Authorization': 'Bearer test-token'}


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

    def test_detection_failure_does_not_partially_persist_ingest(self):
        reset_rate_limit_state()
        client = TestClient(main.app)
        event = {
            'id': 'evt-api-atomic-001',
            'timestamp': '2026-09-03T01:10:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-api-atomic-01',
            'raw_log': 'api atomic ingest fixture',
        }

        with tempfile.TemporaryDirectory() as tmp:
            original_db_path = storage.DEFAULT_DB_PATH
            original_storage = main.AI_SIEM_STORAGE
            original_events = list(main.EVENTS)
            try:
                storage.DEFAULT_DB_PATH = Path(tmp) / 'api-atomic-ingest.db'
                main.AI_SIEM_STORAGE = 'sqlite'
                main.EVENTS[:] = []
                with patch.object(main, 'run_detections', side_effect=RuntimeError('forced detection failure')):
                    with self.assertRaises(RuntimeError):
                        client.post('/api/ingest', json=event, headers=AUTH)

                self.assertEqual(load_events(), [])
                self.assertEqual(main.EVENTS, [])
            finally:
                main.EVENTS[:] = original_events
                main.AI_SIEM_STORAGE = original_storage
                storage.DEFAULT_DB_PATH = original_db_path


if __name__ == '__main__':
    unittest.main()
