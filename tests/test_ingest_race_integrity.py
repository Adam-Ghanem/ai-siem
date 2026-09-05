import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import main, storage
from backend.ingest_storage import IngestCommitRace, save_ingest_batch
from backend.models import Alert, Event
from backend.security import reset_rate_limit_state
from backend.storage import load_alerts, load_events, save_events

AUTH = {'Authorization': 'Bearer test-token'}


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

    def test_api_rechecks_deduplication_after_commit_race(self):
        reset_rate_limit_state()
        client = TestClient(main.app)
        event = {
            'id': 'evt-race-retry-001',
            'timestamp': '2026-09-05T15:05:00+00:00',
            'source': 'unit-test-agent',
            'event_type': 'process_start',
            'asset': 'host-race-retry-01',
            'raw_log': 'same collector retry telemetry',
        }

        with tempfile.TemporaryDirectory() as tmp:
            original_db_path = storage.DEFAULT_DB_PATH
            original_storage = main.AI_SIEM_STORAGE
            original_events = list(main.EVENTS)
            real_save_ingest_batch = save_ingest_batch
            first_attempt = True

            def race_once(events, alerts, path=None):
                nonlocal first_attempt
                events = list(events)
                alerts = list(alerts)
                if first_attempt:
                    first_attempt = False
                    self.assertEqual(storage.save_events(events, path), 1)
                    raise IngestCommitRace('simulated concurrent commit')
                return real_save_ingest_batch(events, alerts, path)

            try:
                storage.DEFAULT_DB_PATH = Path(tmp) / 'api-ingest-race.db'
                main.AI_SIEM_STORAGE = 'sqlite'
                main.EVENTS[:] = []
                with patch.object(main, 'save_ingest_batch', side_effect=race_once):
                    response = client.post('/api/ingest', json=event, headers=AUTH)

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['ingested'], 0)
                self.assertEqual(response.json()['duplicates_ignored'], 1)
                persisted = storage.load_events(limit=10)
                self.assertEqual(len(persisted), 1)
                self.assertEqual(persisted[0].raw_log, event['raw_log'])
            finally:
                main.EVENTS[:] = original_events
                main.AI_SIEM_STORAGE = original_storage
                storage.DEFAULT_DB_PATH = original_db_path


if __name__ == '__main__':
    unittest.main()
