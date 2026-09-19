import tempfile
import unittest
from pathlib import Path

from backend.ingest_storage import IngestCommitRace, save_ingest_batch
from backend.models import Event
from backend.storage import connect


class IngestEventBatchDedupTests(unittest.TestCase):
    @staticmethod
    def _event(event_id: str, event_type: str = 'process_start') -> Event:
        return Event.from_dict(
            {
                'id': event_id,
                'timestamp': '2026-09-19T07:30:00Z',
                'source': 'test',
                'event_type': event_type,
                'asset': 'host-1',
            }
        )

    def test_exact_duplicate_event_inside_batch_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'duplicate-event.db'
            event = self._event('evt-duplicate-1')

            saved_events, saved_alerts = save_ingest_batch(
                [event, event], [], db
            )

            self.assertEqual((saved_events, saved_alerts), (1, 0))
            with connect(db) as conn:
                count = conn.execute(
                    'SELECT COUNT(*) FROM events WHERE id = ?', (event.id,)
                ).fetchone()[0]
            self.assertEqual(count, 1)

    def test_conflicting_event_ids_inside_batch_reject_before_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'conflicting-event.db'
            first = self._event('evt-conflict-1', 'process_start')
            second = self._event('evt-conflict-1', 'network_connection')

            with self.assertRaises(IngestCommitRace) as raised:
                save_ingest_batch([first, second], [], db)

            self.assertEqual(
                raised.exception.reason,
                'Conflicting event ID inside ingest batch',
            )
            self.assertFalse(db.exists())


if __name__ == '__main__':
    unittest.main()
