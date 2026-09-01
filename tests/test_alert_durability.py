import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import backend.main as main
import backend.storage as storage
from backend.models import Alert


class DurableAlertApiTests(unittest.TestCase):
    def test_alerts_include_persisted_history_after_hot_events_are_gone(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'durable-alerts.db'
            previous_path = storage.DEFAULT_DB_PATH
            previous_storage = main.AI_SIEM_STORAGE
            previous_events = list(main.EVENTS)
            try:
                storage.DEFAULT_DB_PATH = db
                main.AI_SIEM_STORAGE = 'sqlite'
                main.EVENTS[:] = []
                stored_alert = Alert(
                    alert_id='AL-HISTORY-1',
                    rule_id='DET-HISTORY-1',
                    title='Persisted detection',
                    severity='high',
                    confidence=0.94,
                    tactic='Credential Access',
                    technique='T1110',
                    timestamp=datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc),
                    asset='host-history',
                    user='adam',
                    src_ip='203.0.113.25',
                    event_ids=['evt-evicted-1'],
                    evidence=['historical evidence'],
                    recommended_action='Investigate.',
                )
                storage.save_alerts([stored_alert])

                result = main.alerts()

                self.assertEqual([alert.alert_id for alert in result], ['AL-HISTORY-1'])
            finally:
                main.EVENTS[:] = previous_events
                main.AI_SIEM_STORAGE = previous_storage
                storage.DEFAULT_DB_PATH = previous_path


if __name__ == '__main__':
    unittest.main()
