import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main, storage
from backend.security import reset_rate_limit_state
from backend.storage import save_events
from tests.helpers import event

AUTH = {'Authorization': 'Bearer test-token'}


class DurableMetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_sqlite_metrics_use_all_persisted_events_not_memory_window(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / 'metrics.db'
            persisted = [
                event(1, source='linux_auth', event_type='ssh_login'),
                event(2, source='firewall', event_type='network_connection'),
                event(3, source='firewall', event_type='network_connection'),
            ]
            with patch.object(storage, 'DEFAULT_DB_PATH', db_path):
                save_events(persisted)
                with patch.object(main, 'AI_SIEM_STORAGE', 'sqlite'), patch.object(
                    main, 'EVENTS', [persisted[-1]]
                ):
                    response = self.client.get('/api/metrics', headers=AUTH)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['total_events'], 3)
        self.assertEqual(body['source_distribution'], {'firewall': 2, 'linux_auth': 1})
        self.assertEqual(
            body['event_type_distribution'],
            {'network_connection': 2, 'ssh_login': 1},
        )


if __name__ == '__main__':
    unittest.main()
