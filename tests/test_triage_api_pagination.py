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

AUTH = {'Authorization': 'Bearer test-token'}


class TriageApiPaginationTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        self.client = TestClient(main.app, raise_server_exceptions=False)

    def test_sqlite_triage_api_uses_native_page_and_true_total(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'triage-api-pagination.db'
            storage.init_db(db)
            for index in range(5):
                storage.save_triage(
                    {
                        'alert_id': f'AL-API-{index}',
                        'action': 'reviewed',
                        'analyst': 'soc-user',
                        'status': 'recorded',
                        'request_id': f'req-api-{index}',
                        'created_at': f'2026-09-03T0{index}:00:00+00:00',
                    },
                    db,
                )

            original_db_path = storage.DEFAULT_DB_PATH
            storage.DEFAULT_DB_PATH = db
            try:
                with patch.object(
                    main,
                    'load_triage',
                    side_effect=AssertionError('legacy triage materialization used'),
                ):
                    response = self.client.get(
                        '/api/triage',
                        params={'limit': 2, 'offset': 2},
                        headers=AUTH,
                    )
            finally:
                storage.DEFAULT_DB_PATH = original_db_path

            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                [item['alert_id'] for item in response.json()],
                ['AL-API-2', 'AL-API-1'],
            )
            self.assertEqual(response.headers['X-Total-Count'], '5')
            self.assertEqual(response.headers['X-Page-Limit'], '2')
            self.assertEqual(response.headers['X-Page-Offset'], '2')
            self.assertEqual(response.headers['X-Next-Offset'], '4')


if __name__ == '__main__':
    unittest.main()
