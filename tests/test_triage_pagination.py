import tempfile
import unittest
from pathlib import Path

from backend.storage import init_db, save_triage, search_triage


class TriagePaginationTests(unittest.TestCase):
    def test_search_triage_paginates_in_sqlite_and_preserves_total(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'triage-pagination.db'
            init_db(db)
            for index in range(5):
                save_triage(
                    {
                        'alert_id': f'AL-{index}',
                        'action': 'reviewed',
                        'analyst': 'soc-user',
                        'status': 'recorded',
                        'request_id': f'req-{index}',
                        'created_at': f'2026-09-03T0{index}:00:00+00:00',
                    },
                    db,
                )

            page, total = search_triage(db, limit=2, offset=2)

            self.assertEqual(total, 5)
            self.assertEqual([item['alert_id'] for item in page], ['AL-2', 'AL-1'])


if __name__ == '__main__':
    unittest.main()
