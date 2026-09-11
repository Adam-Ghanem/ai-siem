import tempfile
import unittest
from pathlib import Path

from backend import storage


class IncidentCaseHistoryTests(unittest.TestCase):
    def test_case_updates_append_history_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cases.db'
            storage.save_incident_case(
                {
                    'incident_id': 'INC-HISTORY',
                    'status': 'investigating',
                    'owner': 'alice',
                    'disposition': 'undetermined',
                    'note': 'Initial review',
                    'updated_by': 'alice',
                    'request_id': 'req-1',
                },
                path=path,
            )
            storage.save_incident_case(
                {
                    'incident_id': 'INC-HISTORY',
                    'status': 'contained',
                    'owner': 'bob',
                    'disposition': 'true_positive',
                    'note': 'Host isolated',
                    'updated_by': 'bob',
                    'request_id': 'req-2',
                },
                path=path,
            )

            history = storage.load_incident_case_history('INC-HISTORY', path=path)

        self.assertEqual([item['status'] for item in history], ['investigating', 'contained'])
        self.assertEqual([item['owner'] for item in history], ['alice', 'bob'])
        self.assertEqual([item['request_id'] for item in history], ['req-1', 'req-2'])

    def test_search_case_history_pages_in_database_and_returns_total(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cases.db'
            for index, status in enumerate(('open', 'investigating', 'contained'), start=1):
                storage.save_incident_case(
                    {
                        'incident_id': 'INC-PAGED',
                        'status': status,
                        'owner': f'analyst-{index}',
                        'disposition': 'undetermined',
                        'note': f'update-{index}',
                        'updated_by': f'analyst-{index}',
                        'request_id': f'req-{index}',
                    },
                    path=path,
                )

            history, total = storage.search_incident_case_history(
                'INC-PAGED',
                path=path,
                limit=1,
                offset=1,
            )

        self.assertEqual(total, 3)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['status'], 'investigating')
        self.assertEqual(history[0]['request_id'], 'req-2')


if __name__ == '__main__':
    unittest.main()
