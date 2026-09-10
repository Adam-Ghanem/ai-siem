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

            loader = getattr(storage, 'load_incident_case_history', lambda *_args, **_kwargs: [])
            history = loader('INC-HISTORY', path=path)

        self.assertEqual([item['status'] for item in history], ['investigating', 'contained'])
        self.assertEqual([item['owner'] for item in history], ['alice', 'bob'])
        self.assertEqual([item['request_id'] for item in history], ['req-1', 'req-2'])


if __name__ == '__main__':
    unittest.main()
