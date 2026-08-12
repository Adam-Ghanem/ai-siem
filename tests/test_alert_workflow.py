import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

from backend import main
from backend.models import Event
from backend.storage import load_alert_acknowledgements, load_analyst_notes, save_alert_acknowledgement, save_analyst_note


class AlertWorkflowStorageTests(unittest.TestCase):
    def test_acknowledgement_and_notes_survive_reopen_and_are_tenant_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'workflow.db')
            ack = save_alert_acknowledgement({'alert_id': 'a-1', 'tenant_id': 'tenant-a', 'principal_id': 'analyst-a', 'acknowledged': True, 'comment': 'confirmed'}, path)
            note = save_analyst_note({'alert_id': 'a-1', 'tenant_id': 'tenant-a', 'principal_id': 'analyst-a', 'analyst': 'adam', 'note': 'Evidence preserved'}, path)
            self.assertTrue(ack['acknowledged'])
            self.assertEqual(note['note_id'], 1)
            self.assertEqual(load_alert_acknowledgements(path=path, tenant_id='tenant-a')[0]['alert_id'], 'a-1')
            self.assertEqual(load_alert_acknowledgements(path=path, tenant_id='tenant-b'), [])
            self.assertEqual(load_analyst_notes('a-1', path=path, tenant_id='tenant-a')[0]['note'], 'Evidence preserved')
            self.assertEqual(load_analyst_notes('a-1', path=path, tenant_id='tenant-b'), [])


class AlertWorkflowApiTests(unittest.TestCase):
    def test_ack_and_note_api_are_persisted_and_bounded(self):
        client = TestClient(main.app)
        alert = main.alerts('default')[0]
        alert_id = alert.alert_id
        headers = {'Authorization': 'Bearer test-token'}
        with patch.object(main, 'AI_SIEM_STORAGE', 'memory'), patch.object(main, 'STORAGE') as storage:
            storage.load_alert_acknowledgements.return_value = []
            storage.load_analyst_notes.return_value = []
            storage.save_alert_acknowledgement.side_effect = lambda record: record
            storage.save_analyst_note.side_effect = lambda record: {**record, 'note_id': 'n-1'}
            ack = client.post(f'/api/alerts/{alert_id}/acknowledge', headers=headers, json={'acknowledged': True, 'comment': 'reviewed'})
            note = client.post(f'/api/alerts/{alert_id}/notes', headers=headers, json={'note': 'Evidence preserved', 'analyst': 'adam'})
        self.assertEqual(ack.status_code, 200)
        self.assertTrue(ack.json()['acknowledged'])
        self.assertEqual(note.status_code, 200)
        self.assertEqual(note.json()['note_id'], 'n-1')

    def test_newline_injection_and_wrong_ack_type_are_rejected(self):
        client = TestClient(main.app)
        alert_id = main.alerts('default')[0].alert_id
        headers = {'Authorization': 'Bearer test-token'}
        bad_ack = client.post(f'/api/alerts/{alert_id}/acknowledge', headers=headers, json={'acknowledged': 'yes'})
        bad_note = client.post(f'/api/alerts/{alert_id}/notes', headers=headers, json={'note': 'line 1\nline 2'})
        self.assertEqual(bad_ack.status_code, 400)
        self.assertEqual(bad_note.status_code, 400)

    def test_reader_cannot_write_acknowledgement(self):
        from backend import security
        old = security.PRINCIPALS
        try:
            security.PRINCIPALS = {'reader-token': security.AuthContext('reader', 'default', frozenset({'reader'}))}
            client = TestClient(main.app)
            alert_id = main.alerts('default')[0].alert_id
            response = client.post(f'/api/alerts/{alert_id}/acknowledge', headers={'Authorization': 'Bearer reader-token'}, json={'acknowledged': True})
        finally:
            security.PRINCIPALS = old
        self.assertEqual(response.status_code, 403)


if __name__ == '__main__':
    unittest.main()
