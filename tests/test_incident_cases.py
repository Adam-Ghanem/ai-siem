import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from backend import main, security
from backend.security import reset_rate_limit_state
from backend.storage import load_incident_case, save_incident_case

AUTH = {'Authorization': 'Bearer test-token'}


class IncidentCaseStorageTests(unittest.TestCase):
    def test_incident_case_upsert_persists_latest_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cases.db'
            first = save_incident_case(
                {
                    'incident_id': 'INC-ABC123',
                    'status': 'investigating',
                    'owner': 'alice',
                    'disposition': 'undetermined',
                    'note': 'Initial review',
                    'updated_by': 'alice',
                    'request_id': 'req-1',
                },
                path=path,
            )
            second = save_incident_case(
                {
                    'incident_id': 'INC-ABC123',
                    'status': 'contained',
                    'owner': 'bob',
                    'disposition': 'true_positive',
                    'note': 'Host isolated',
                    'updated_by': 'bob',
                    'request_id': 'req-2',
                },
                path=path,
            )

            loaded = load_incident_case('INC-ABC123', path=path)

        self.assertEqual(first['incident_id'], 'INC-ABC123')
        self.assertEqual(second['status'], 'contained')
        self.assertEqual(loaded['owner'], 'bob')
        self.assertEqual(loaded['disposition'], 'true_positive')
        self.assertEqual(loaded['note'], 'Host isolated')
        self.assertEqual(loaded['request_id'], 'req-2')

    def test_incident_case_rejects_stale_expected_updated_at(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cases.db'
            first = save_incident_case(
                {
                    'incident_id': 'INC-ABC123',
                    'status': 'investigating',
                    'owner': 'alice',
                    'note': 'Initial review',
                },
                path=path,
            )
            save_incident_case(
                {
                    'incident_id': 'INC-ABC123',
                    'status': 'contained',
                    'owner': 'bob',
                    'note': 'Host isolated',
                },
                path=path,
                expected_updated_at=first['updated_at'],
            )

            with self.assertRaises(ValueError):
                save_incident_case(
                    {
                        'incident_id': 'INC-ABC123',
                        'status': 'resolved',
                        'owner': 'alice',
                        'note': 'Stale browser tab',
                    },
                    path=path,
                    expected_updated_at=first['updated_at'],
                )

            loaded = load_incident_case('INC-ABC123', path=path)

        self.assertEqual(loaded['status'], 'contained')
        self.assertEqual(loaded['owner'], 'bob')


class IncidentCaseApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        reset_rate_limit_state()

    def test_case_update_overlays_incident_workflow_state(self):
        incident = self.client.get('/api/incidents', headers=AUTH).json()[0]
        case_store = {}

        def fake_save(record):
            case_store[record['incident_id']] = dict(record)
            return dict(record)

        def fake_load(incident_id):
            value = case_store.get(incident_id)
            return dict(value) if value else None

        with patch.object(main, 'save_incident_case', side_effect=fake_save), patch.object(
            main, 'load_incident_case', side_effect=fake_load
        ):
            response = self.client.post(
                f"/api/incidents/{incident['incident_id']}/case",
                headers=AUTH,
                json={
                    'status': 'investigating',
                    'owner': 'soc-l2',
                    'disposition': 'undetermined',
                    'note': 'Escalated for endpoint review',
                },
            )
            self.assertEqual(response.status_code, 200)

            updated = self.client.get(
                f"/api/incidents/{incident['incident_id']}", headers=AUTH
            )

        self.assertEqual(updated.status_code, 200)
        body = updated.json()
        self.assertEqual(body['status'], 'investigating')
        self.assertEqual(body['owner'], 'soc-l2')
        self.assertEqual(body['case']['disposition'], 'undetermined')
        self.assertEqual(body['case']['note'], 'Escalated for endpoint review')

    def test_case_update_attributes_structured_identity_principal(self):
        incident = self.client.get('/api/incidents', headers=AUTH).json()[0]
        captured = {}
        identity_token = 'principal-test-token'
        identity = {'role': 'analyst', 'principal': 'alice@example.com'}

        def fake_save(record):
            captured.update(record)
            return dict(record)

        with patch.dict(security.API_KEYS, {identity_token: identity}, clear=True), patch.object(
            main, 'save_incident_case', side_effect=fake_save
        ), patch.object(main, 'load_incident_case', return_value=None):
            response = self.client.post(
                f"/api/incidents/{incident['incident_id']}/case",
                headers={'Authorization': f'Bearer {identity_token}'},
                json={'status': 'investigating'},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['updated_by'], 'alice@example.com')
        self.assertEqual(captured['updated_by'], 'alice@example.com')

    def test_case_update_rejects_invalid_status(self):
        incident = self.client.get('/api/incidents', headers=AUTH).json()[0]
        response = self.client.post(
            f"/api/incidents/{incident['incident_id']}/case",
            headers=AUTH,
            json={'status': 'definitely-not-valid'},
        )
        self.assertEqual(response.status_code, 400)

    def test_case_update_returns_conflict_for_stale_version(self):
        incident = self.client.get('/api/incidents', headers=AUTH).json()[0]
        current_case = {
            'incident_id': incident['incident_id'],
            'status': 'investigating',
            'owner': 'alice',
            'disposition': 'undetermined',
            'note': 'Initial review',
            'updated_at': '2026-09-06T01:00:00+00:00',
        }

        def fake_save(record, *, expected_updated_at=None):
            if expected_updated_at == '2026-09-06T00:59:00+00:00':
                raise ValueError('Incident case was modified by another request')
            return dict(record)

        with patch.object(main, 'load_incident_case', return_value=current_case), patch.object(
            main, 'save_incident_case', side_effect=fake_save
        ):
            response = self.client.post(
                f"/api/incidents/{incident['incident_id']}/case",
                headers=AUTH,
                json={
                    'status': 'contained',
                    'expected_updated_at': '2026-09-06T00:59:00+00:00',
                },
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['detail'], 'Incident case was modified by another request')


if __name__ == '__main__':
    unittest.main()
