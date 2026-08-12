import os
import unittest

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

from backend import main
import backend.security as security
from backend.security import AuthContext, reset_rate_limit_state


class MultiTenancyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.original_principals = security.PRINCIPALS.copy()
        security.PRINCIPALS = {
            'tenant-a-token': AuthContext('analyst-a', 'tenant-a', frozenset({'analyst', 'ingestor'})),
            'tenant-b-token': AuthContext('analyst-b', 'tenant-b', frozenset({'analyst', 'ingestor'})),
            'reader-token': AuthContext('reader-a', 'tenant-a', frozenset({'reader'})),
        }

    @classmethod
    def tearDownClass(cls):
        security.PRINCIPALS = cls.original_principals

    def setUp(self):
        reset_rate_limit_state()

    @staticmethod
    def auth(token):
        return {'Authorization': f'Bearer {token}'}

    def test_me_exposes_authenticated_principal_and_tenant(self):
        response = self.client.get('/api/me', headers=self.auth('tenant-a-token'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['principal_id'], 'analyst-a')
        self.assertEqual(response.json()['tenant_id'], 'tenant-a')
        self.assertEqual(response.json()['roles'], ['analyst', 'ingestor'])

    def test_events_are_isolated_between_tenants(self):
        event_a = {
            'id': 'shared-event-id',
            'source': 'tenant-a-source',
            'event_type': 'auth_success',
            'asset': 'tenant-a-host',
        }
        event_b = {
            'id': 'shared-event-id',
            'source': 'tenant-b-source',
            'event_type': 'auth_success',
            'asset': 'tenant-b-host',
        }
        self.assertEqual(self.client.post('/api/ingest', headers=self.auth('tenant-a-token'), json=event_a).status_code, 200)
        self.assertEqual(self.client.post('/api/ingest', headers=self.auth('tenant-b-token'), json=event_b).status_code, 200)

        events_a = self.client.get('/api/events?limit=1000', headers=self.auth('tenant-a-token')).json()
        events_b = self.client.get('/api/events?limit=1000', headers=self.auth('tenant-b-token')).json()
        self.assertTrue(any(event['asset'] == 'tenant-a-host' for event in events_a))
        self.assertFalse(any(event['asset'] == 'tenant-b-host' for event in events_a))
        self.assertTrue(any(event['asset'] == 'tenant-b-host' for event in events_b))
        self.assertFalse(any(event['asset'] == 'tenant-a-host' for event in events_b))

    def test_reader_can_read_but_cannot_ingest_or_triage(self):
        events = self.client.get('/api/events?limit=1', headers=self.auth('reader-token'))
        self.assertEqual(events.status_code, 200)
        ingest = self.client.post(
            '/api/ingest',
            headers=self.auth('reader-token'),
            json={'source': 'reader', 'event_type': 'test'},
        )
        self.assertEqual(ingest.status_code, 403)
        triage = self.client.post(
            '/api/triage',
            headers=self.auth('reader-token'),
            json={'alert_id': 'AL-reader', 'action': 'reviewed'},
        )
        self.assertEqual(triage.status_code, 403)

    def test_ingest_returns_batch_and_history_is_tenant_scoped(self):
        response = self.client.post(
            '/api/ingest',
            headers=self.auth('tenant-a-token'),
            json={'source': 'tenant-a-ingest', 'event_type': 'test'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['batch_id'])
        batches_a = self.client.get('/api/ingest/batches?limit=1000', headers=self.auth('tenant-a-token')).json()
        batches_b = self.client.get('/api/ingest/batches?limit=1000', headers=self.auth('tenant-b-token')).json()
        self.assertTrue(any(item['batch_id'] == response.json()['batch_id'] for item in batches_a))
        self.assertFalse(any(item['batch_id'] == response.json()['batch_id'] for item in batches_b))
        self.assertEqual(batches_a[0]['tenant_id'], 'tenant-a')
        self.assertEqual(batches_a[0]['status'], 'accepted')

    def test_triage_records_authenticated_tenant_and_principal(self):
        response = self.client.post(
            '/api/triage',
            headers=self.auth('tenant-a-token'),
            json={'alert_id': 'AL-tenant-a', 'action': 'reviewed'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['tenant_id'], 'tenant-a')
        self.assertEqual(response.json()['principal_id'], 'analyst-a')
        triage_a = self.client.get('/api/triage?limit=1000', headers=self.auth('tenant-a-token')).json()
        triage_b = self.client.get('/api/triage?limit=1000', headers=self.auth('tenant-b-token')).json()
        self.assertTrue(any(item['alert_id'] == 'AL-tenant-a' for item in triage_a))
        self.assertFalse(any(item['alert_id'] == 'AL-tenant-a' for item in triage_b))


if __name__ == '__main__':
    unittest.main()
