import os
import unittest
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

import backend.security as security
from backend import main
from backend.security import reset_rate_limit_state


class RoleAccessTests(unittest.TestCase):
    def setUp(self):
        reset_rate_limit_state()
        self.client = TestClient(main.app)

    def _roles(self):
        return patch.multiple(
            security,
            API_KEY='',
            ADMIN_API_KEY='admin-secret',
            OPERATOR_API_KEY='operator-secret',
            VIEWER_API_KEY='viewer-secret',
        )

    def test_viewer_can_read_but_cannot_mutate(self):
        headers = {'Authorization': 'Bearer viewer-secret'}
        with self._roles():
            session = self.client.get('/api/session', headers=headers)
            self.assertEqual(session.status_code, 200)
            self.assertEqual(session.json()['role'], 'viewer')
            self.assertEqual(
                self.client.get('/api/alerts', headers=headers).status_code,
                200,
            )
            self.assertEqual(
                self.client.post(
                    '/api/ingest', headers=headers, json={'logs': []}
                ).status_code,
                403,
            )
            self.assertEqual(
                self.client.get('/api/parser/stats', headers=headers).status_code,
                403,
            )

    def test_operator_can_assign_alert_but_not_read_admin_diagnostics(self):
        headers = {'Authorization': 'Bearer operator-secret'}
        with self._roles():
            alert_id = self.client.get('/api/alerts', headers=headers).json()[0][
                'alert_id'
            ]
            response = self.client.patch(
                f'/api/alerts/{alert_id}',
                headers=headers,
                json={'assigned_to': 'tier-one'},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['assigned_to'], 'tier-one')
            spoofed = self.client.patch(
                f'/api/alerts/{alert_id}',
                headers=headers,
                json={'assigned_to': 'tier-two', 'actor': 'admin'},
            )
            self.assertEqual(spoofed.status_code, 400)
            history = self.client.get(
                '/api/operations/history',
                headers=headers,
                params={'object_id': alert_id},
            ).json()
            self.assertEqual(history[0]['actor'], 'operator-session')
            self.assertEqual(
                self.client.get('/api/storage/stats', headers=headers).status_code,
                403,
            )

    def test_admin_can_access_diagnostics(self):
        headers = {'Authorization': 'Bearer admin-secret'}
        with self._roles():
            self.assertEqual(
                self.client.get('/api/parser/stats', headers=headers).status_code,
                200,
            )
            self.assertEqual(
                self.client.get('/api/storage/stats', headers=headers).status_code,
                200,
            )


if __name__ == '__main__':
    unittest.main()
