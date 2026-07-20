import json
import os
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

import backend.notifications as notifications
import backend.security as security
from backend import main
from backend.notifications import (
    NotificationChannel,
    NotificationService,
    build_alert_payload,
    validate_notification_url,
)
from backend.operations import OperationsStore
from tests.helpers import alert


class _Response:
    def __init__(self, body=b'accepted', status=200):
        self.body = body
        self.status = status

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _Opener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        outcome = self.outcomes.pop(0) if self.outcomes else _Response()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class NotificationTests(unittest.TestCase):
    def setUp(self):
        security.reset_rate_limit_state()

    def _service(self, opener, **kwargs):
        return NotificationService(
            (
                NotificationChannel(
                    'webhook', 'https://hooks.example.test/alerts', True
                ),
            ),
            opener=opener,
            sleeper=lambda _: None,
            **kwargs,
        )

    def test_url_validation_rejects_unsafe_destinations(self):
        for value in (
            'http://hooks.example.test/alerts',
            'ftp://hooks.example.test/alerts',
            'https://user:secret@hooks.example.test/alerts',
            'https://hooks.example.test/alerts?token=secret',
            'https://hooks.example.test/alerts#fragment',
            'https://hooks.example.test/alerts\nInjected: value',
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_notification_url(value)
        self.assertEqual(
            validate_notification_url('https://hooks.example.test/alerts'),
            'https://hooks.example.test/alerts',
        )

    def test_redirect_handler_refuses_redirects(self):
        handler = notifications._NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                None,
                None,
                302,
                'Found',
                {'Location': 'https://other.example.test'},
                'https://other.example.test',
            )
        )

    def test_payload_is_deidentified_unless_explicitly_enabled(self):
        source = {
            'alert_id': 'AL-123',
            'rule_id': 'DET-1',
            'title': 'Suspicious activity from 203.0.113.42 on payroll-db.internal',
            'severity': 'high',
            'asset': 'payroll-db.internal',
            'hostname': 'payroll-db.internal',
            'src_ip': '203.0.113.42',
            'user': 'employee@example.test',
            'evidence': ['raw secret evidence'],
        }
        redacted = json.dumps(build_alert_payload(source), sort_keys=True)
        self.assertNotIn('203.0.113.42', redacted)
        self.assertNotIn('payroll-db.internal', redacted)
        self.assertNotIn('employee@example.test', redacted)
        self.assertNotIn('raw secret evidence', redacted)
        self.assertIn('targets_redacted', redacted)

        opted_in = build_alert_payload(source, include_raw_targets=True)
        self.assertEqual(opted_in['alert']['targets']['src_ip'], '203.0.113.42')
        self.assertEqual(
            opted_in['alert']['targets']['hostname'], 'payroll-db.internal'
        )

    def test_debounce_suppresses_duplicate_alert_delivery(self):
        current = [100.0]
        opener = _Opener([_Response(), _Response()])
        service = self._service(
            opener,
            clock=lambda: current[0],
            debounce_seconds=900,
        )
        payload = {'alert_id': 'AL-1', 'title': 'Alert', 'severity': 'high'}

        self.assertEqual(service.send_alert_notification(payload).delivered, 1)
        duplicate = service.send_alert_notification(payload)
        self.assertEqual(duplicate.skipped, 1)
        self.assertEqual(duplicate.channels[0].detail, 'debounced')
        self.assertEqual(len(opener.requests), 1)

        current[0] += 901
        self.assertEqual(service.send_alert_notification(payload).delivered, 1)
        self.assertEqual(len(opener.requests), 2)

    def test_circuit_breaker_stops_hammering_and_recovers(self):
        current = [50.0]
        opener = _Opener(
            [
                urllib.error.URLError('offline'),
                urllib.error.URLError('offline'),
                _Response(),
            ]
        )
        service = self._service(
            opener,
            clock=lambda: current[0],
            circuit_failure_threshold=2,
            circuit_reset_seconds=10,
        )
        payload = {'alert_id': 'AL-2', 'title': 'Alert', 'severity': 'high'}

        self.assertEqual(service.send_alert_notification(payload).failed, 1)
        blocked = service.send_alert_notification(payload)
        self.assertEqual(blocked.channels[0].detail, 'circuit_open')
        self.assertEqual(len(opener.requests), 2)

        current[0] += 11
        self.assertEqual(service.send_alert_notification(payload).delivered, 1)
        self.assertEqual(len(opener.requests), 3)

    def test_failure_is_bounded_and_does_not_break_alert_creation(self):
        failures = [urllib.error.URLError('offline')] * 4
        service = self._service(
            _Opener(failures),
            circuit_failure_threshold=10,
        )
        store = OperationsStore(
            persistent=False,
            notifier=lambda payload, reason: bool(
                service.send_alert_notification(payload, reason=reason).delivered
            ),
        )
        detected = alert(41, severity='high')

        self.assertEqual(store.sync_alerts([detected]), [detected.alert_id])
        self.assertEqual(store.alert_views([detected])[0]['status'], 'open')

    def test_sla_breach_is_recorded_and_notified_once(self):
        current = [datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)]
        dispatched = []
        store = OperationsStore(
            persistent=False,
            clock=lambda: current[0],
            notifier=lambda payload, reason: dispatched.append(reason) is None,
        )
        detected = alert(42, severity='high')
        store.sync_alerts([detected])
        current[0] += timedelta(minutes=61)

        self.assertTrue(store.alert_views([detected])[0]['sla_breached'])
        self.assertTrue(store.alert_views([detected])[0]['sla_breached'])
        self.assertEqual(dispatched, ['new_alert', 'sla_breach'])
        breaches = [
            record
            for record in store.history(object_id=detected.alert_id)
            if record['action'] == 'sla_breached'
        ]
        self.assertEqual(len(breaches), 1)

    def test_notification_endpoints_require_admin_and_hide_urls(self):
        client = TestClient(main.app)
        service = self._service(_Opener([_Response()]))
        with patch.multiple(
            security,
            API_KEY='',
            ADMIN_API_KEY='admin-secret',
            OPERATOR_API_KEY='operator-secret',
            VIEWER_API_KEY='viewer-secret',
        ), patch.object(notifications, 'SERVICE', service):
            for token in ('viewer-secret', 'operator-secret'):
                headers = {'Authorization': f'Bearer {token}'}
                self.assertEqual(
                    client.get('/api/notifications/status', headers=headers).status_code,
                    403,
                )
                self.assertEqual(
                    client.post('/api/notifications/test', headers=headers).status_code,
                    403,
                )

            headers = {'Authorization': 'Bearer admin-secret'}
            status = client.get('/api/notifications/status', headers=headers)
            self.assertEqual(status.status_code, 200)
            self.assertEqual(
                status.json()['channels'],
                [{'kind': 'webhook', 'enabled': True}],
            )
            self.assertNotIn('hooks.example.test', status.text)
            test_result = client.post('/api/notifications/test', headers=headers)
            self.assertEqual(test_result.status_code, 200)
            self.assertEqual(test_result.json()['delivered'], 1)
            self.assertNotIn('hooks.example.test', test_result.text)


if __name__ == '__main__':
    unittest.main()
