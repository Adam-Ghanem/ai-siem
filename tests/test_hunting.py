import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

import backend.hunting as hunting
import backend.security as security
from backend import main
from backend.hunting import HuntQuery, run_hunt
from tests.helpers import BASE, event


class HuntingTests(unittest.TestCase):
    def setUp(self):
        security.reset_rate_limit_state()

    def test_structured_hunt_filters_sorts_facets_and_paginates(self):
        events = [
            event(
                1,
                source='edr',
                event_type='process_start',
                asset='wkstn-01',
                user='alice',
                process_name='powershell.exe',
                command_line='powershell -NoProfile',
                status='success',
            ),
            event(
                2,
                source='edr',
                event_type='process_start',
                asset='wkstn-02',
                user='bob',
                process_name='powershell.exe',
                command_line='PowerShell -EncodedCommand test',
                status='success',
            ),
            event(3, source='firewall', event_type='connection'),
        ]
        query = HuntQuery.from_payload(
            {
                'q': 'powershell',
                'source': 'EDR',
                'sort': 'oldest',
                'offset': 1,
                'limit': 1,
            }
        )
        result = run_hunt(events, query)
        self.assertEqual(result['total_matches'], 2)
        self.assertEqual([item['id'] for item in result['events']], ['evt-2'])
        self.assertTrue(result['has_more'] is False)
        self.assertEqual(
            result['facets']['event_type'],
            [{'value': 'process_start', 'count': 2}],
        )
        self.assertEqual(result['time_bounds']['oldest_match'], BASE.replace(second=1).isoformat())

    def test_default_results_exclude_raw_log_and_raw_preview_is_bounded(self):
        target = event(
            4,
            message='indicator 198.51.100.9',
            raw_log='secret-prefix-' + ('x' * 5000),
        )
        safe = run_hunt([target], HuntQuery.from_payload({'q': '198.51.100.9'}))
        self.assertNotIn('raw_log', safe['events'][0])

        raw_only = run_hunt(
            [target],
            HuntQuery.from_payload({'q': 'secret-prefix'}),
        )
        self.assertEqual(raw_only['total_matches'], 0)

        raw = run_hunt(
            [target],
            HuntQuery.from_payload(
                {'q': 'secret-prefix', 'include_raw': True}
            ),
        )
        self.assertEqual(raw['total_matches'], 1)
        self.assertEqual(
            len(raw['events'][0]['raw_log']),
            hunting.MAX_RAW_PREVIEW_CHARS,
        )
        self.assertTrue(raw['events'][0]['raw_log_truncated'])

    def test_query_validation_rejects_executable_or_ambiguous_input(self):
        invalid_payloads = (
            {'regex': '.*'},
            {'q': 'line\nbreak'},
            {'limit': True},
            {'limit': 501},
            {'include_raw': 'yes'},
            {'sort': 'random'},
            {'sort': []},
            {'start_time': '2026-07-20T10:00:00'},
            {
                'start_time': '2026-07-21T10:00:00+00:00',
                'end_time': '2026-07-20T10:00:00+00:00',
            },
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    HuntQuery.from_payload(payload)

    def test_scan_scope_is_bounded_and_disclosed(self):
        events = [event(index) for index in range(5)]
        with patch.object(hunting, 'MAX_HUNT_SCAN_EVENTS', 2):
            result = run_hunt(events, HuntQuery.from_payload({}))
        self.assertEqual(result['scope']['available_events'], 5)
        self.assertEqual(result['scope']['scanned_events'], 2)
        self.assertTrue(result['scope']['scan_truncated'])
        self.assertEqual(
            [item['id'] for item in result['events']],
            ['evt-4', 'evt-3'],
        )

    def test_api_allows_safe_viewer_hunts_and_gates_raw_events(self):
        client = TestClient(main.app)
        with patch.multiple(
            security,
            API_KEY='',
            ADMIN_API_KEY='admin-hunt-key',
            OPERATOR_API_KEY='operator-hunt-key',
            VIEWER_API_KEY='viewer-hunt-key',
        ):
            viewer = {'Authorization': 'Bearer viewer-hunt-key'}
            operator = {'Authorization': 'Bearer operator-hunt-key'}
            response = client.post('/api/hunt', headers=viewer, json={'limit': 2})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('raw_log', response.json()['events'][0])
            self.assertEqual(
                client.post(
                    '/api/hunt',
                    headers=viewer,
                    json={'include_raw': True},
                ).status_code,
                403,
            )
            raw = client.post(
                '/api/hunt',
                headers=operator,
                json={'include_raw': True, 'limit': 1},
            )
            self.assertEqual(raw.status_code, 200)
            self.assertIn('raw_log', raw.json()['events'][0])
            self.assertIn(
                'read:raw-events',
                client.get('/api/session', headers=operator).json()['capabilities'],
            )

    def test_event_list_defaults_safe_and_requires_operator_for_raw(self):
        client = TestClient(main.app)
        target = event(90, raw_log='sensitive-' + ('z' * 5000))
        with patch.object(main, 'EVENTS', [target]), patch.multiple(
            security,
            API_KEY='',
            ADMIN_API_KEY='admin-event-key',
            OPERATOR_API_KEY='operator-event-key',
            VIEWER_API_KEY='viewer-event-key',
        ):
            viewer = {'Authorization': 'Bearer viewer-event-key'}
            operator = {'Authorization': 'Bearer operator-event-key'}
            safe = client.get('/api/events', headers=viewer)
            self.assertEqual(safe.status_code, 200)
            self.assertNotIn('raw_log', safe.json()[0])
            self.assertEqual(
                client.get(
                    '/api/events?include_raw=true', headers=viewer
                ).status_code,
                403,
            )
            raw = client.get(
                '/api/events?include_raw=true', headers=operator
            )
            self.assertEqual(raw.status_code, 200)
            self.assertEqual(
                len(raw.json()[0]['raw_log']),
                hunting.MAX_RAW_PREVIEW_CHARS,
            )
            self.assertTrue(raw.json()[0]['raw_log_truncated'])

    def test_hunt_capacity_gate_fails_fast_and_advertises_retry(self):
        client = TestClient(main.app)
        slot = threading.BoundedSemaphore(1)
        self.assertTrue(slot.acquire(blocking=False))
        with patch.object(main, '_HUNT_SLOTS', slot):
            response = client.post(
                '/api/hunt',
                headers={'Authorization': 'Bearer test-token'},
                json={'limit': 1},
            )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers['retry-after'], '1')
        slot.release()

    def test_hunt_terms_are_not_written_to_the_audit_log(self):
        client = TestClient(main.app)
        unique_term = 'customer-sensitive-hunt-term'
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / 'audit.log'
            with patch.object(security, 'AUDIT_LOG_PATH', audit_path):
                response = client.post(
                    '/api/hunt',
                    headers={'Authorization': 'Bearer test-token'},
                    json={'q': unique_term},
                )
            self.assertEqual(response.status_code, 200)
            audit = audit_path.read_text(encoding='utf-8')
        self.assertIn('action=threat_hunt', audit)
        self.assertNotIn(unique_term, audit)


if __name__ == '__main__':
    unittest.main()
