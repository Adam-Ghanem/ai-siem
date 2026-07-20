import csv
import io
import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

import backend.security as security
from backend import main
from backend.reports import build_evidence_export, render_evidence_csv


class ReportTests(unittest.TestCase):
    def setUp(self):
        security.reset_rate_limit_state()

    @staticmethod
    def _bundle(include_raw_targets=False, title='Suspicious payroll-db activity'):
        alerts = [
            {
                'alert_id': 'AL-REPORT-1',
                'rule_id': 'DET-REPORT',
                'title': title,
                'severity': 'high',
                'status': 'investigating',
                'assigned_to': 'tier-one',
                'tactic': 'Credential Access',
                'technique': 'T1110',
                'timestamp': '2026-07-20T08:00:00+00:00',
                'asset': 'payroll-db.internal',
                'user': 'employee@example.test',
                'src_ip': '203.0.113.42',
                'recommended_action': 'Inspect payroll-db.internal',
                'occurrence_count': 3,
            }
        ]
        incidents = [
            {
                'incident_id': 'INC-REPORT-1',
                'title': 'Activity affecting payroll-db.internal',
                'priority': 'P2',
                'status': 'investigating',
                'assigned_to': 'tier-one',
                'related_alert_ids': ['AL-REPORT-1'],
                'related_assets': ['payroll-db.internal'],
                'related_users': ['employee@example.test'],
                'related_src_ips': ['203.0.113.42'],
                'evidence_summary': 'Observed 203.0.113.42 on payroll-db.internal',
                'recommended_actions': ['Validate payroll-db.internal'],
            }
        ]
        return build_evidence_export(
            alerts,
            incidents,
            {'total_events': 20, 'risk_score': 45, 'top_tactics': {}},
            {'open_alerts': 1, 'open_incidents': 1},
            include_raw_targets=include_raw_targets,
            limit=10,
        )

    def test_evidence_export_is_deidentified_by_default(self):
        encoded = json.dumps(self._bundle(), sort_keys=True)
        for raw_value in (
            'payroll-db.internal',
            'employee@example.test',
            '203.0.113.42',
        ):
            self.assertNotIn(raw_value, encoded)
        self.assertFalse(self._bundle()['privacy']['raw_targets_included'])

        raw = self._bundle(include_raw_targets=True)
        self.assertEqual(raw['alerts'][0]['src_ip'], '203.0.113.42')
        self.assertEqual(
            raw['incidents'][0]['related_assets'], ['payroll-db.internal']
        )

    def test_csv_export_prevents_spreadsheet_formula_execution(self):
        bundle = self._bundle(title='=HYPERLINK("https://example.test")')
        rendered = render_evidence_csv(bundle)
        row = next(csv.DictReader(io.StringIO(rendered)))
        self.assertTrue(row['title'].startswith("'="))

    def test_api_enforces_export_roles_and_raw_target_admin_gate(self):
        client = TestClient(main.app)
        with patch.multiple(
            security,
            API_KEY='',
            ADMIN_API_KEY='admin-secret',
            OPERATOR_API_KEY='operator-secret',
            VIEWER_API_KEY='viewer-secret',
        ):
            viewer = {'Authorization': 'Bearer viewer-secret'}
            operator = {'Authorization': 'Bearer operator-secret'}
            admin = {'Authorization': 'Bearer admin-secret'}

            summary = client.get('/api/reports/summary', headers=viewer)
            self.assertEqual(summary.status_code, 200)
            self.assertTrue(summary.json()['privacy']['aggregate_only'])
            self.assertEqual(
                client.get('/api/reports/export', headers=viewer).status_code,
                403,
            )

            exported = client.get('/api/reports/export', headers=operator)
            self.assertEqual(exported.status_code, 200)
            self.assertIn('attachment;', exported.headers['content-disposition'])
            self.assertFalse(exported.json()['privacy']['raw_targets_included'])
            self.assertEqual(
                client.get(
                    '/api/reports/export?include_raw_targets=true',
                    headers=operator,
                ).status_code,
                403,
            )

            raw = client.get(
                '/api/reports/export?include_raw_targets=true', headers=admin
            )
            self.assertEqual(raw.status_code, 200)
            self.assertTrue(raw.json()['privacy']['raw_targets_included'])
            csv_response = client.get(
                '/api/reports/export?format=csv', headers=operator
            )
            self.assertEqual(csv_response.status_code, 200)
            self.assertIn('text/csv', csv_response.headers['content-type'])

    def test_readiness_is_admin_only_and_never_exposes_keys(self):
        client = TestClient(main.app)
        with patch.multiple(
            security,
            API_KEY='',
            ADMIN_API_KEY='admin-secret',
            OPERATOR_API_KEY='operator-secret',
            VIEWER_API_KEY='viewer-secret',
        ):
            for token in ('viewer-secret', 'operator-secret'):
                response = client.get(
                    '/api/readiness',
                    headers={'Authorization': f'Bearer {token}'},
                )
                self.assertEqual(response.status_code, 403)
            response = client.get(
                '/api/readiness',
                headers={'Authorization': 'Bearer admin-secret'},
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()['ready'])
            for secret in ('admin-secret', 'operator-secret', 'viewer-secret'):
                self.assertNotIn(secret, response.text)
            credential_check = next(
                check
                for check in response.json()['checks']
                if check['name'] == 'credentials'
            )
            self.assertEqual(
                credential_check['detail']['configured_roles'],
                ['admin', 'operator', 'viewer'],
            )


if __name__ == '__main__':
    unittest.main()
