import os
import unittest

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

from backend import main
from backend.sigma import MAX_SIGMA_DOCUMENT_BYTES, SigmaRuleError, export_sigma, import_sigma


SIGMA_RULE = '''
title: Windows suspicious PowerShell
id: 11111111-1111-4111-8111-111111111111
status: stable
description: Detects a PowerShell execution marker.
logsource:
  product: windows
detection:
  selection:
    EventID: 4104
    ScriptBlockText: '*FromBase64String*'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
x_ai_siem:
  confidence: 0.91
  field_equals:
    event_type: powershell_execution
  contains:
    command_line:
      - FromBase64String
  threshold: 1
  time_window_minutes: 5
  group_by:
    - asset
'''


class SigmaTests(unittest.TestCase):
    def test_import_export_round_trip_preserves_detection_contract(self):
        imported = import_sigma(SIGMA_RULE)
        self.assertEqual(len(imported), 1)
        rule = imported[0]
        self.assertEqual(rule['severity'], 'high')
        self.assertEqual(rule['tactic'], 'Execution')
        self.assertEqual(rule['technique'], 'T1059.001')
        self.assertEqual(rule['field_equals']['event_type'], 'powershell_execution')
        self.assertEqual(rule['confidence'], 0.91)

        exported = export_sigma(imported)
        round_trip = import_sigma(exported)
        self.assertEqual(round_trip[0]['sigma_id'], rule['sigma_id'])
        self.assertEqual(round_trip[0]['field_equals'], rule['field_equals'])
        self.assertEqual(round_trip[0]['contains'], rule['contains'])

    def test_unsafe_yaml_tag_is_rejected(self):
        with self.assertRaises(SigmaRuleError):
            import_sigma('!!python/object:__main__.Anything {}')

    def test_malformed_yaml_is_rejected(self):
        with self.assertRaises(SigmaRuleError):
            import_sigma('title: [unterminated')

    def test_oversized_document_is_rejected(self):
        with self.assertRaises(SigmaRuleError):
            import_sigma('x' * (MAX_SIGMA_DOCUMENT_BYTES + 1))

    def test_api_exports_yaml_and_imports_new_rule(self):
        client = TestClient(main.app)
        headers = {
            'Authorization': 'Bearer test-token',
            'Content-Type': 'application/yaml',
        }
        export_response = client.get('/api/rules/sigma', headers=headers)
        self.assertEqual(export_response.status_code, 200)
        self.assertIn('application/yaml', export_response.headers['content-type'])
        import_response = client.post('/api/rules/sigma/import', headers=headers, content=SIGMA_RULE)
        self.assertEqual(import_response.status_code, 200)
        self.assertEqual(import_response.json()['imported'], 1)
        duplicate = client.post('/api/rules/sigma/import', headers=headers, content=SIGMA_RULE)
        self.assertEqual(duplicate.status_code, 409)


if __name__ == '__main__':
    unittest.main()
