import os
import unittest
from unittest.mock import patch

os.environ['AI_SIEM_API_KEY'] = 'test-token'
os.environ['AI_SIEM_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE'] = '1000'
os.environ['AI_SIEM_AUDIT_LOG'] = 'logs/test-ingest-body-audit.log'

from fastapi.testclient import TestClient

from backend import main as main_module


AUTH = {'Authorization': 'Bearer test-token', 'Content-Type': 'application/json'}


class IngestBodyLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main_module.app)

    def test_ingest_rejects_body_before_json_parsing_when_stream_exceeds_limit(self):
        payload = b'{"logs":["' + (b'A' * 100) + b'"]}'
        with patch.object(main_module, 'MAX_INGEST_BODY_BYTES', 64, create=True):
            response = self.client.post('/api/ingest', headers=AUTH, content=payload)

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.json()['detail'],
            'Maximum ingest request body size is 64 bytes',
        )


if __name__ == '__main__':
    unittest.main()
