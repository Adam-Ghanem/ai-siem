import os
from pathlib import Path
import unittest
from unittest.mock import patch

from backend.healthcheck import resolve_readiness_token


class ContainerReadinessTests(unittest.TestCase):
    def test_docker_healthcheck_uses_readiness_helper(self):
        dockerfile = Path('Dockerfile').read_text(encoding='utf-8')
        healthcheck = next(
            line for line in dockerfile.splitlines() if line.startswith('HEALTHCHECK ')
        )

        self.assertIn('python -m backend.healthcheck', healthcheck)

    def test_readiness_helper_prefers_legacy_api_key(self):
        with patch.dict(
            os.environ,
            {
                'AI_SIEM_API_KEY': 'legacy-token',
                'AI_SIEM_API_KEYS': '{"viewer-token":"viewer"}',
            },
            clear=False,
        ):
            self.assertEqual(resolve_readiness_token(), 'legacy-token')

    def test_readiness_helper_supports_rbac_api_keys(self):
        with patch.dict(
            os.environ,
            {
                'AI_SIEM_API_KEY': '',
                'AI_SIEM_API_KEYS': (
                    '{"ingest-token":"ingestor",'
                    '"viewer-token":{"role":"viewer","principal":"healthcheck"}}'
                ),
            },
            clear=False,
        ):
            self.assertEqual(resolve_readiness_token(), 'viewer-token')

    def test_readiness_helper_fails_without_read_capable_token(self):
        with patch.dict(
            os.environ,
            {
                'AI_SIEM_API_KEY': '',
                'AI_SIEM_API_KEYS': '{"ingest-token":"ingestor"}',
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, 'no read-capable readiness token'):
                resolve_readiness_token()


if __name__ == '__main__':
    unittest.main()
