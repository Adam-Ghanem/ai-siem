import unittest

from backend import main


class HealthPrivacyTests(unittest.TestCase):
    def test_public_health_exposes_only_liveness_fields(self):
        self.assertEqual(
            main.health(),
            {
                'status': 'ok',
                'service': 'AI-SIEM',
            },
        )


if __name__ == '__main__':
    unittest.main()
