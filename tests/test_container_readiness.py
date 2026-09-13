from pathlib import Path
import unittest


class ContainerReadinessTests(unittest.TestCase):
    def test_docker_healthcheck_uses_authenticated_readiness_probe(self):
        dockerfile = Path('Dockerfile').read_text(encoding='utf-8')
        healthcheck = next(
            line for line in dockerfile.splitlines() if line.startswith('HEALTHCHECK ')
        )

        self.assertIn('/api/ready', healthcheck)
        self.assertIn('Authorization', healthcheck)
        self.assertIn('AI_SIEM_API_KEY', healthcheck)


if __name__ == '__main__':
    unittest.main()
