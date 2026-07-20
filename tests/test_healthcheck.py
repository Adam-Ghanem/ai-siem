import unittest

import healthcheck


class HealthcheckSecurityTests(unittest.TestCase):
    def test_local_http_url_is_allowed(self):
        self.assertEqual(
            healthcheck.validate_api_url('http://127.0.0.1:8000/'),
            'http://127.0.0.1:8000',
        )

    def test_remote_http_and_credential_urls_are_rejected(self):
        invalid_urls = [
            'http://siem.example.test',
            'https://user:secret@siem.example.test',
            'https://siem.example.test/api',
            'https://siem.example.test?token=secret',
        ]
        for value in invalid_urls:
            with self.subTest(value=value), self.assertRaises(ValueError):
                healthcheck.validate_api_url(value)

    def test_redirect_handler_refuses_redirects(self):
        handler = healthcheck._NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(None, None, 302, 'Found', {}, 'https://other.test')
        )


if __name__ == '__main__':
    unittest.main()
