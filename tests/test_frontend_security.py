import unittest
from pathlib import Path


class FrontendSecurityTests(unittest.TestCase):
    def test_dashboard_escapes_api_data_and_uses_tab_scoped_key_storage(self):
        source = Path('frontend/app.js').read_text(encoding='utf-8')
        self.assertIn('escapeHtml', source)
        self.assertIn('sessionStorage', source)
        self.assertNotIn('localStorage', source)
        self.assertNotIn('Math.random', source)
        self.assertNotIn('bar.style.height', source)


if __name__ == '__main__':
    unittest.main()
