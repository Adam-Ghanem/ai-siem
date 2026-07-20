import re
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
        self.assertIn("api('/api/session')", source)
        self.assertIn("method: 'PATCH'", source)
        self.assertIn('canOperate()', source)
        self.assertIn("api('/api/notifications/status')", source)
        self.assertIn("requestJson('/api/notifications/test'", source)
        self.assertIn("api('/api/reports/summary')", source)
        self.assertIn("api('/api/readiness')", source)
        self.assertIn('/api/reports/export?format=', source)
        self.assertIn('without raw targets', source)
        self.assertNotIn('include_raw_targets=true', source)
        self.assertIn("requestJson('/api/hunt'", source)
        self.assertIn('Hunt capacity is busy.', source)
        self.assertIn("method: 'POST'", source)
        self.assertIn('canViewRawEvents()', source)
        self.assertIn("includes('read:raw-events')", source)
        self.assertNotIn('eval(', source)
        self.assertIn('canAdminister()', source)

    def test_every_static_id_selector_exists_in_the_dashboard(self):
        source = Path('frontend/app.js').read_text(encoding='utf-8')
        markup = Path('frontend/index.html').read_text(encoding='utf-8')
        selectors = set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", source))
        element_ids = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', markup))
        self.assertEqual(selectors - element_ids, set())


if __name__ == '__main__':
    unittest.main()
