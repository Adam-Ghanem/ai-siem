import unittest
from fastapi.testclient import TestClient

from backend.app.main import app

class ApiPlusTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_mitre_endpoint(self):
        response = self.client.get('/api/mitre')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn('configured_rule_count', body)
        self.assertGreaterEqual(body['configured_rule_count'], 8)

    def test_rule_detail_endpoint(self):
        response = self.client.get('/api/rules/DET-SSH-001')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['rule_id'], 'DET-SSH-001')

    def test_export_endpoint_contains_snapshot(self):
        response = self.client.get('/api/export')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn('summary', body)
        self.assertIn('alerts', body)
        self.assertIn('incidents', body)

    def test_filters_accept_src_ip(self):
        response = self.client.get('/api/events?src_ip=185.199.88.10')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(item.get('src_ip') == '185.199.88.10' for item in response.json()))

if __name__ == '__main__':
    unittest.main()
