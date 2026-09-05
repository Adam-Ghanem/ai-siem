import unittest

from starlette.requests import Request

import backend.security as security


def make_request(client_ip: str, forwarded_for: str | None = None) -> Request:
    headers = []
    if forwarded_for is not None:
        headers.append((b'x-forwarded-for', forwarded_for.encode('utf-8')))
    return Request(
        {
            'type': 'http',
            'method': 'GET',
            'path': '/api/events',
            'headers': headers,
            'client': (client_ip, 12345),
            'scheme': 'http',
            'server': ('testserver', 80),
            'query_string': b'',
        }
    )


class TrustedProxyClientIpTests(unittest.TestCase):
    def setUp(self):
        self.original_trust_proxy_headers = security.TRUST_PROXY_HEADERS
        self.original_trusted_proxy_networks = security.TRUSTED_PROXY_NETWORKS
        security.TRUST_PROXY_HEADERS = True
        security.TRUSTED_PROXY_NETWORKS = security._load_trusted_proxy_networks('10.0.0.0/8')

    def tearDown(self):
        security.TRUST_PROXY_HEADERS = self.original_trust_proxy_headers
        security.TRUSTED_PROXY_NETWORKS = self.original_trusted_proxy_networks

    def test_untrusted_direct_client_cannot_spoof_x_forwarded_for(self):
        request = make_request('203.0.113.10', '198.51.100.25')
        self.assertEqual(security.client_ip(request), '203.0.113.10')

    def test_trusted_proxy_can_supply_x_forwarded_for(self):
        request = make_request('10.1.2.3', '198.51.100.25')
        self.assertEqual(security.client_ip(request), '198.51.100.25')


if __name__ == '__main__':
    unittest.main()
