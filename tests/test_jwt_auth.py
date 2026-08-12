import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from unittest.mock import patch

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')
os.environ.setdefault('AI_SIEM_INGEST_RATE_LIMIT_PER_MINUTE', '1000')

from fastapi.testclient import TestClient

from backend import main, security
from backend.jwt_auth import JWTValidationError, verify_hs256


def _segment(value):
    raw = json.dumps(value, separators=(',', ':')).encode('utf-8')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def make_token(secret='jwt-test-secret', **overrides):
    now = int(time.time())
    payload = {
        'sub': 'jwt-analyst',
        'tenant_id': 'tenant-jwt',
        'roles': ['analyst'],
        'iss': 'ai-siem-test',
        'aud': 'ai-siem-api-test',
        'iat': now,
        'nbf': now - 1,
        'exp': now + 300,
    }
    payload.update(overrides)
    header = {'alg': 'HS256', 'typ': 'JWT'}
    encoded_header = _segment(header)
    encoded_payload = _segment(payload)
    signing_input = f'{encoded_header}.{encoded_payload}'.encode('ascii')
    signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
    return f'{encoded_header}.{encoded_payload}.{encoded_signature}'


class JWTAuthTests(unittest.TestCase):
    def test_valid_jwt_returns_claim_context(self):
        context = verify_hs256(
            make_token(), 'jwt-test-secret', 'ai-siem-test', 'ai-siem-api-test'
        )
        self.assertEqual(context.principal_id, 'jwt-analyst')
        self.assertEqual(context.tenant_id, 'tenant-jwt')
        self.assertIn('analyst', context.roles)

    def test_expired_token_is_rejected(self):
        with self.assertRaises(JWTValidationError):
            verify_hs256(
                make_token(exp=int(time.time()) - 120),
                'jwt-test-secret',
                'ai-siem-test',
                'ai-siem-api-test',
                clock_skew_seconds=0,
            )

    def test_wrong_audience_and_signature_are_rejected(self):
        with self.assertRaises(JWTValidationError):
            verify_hs256(
                make_token(), 'jwt-test-secret', 'ai-siem-test', 'wrong-audience'
            )
        with self.assertRaises(JWTValidationError):
            verify_hs256(
                make_token(), 'wrong-secret', 'ai-siem-test', 'ai-siem-api-test'
            )

    def test_api_uses_jwt_tenant_and_roles(self):
        token = make_token()
        old = (security.AUTH_MODE, security.JWT_SECRET, security.JWT_ISSUER, security.JWT_AUDIENCE)
        try:
            security.AUTH_MODE = 'jwt'
            security.JWT_SECRET = 'jwt-test-secret'
            security.JWT_ISSUER = 'ai-siem-test'
            security.JWT_AUDIENCE = 'ai-siem-api-test'
            client = TestClient(main.app)
            response = client.get('/api/me', headers={'Authorization': f'Bearer {token}'})
        finally:
            security.AUTH_MODE, security.JWT_SECRET, security.JWT_ISSUER, security.JWT_AUDIENCE = old
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['tenant_id'], 'tenant-jwt')
        self.assertIn('analyst', response.json()['roles'])

    def test_legacy_token_is_rejected_in_jwt_mode(self):
        old = security.AUTH_MODE
        try:
            security.AUTH_MODE = 'jwt'
            security.JWT_SECRET = 'jwt-test-secret'
            client = TestClient(main.app)
            response = client.get('/api/me', headers={'Authorization': 'Bearer test-token'})
        finally:
            security.AUTH_MODE = old
        self.assertEqual(response.status_code, 401)

    def test_viewer_role_maps_to_reader(self):
        context = verify_hs256(
            make_token(roles=['viewer']),
            'jwt-test-secret',
            'ai-siem-test',
            'ai-siem-api-test',
        )
        self.assertIn('viewer', context.roles)
        self.assertIn('reader', context.roles)


if __name__ == '__main__':
    unittest.main()
