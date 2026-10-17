import asyncio
import json
import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_RATE_LIMIT_PER_MINUTE', '1000')

from backend.ai_gateway import (
    AIProviderError,
    AIQuotaExceeded,
    AISettings,
    AIUnavailable,
    _reset_request_budget_for_tests,
    analyze_alert,
)
from backend import main
from backend import security
from tests.helpers import alert, event


def ai_settings(**overrides):
    params = dict(
        enabled=True,
        external_opt_in=True,
        model='mock-model',
        api_key='fake-secret-for-mocked-transport',
        max_requests_per_minute=3,
    )
    params.update(overrides)
    return AISettings(**params)


def response_body(event_id='evt-1'):
    result = {
        'verdict': 'insufficient_evidence',
        'summary': 'The metadata supports review, not confirmation.',
        'supporting_event_ids': [event_id],
        'recommended_actions': ['Inspect authorized endpoint evidence.'],
    }
    return {
        'status': 'completed',
        'output': [{
            'type': 'message',
            'content': [{'type': 'output_text', 'text': json.dumps(result)}],
        }],
    }


class AIGatewayTests(unittest.TestCase):
    def setUp(self):
        _reset_request_budget_for_tests()

    def test_explicit_opt_in_and_configuration_required(self):
        with self.assertRaises(AIUnavailable):
            asyncio.run(analyze_alert(
                alert(1), [event(1)],
                settings=ai_settings(external_opt_in=False),
            ))
        with self.assertRaises(AIUnavailable):
            asyncio.run(analyze_alert(
                alert(1), [event(1)],
                settings=ai_settings(api_key=''),
            ))

    def test_metadata_only_and_evidence_citations(self):
        captured = []
        def responder(request):
            captured.append(request)
            return httpx.Response(200, json=response_body())
        async def exercise():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(responder)
            ) as client:
                return await analyze_alert(
                    alert(1),
                    [event(1, raw_log='MY_PRIVATE_TOKEN', user='private-user',
                           src_ip='8.8.8.8', command_line='PRIVATE_COMMAND')],
                    settings=ai_settings(),
                    client=client,
                )
        result = asyncio.run(exercise())
        self.assertEqual(result['verdict'], 'insufficient_evidence')
        self.assertEqual(result['supporting_event_ids'], ['evt-1'])
        self.assertTrue(result['advisory_only'])
        wire = captured[0].content.decode()
        self.assertNotIn('MY_PRIVATE_TOKEN', wire)
        self.assertNotIn('private-user', wire)
        self.assertNotIn('PRIVATE_COMMAND', wire)
        self.assertNotIn('8.8.8.8', wire)
        self.assertIn('"store":false', wire)
        self.assertIn('"max_output_tokens":400', wire)
        self.assertEqual(captured[0].url.host, 'api.openai.com')

    def test_fabricated_evidence_reference_is_rejected(self):
        async def exercise():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(
                        200, json=response_body('evt-invented'))
                )
            ) as client:
                await analyze_alert(
                    alert(1), [event(1)],
                    settings=ai_settings(), client=client,
                )
        with self.assertRaisesRegex(AIProviderError, 'evidence'):
            asyncio.run(exercise())

    def test_per_process_call_quota_bounds_requests(self):
        async def exercise():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, json=response_body())
                )
            ) as client:
                for _ in range(2):
                    await analyze_alert(
                        alert(1), [event(1)],
                        settings=ai_settings(max_requests_per_minute=1),
                        client=client,
                    )
        with self.assertRaises(AIQuotaExceeded):
            asyncio.run(exercise())

    def test_disabled_by_default_http_endpoint_and_role_enforcement(self):
        client = TestClient(main.app)
        sample_alert = main.alerts()[0]
        url = f'/api/ai/alerts/{sample_alert.alert_id}/analyze'
        with patch.dict(os.environ, {
            'AI_SIEM_AI_ENABLED': 'false',
            'AI_SIEM_AI_EXTERNAL_OPT_IN': 'false',
        }):
            disabled = client.post(url, headers={'Authorization': 'Bearer test-token'})
        self.assertEqual(disabled.status_code, 503)
        before = security.API_KEYS
        security.API_KEYS = {'viewer-demo-key': 'viewer'}
        try:
            forbidden = client.post(
                url, headers={'Authorization': 'Bearer viewer-demo-key'},
            )
            self.assertEqual(forbidden.status_code, 403)
        finally:
            security.API_KEYS = before

    def test_success_endpoint_uses_stored_alert_not_request_body(self):
        client = TestClient(main.app)
        sample_alert = main.alerts()[0]
        url = f'/api/ai/alerts/{sample_alert.alert_id}/analyze'
        output = {'alert_id': sample_alert.alert_id, 'advisory_only': True}
        with patch.dict(os.environ, {
            'AI_SIEM_AI_ENABLED': 'true',
            'AI_SIEM_AI_EXTERNAL_OPT_IN': 'true',
        }):
            with patch('backend.main.analyze_alert',
                       new_callable=AsyncMock, return_value=output) as mocked:
                result = client.post(
                    url, headers={'Authorization': 'Bearer test-token'},
                )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), output)
        self.assertTrue(mocked.await_args)
