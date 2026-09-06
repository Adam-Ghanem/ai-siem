import hashlib
import multiprocessing
import os
import time
import unittest
from pathlib import Path

os.environ.setdefault('AI_SIEM_API_KEY', 'test-token')
os.environ.setdefault('AI_SIEM_AUDIT_LOG', 'logs/test-audit-integrity.log')

from starlette.requests import Request

import backend.security as security


AUDIT_PATH = Path('logs/test-audit-integrity.log')


def _concurrent_audit_writer(path: str, request_id: str, start_event) -> None:
    security.AUDIT_LOG_PATH = Path(path)
    security.AUDIT_HMAC_KEY = b''
    security.AUDIT_HMAC_PREVIOUS_KEYS = ()
    security._AUDIT_HEAD_CACHE.clear()

    original_current_head = security._current_audit_head

    def delayed_current_head(audit_path: Path) -> str:
        head = original_current_head(audit_path)
        time.sleep(0.3)
        return head

    security._current_audit_head = delayed_current_head
    scope = {
        'type': 'http',
        'method': 'POST',
        'path': '/api/triage',
        'raw_path': b'/api/triage',
        'query_string': b'',
        'headers': [],
        'scheme': 'http',
        'server': ('testserver', 80),
        'client': ('198.51.100.10', 12345),
    }
    request = Request(scope)
    request.state.request_id = request_id
    request.state.authz_role = 'analyst'
    start_event.wait(timeout=5)
    security.audit_log(request, 'triage', 'success', request_id)


class AuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        security.AUDIT_LOG_PATH = AUDIT_PATH
        security.AUDIT_HMAC_KEY = b''
        security.AUDIT_HMAC_PREVIOUS_KEYS = ()
        security._AUDIT_HEAD_CACHE.clear()
        AUDIT_PATH.unlink(missing_ok=True)

    @staticmethod
    def _request(request_id: str) -> Request:
        scope = {
            'type': 'http',
            'method': 'POST',
            'path': '/api/triage',
            'raw_path': b'/api/triage',
            'query_string': b'',
            'headers': [],
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('198.51.100.10', 12345),
        }
        request = Request(scope)
        request.state.request_id = request_id
        request.state.authz_role = 'analyst'
        return request

    def test_untrusted_detail_cannot_inject_additional_audit_fields(self):
        request = self._request('req-1')

        security.audit_log(
            request,
            'triage',
            'success',
            'alert_id=AL-1 forged=true role=admin',
        )

        text = AUDIT_PATH.read_text(encoding='utf-8').strip()
        fields = text.split()
        self.assertIn('result=success', fields)
        self.assertNotIn('forged=true', fields)
        self.assertEqual(fields.count('role=admin'), 0)
        self.assertIn(
            'detail=alert_id%3DAL-1%20forged%3Dtrue%20role%3Dadmin',
            text,
        )

    def test_audit_records_are_hash_chained(self):
        security.audit_log(self._request('req-1'), 'triage', 'success', 'first')
        security.audit_log(self._request('req-2'), 'triage', 'success', 'second')

        lines = AUDIT_PATH.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 2)
        first_fields = dict(field.split('=', 1) for field in lines[0].split())
        second_fields = dict(field.split('=', 1) for field in lines[1].split())
        self.assertEqual(first_fields['prev_hash'], '0' * 64)
        self.assertEqual(second_fields['prev_hash'], first_fields['hash'])
        self.assertTrue(security.verify_audit_log(AUDIT_PATH))

    def test_concurrent_process_writers_preserve_single_audit_chain(self):
        start_event = multiprocessing.Event()
        writers = [
            multiprocessing.Process(
                target=_concurrent_audit_writer,
                args=(str(AUDIT_PATH), f'worker-{index}', start_event),
            )
            for index in range(2)
        ]
        for writer in writers:
            writer.start()
        start_event.set()
        for writer in writers:
            writer.join(timeout=5)
            self.assertFalse(writer.is_alive())
            self.assertEqual(writer.exitcode, 0)

        security._AUDIT_HEAD_CACHE.clear()
        lines = AUDIT_PATH.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(security.verify_audit_log(AUDIT_PATH))

    def test_audit_verifier_detects_modified_record(self):
        security.audit_log(self._request('req-1'), 'triage', 'success', 'first')
        security.audit_log(self._request('req-2'), 'triage', 'success', 'second')
        original = AUDIT_PATH.read_text(encoding='utf-8')
        AUDIT_PATH.write_text(original.replace('result=success', 'result=failure', 1), encoding='utf-8')

        self.assertFalse(security.verify_audit_log(AUDIT_PATH))

    def test_configured_hmac_key_signs_audit_records(self):
        security.AUDIT_HMAC_KEY = b'separate-test-signing-key'

        security.audit_log(self._request('req-hmac'), 'triage', 'success', 'signed')

        fields = dict(
            field.split('=', 1)
            for field in AUDIT_PATH.read_text(encoding='utf-8').strip().split()
        )
        self.assertIn('integrity', fields)
        self.assertEqual(fields.get('integrity'), 'hmac-sha256')
        self.assertEqual(len(fields.get('mac', '')), 64)
        self.assertTrue(security.verify_audit_log(AUDIT_PATH))

    def test_hmac_verifier_rejects_sha_rewrite_without_signing_key(self):
        security.AUDIT_HMAC_KEY = b'separate-test-signing-key'
        security.audit_log(self._request('req-hmac'), 'triage', 'success', 'original')

        line = AUDIT_PATH.read_text(encoding='utf-8').strip()
        record, integrity = line.rsplit(' prev_hash=', 1)
        previous_hash, _, remainder = integrity.partition(' hash=')
        _, _, mac_part = remainder.partition(' mac=')
        del mac_part
        forged_record = record.replace('result=success', 'result=failure')
        forged_hash = hashlib.sha256(f'{previous_hash} {forged_record}'.encode('utf-8')).hexdigest()
        AUDIT_PATH.write_text(
            f'{forged_record} prev_hash={previous_hash} hash={forged_hash}\n',
            encoding='utf-8',
        )
        security._AUDIT_HEAD_CACHE.clear()

        self.assertFalse(security.verify_audit_log(AUDIT_PATH))

    def test_hmac_rotation_verifies_existing_records_with_previous_key(self):
        old_key = b'old-audit-signing-key'
        new_key = b'new-audit-signing-key'
        security.AUDIT_HMAC_KEY = old_key
        security.audit_log(self._request('req-old'), 'triage', 'success', 'old-key')

        security.AUDIT_HMAC_KEY = new_key
        security.AUDIT_HMAC_PREVIOUS_KEYS = (old_key,)
        security._AUDIT_HEAD_CACHE.clear()
        security.audit_log(self._request('req-new'), 'triage', 'success', 'new-key')

        self.assertTrue(security.verify_audit_log(AUDIT_PATH))
        lines = AUDIT_PATH.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 2)

    def test_previous_hmac_key_config_requires_json_string_array(self):
        self.assertEqual(
            security._load_audit_hmac_previous_keys('["old-key", "older-key"]'),
            (b'old-key', b'older-key'),
        )
        with self.assertRaises(RuntimeError):
            security._load_audit_hmac_previous_keys('{"old": "key"}')
        with self.assertRaises(RuntimeError):
            security._load_audit_hmac_previous_keys('["old-key", ""]')


if __name__ == '__main__':
    unittest.main()
