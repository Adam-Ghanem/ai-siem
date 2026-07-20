import tempfile
import unittest
from pathlib import Path

from agents.linux_log_agent import (
    _NoRedirectHandler,
    load_offsets,
    read_new_lines,
    save_offsets,
    validate_api_url,
)


class AgentTests(unittest.TestCase):
    def test_remote_http_and_credential_urls_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_api_url('http://siem.example.com')
        with self.assertRaises(ValueError):
            validate_api_url('https://user:secret@siem.example.com')
        with self.assertRaises(ValueError):
            validate_api_url('https://siem.example.com?token=secret')
        self.assertEqual(
            validate_api_url('http://localhost:8000'), 'http://localhost:8000'
        )
        self.assertEqual(
            validate_api_url('https://siem.example.com'), 'https://siem.example.com'
        )

    def test_redirect_handler_refuses_redirects(self):
        handler = _NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                None, None, 302, 'Found', {}, 'https://other.example'
            )
        )

    def test_offset_can_be_committed_only_after_successful_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'auth.log'
            log.write_text('first\nsecond\n', encoding='utf-8')
            lines, next_offset = read_new_lines(log, 0, 25)
            self.assertEqual(lines, ['first', 'second'])
            retry_lines, retry_offset = read_new_lines(log, 0, 25)
            self.assertEqual(retry_lines, lines)
            self.assertEqual(retry_offset, next_offset)
            committed_lines, _ = read_new_lines(log, next_offset, 25)
            self.assertEqual(committed_lines, [])

    def test_offset_state_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state.json'
            save_offsets(state, {'/var/log/auth.log': 42})
            self.assertEqual(load_offsets(state), {'/var/log/auth.log': 42})


if __name__ == '__main__':
    unittest.main()
