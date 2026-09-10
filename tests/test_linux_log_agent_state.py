import json
import tempfile
import unittest
from pathlib import Path

from agents.linux_log_agent import load_offsets, process_file, read_new_lines, save_offsets


class LinuxLogAgentStateTests(unittest.TestCase):
    def test_load_offsets_rejects_malformed_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'offsets.json'
            state.write_text(
                json.dumps({
                    '/valid.log': 12,
                    '/negative.log': -1,
                    '/bool.log': True,
                    '/text.log': '9',
                    'nested': {'offset': 3},
                }),
                encoding='utf-8',
            )

            self.assertEqual(load_offsets(state), {'/valid.log': 12})

    def test_save_offsets_replaces_state_atomically_and_leaves_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'agent' / 'offsets.json'
            save_offsets(state, {'/var/log/auth.log': 42})

            self.assertEqual(
                json.loads(state.read_text(encoding='utf-8')),
                {'/var/log/auth.log': 42},
            )
            self.assertEqual(list(state.parent.glob(f'.{state.name}.*.tmp')), [])

    def test_invalid_in_memory_offset_does_not_break_log_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'auth.log'
            log.write_text('first\nsecond\n', encoding='utf-8')
            offsets = {str(log): 'corrupt'}

            self.assertEqual(read_new_lines(log, offsets, 10), [])
            self.assertEqual(offsets[str(log)], log.stat().st_size)

    def test_failed_delivery_does_not_advance_offset_or_drop_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'auth.log'
            log.write_text('first\nsecond\n', encoding='utf-8')
            offsets = {str(log): 0}

            def fail_send(lines):
                self.assertEqual(lines, ['first', 'second'])
                raise RuntimeError('backend unavailable')

            with self.assertRaisesRegex(RuntimeError, 'backend unavailable'):
                process_file(log, offsets, 10, fail_send)

            self.assertEqual(offsets[str(log)], 0)
            delivered = []
            process_file(log, offsets, 10, delivered.extend)
            self.assertEqual(delivered, ['first', 'second'])
            self.assertEqual(offsets[str(log)], log.stat().st_size)


if __name__ == '__main__':
    unittest.main()
