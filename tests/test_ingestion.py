import unittest

from backend.ingestion import AsyncIngestionPipeline


class AsyncIngestionPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_process_parses_without_blocking_storage_when_disabled(self):
        pipeline = AsyncIngestionPipeline(storage_enabled=False)
        result = await pipeline.process(
            [
                'Jun 11 12:00:00 host-a sshd[1]: Accepted password for adam from 203.0.113.10 port 22 ssh2'
            ],
            'tenant-a',
        )
        self.assertEqual(result.tenant_id, 'tenant-a')
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].tenant_id, 'tenant-a')
        self.assertTrue(result.events[0].id.startswith('tenant-a:'))

    async def test_process_preserves_multiple_events_and_scopes_ids(self):
        pipeline = AsyncIngestionPipeline(storage_enabled=False)
        result = await pipeline.process(
            [
                'Jun 11 12:00:00 host-a sshd[1]: Failed password for adam from 203.0.113.10 port 22 ssh2',
                'Jun 11 12:00:01 host-a sshd[2]: Failed password for adam from 203.0.113.10 port 22 ssh2',
            ],
            'tenant-b',
        )
        self.assertEqual(len(result.events), 2)
        self.assertTrue(all(event.id.startswith('tenant-b:') for event in result.events))


if __name__ == '__main__':
    unittest.main()
