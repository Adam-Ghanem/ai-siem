from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from .models import Event
from .parser import parse_events
from .storage import save_events as sqlite_save_events


@dataclass(frozen=True)
class AsyncIngestResult:
    events: list[Event]
    tenant_id: str


class AsyncIngestionPipeline:
    """Run CPU/blocking parse and SQLite work without blocking FastAPI's event loop."""

    def __init__(self, storage_enabled: bool = True, persist_callback=sqlite_save_events) -> None:
        self.storage_enabled = storage_enabled
        self.persist_callback = persist_callback

    @staticmethod
    def _assign_tenant(events: list[Event], tenant_id: str) -> list[Event]:
        for event in events:
            event.tenant_id = tenant_id
            if tenant_id != 'default' and not event.id.startswith(f'{tenant_id}:'):
                event.id = f'{tenant_id}:{event.id}'
        return events

    async def parse(self, items: list[str | dict[str, Any]]) -> list[Event]:
        return await asyncio.to_thread(parse_events, items)

    async def persist(self, events: list[Event]) -> int:
        if not self.storage_enabled:
            return 0
        return await asyncio.to_thread(self.persist_callback, events)

    async def process(
        self,
        items: list[str | dict[str, Any]],
        tenant_id: str,
    ) -> AsyncIngestResult:
        parsed = await self.parse(items)
        scoped = self._assign_tenant(parsed, tenant_id)
        await self.persist(scoped)
        return AsyncIngestResult(events=scoped, tenant_id=tenant_id)
