from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import Event
from .storage import connect, init_db


def load_events_by_ids(
    event_ids: Iterable[str],
    path: str | Path | None = None,
) -> list[Event]:
    """Load exact supporting events without materializing the event history."""
    ids = list(dict.fromkeys(str(event_id) for event_id in event_ids if event_id))
    if not ids:
        return []

    init_db(path)
    loaded: dict[str, Event] = {}
    batch_size = 500
    with connect(path) as conn:
        for start in range(0, len(ids), batch_size):
            batch = ids[start:start + batch_size]
            placeholders = ','.join('?' for _ in batch)
            query = f'SELECT id, event_json FROM events WHERE id IN ({placeholders})'
            for row in conn.execute(query, tuple(batch)):
                loaded[row['id']] = Event.from_dict(json.loads(row['event_json']))

    return [loaded[event_id] for event_id in ids if event_id in loaded]
