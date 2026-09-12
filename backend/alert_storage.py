import json
from pathlib import Path
from typing import Iterable

from .storage import _alert_from_dict, connect, init_db


def alert_exists(alert_id: str, path: str | Path | None = None) -> bool:
    """Return whether an alert exists without materializing alert history."""
    if not alert_id:
        return False

    init_db(path)
    with connect(path) as conn:
        row = conn.execute(
            'SELECT 1 FROM alerts WHERE alert_id = ? LIMIT 1',
            (alert_id,),
        ).fetchone()
    return row is not None


def load_alerts_by_ids(
    alert_ids: Iterable[str],
    path: str | Path | None = None,
) -> list:
    """Load only requested alerts, preserving caller order and bounding SQL parameters."""
    ids = list(dict.fromkeys(str(alert_id) for alert_id in alert_ids if alert_id))
    if not ids:
        return []

    init_db(path)
    by_id = {}
    batch_size = 500
    with connect(path) as conn:
        for start in range(0, len(ids), batch_size):
            batch = ids[start:start + batch_size]
            placeholders = ','.join('?' for _ in batch)
            query = f'SELECT alert_id, alert_json FROM alerts WHERE alert_id IN ({placeholders})'
            for row in conn.execute(query, tuple(batch)):
                by_id[row['alert_id']] = _alert_from_dict(json.loads(row['alert_json']))

    return [by_id[alert_id] for alert_id in ids if alert_id in by_id]
