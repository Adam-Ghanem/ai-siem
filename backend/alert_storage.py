from pathlib import Path

from .storage import connect, init_db


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
