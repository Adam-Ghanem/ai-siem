from __future__ import annotations

from pathlib import Path

from .metrics import PW, SW
from .storage import connect, init_db


def calculate_sqlite_metrics(path: str | Path | None = None) -> dict:
    """Calculate dashboard metrics without materializing durable histories."""
    init_db(path)
    with connect(path) as conn:
        conn.execute('BEGIN')

        event_total = int(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0])
        source_distribution = {
            str(row['source']): int(row['count'])
            for row in conn.execute(
                'SELECT source, COUNT(*) AS count FROM events GROUP BY source'
            )
        }
        event_type_distribution = {
            str(row['event_type']): int(row['count'])
            for row in conn.execute(
                'SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type'
            )
        }

        alert_row = conn.execute(
            '''
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high,
                SUM(
                    CASE severity
                        WHEN 'critical' THEN ?
                        WHEN 'high' THEN ?
                        WHEN 'medium' THEN ?
                        WHEN 'low' THEN ?
                        ELSE 1
                    END
                ) AS risk
            FROM alerts
            ''',
            (SW['critical'], SW['high'], SW['medium'], SW['low']),
        ).fetchone()
        top_tactics = {
            str(row['tactic']): int(row['count'])
            for row in conn.execute(
                '''
                SELECT tactic, COUNT(*) AS count
                FROM alerts
                GROUP BY tactic
                ORDER BY count DESC, tactic ASC
                LIMIT 5
                '''
            )
        }

        incident_row = conn.execute(
            '''
            SELECT
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count,
                SUM(
                    CASE
                        WHEN status != 'open' THEN 0
                        WHEN priority = 'P1' THEN ?
                        WHEN priority = 'P2' THEN ?
                        WHEN priority = 'P3' THEN ?
                        ELSE 1
                    END
                ) AS risk
            FROM incidents
            ''',
            (PW['P1'], PW['P2'], PW['P3']),
        ).fetchone()
        conn.rollback()

    alert_risk = int(alert_row['risk'] or 0)
    incident_risk = int(incident_row['risk'] or 0)
    return {
        'total_events': event_total,
        'total_alerts': int(alert_row['total'] or 0),
        'critical_alerts': int(alert_row['critical'] or 0),
        'high_alerts': int(alert_row['high'] or 0),
        'open_incidents': int(incident_row['open_count'] or 0),
        'risk_score': min(100, alert_risk + incident_risk),
        'top_tactics': top_tactics,
        'source_distribution': source_distribution,
        'event_type_distribution': event_type_distribution,
    }
