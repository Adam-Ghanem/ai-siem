"""Persistent SOC alert and incident lifecycle operations."""

from __future__ import annotations

import re
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4

from .models import Alert, Incident
from .notifications import dispatch_alert_notification, severity_is_enabled
from .storage import connect, init_db

ALERT_STATUSES = {
    'open',
    'acknowledged',
    'investigating',
    'resolved',
    'false_positive',
}
INCIDENT_STATUSES = {'open', 'investigating', 'contained', 'resolved', 'closed'}
ALERT_CLOSED_STATUSES = {'resolved', 'false_positive'}
INCIDENT_CLOSED_STATUSES = {'resolved', 'closed'}
ALERT_TRANSITIONS = {
    'open': {'acknowledged', 'investigating', 'resolved', 'false_positive'},
    'acknowledged': {'open', 'investigating', 'resolved', 'false_positive'},
    'investigating': {'open', 'resolved', 'false_positive'},
    'resolved': {'open', 'acknowledged', 'investigating'},
    'false_positive': {'open', 'acknowledged', 'investigating'},
}
INCIDENT_TRANSITIONS = {
    'open': {'investigating', 'contained', 'resolved', 'closed'},
    'investigating': {'open', 'contained', 'resolved', 'closed'},
    'contained': {'investigating', 'resolved', 'closed'},
    'resolved': {'open', 'investigating', 'closed'},
    'closed': {'open', 'investigating'},
}
ALERT_SLA_MINUTES = {'critical': 15, 'high': 60, 'medium': 240, 'low': 1440}
INCIDENT_SLA_MINUTES = {'P1': 30, 'P2': 240, 'P3': 1440}

_ACTOR_PATTERN = re.compile(r'^[A-Za-z0-9@._ -]{1,80}$')


class OperationNotFound(LookupError):
    """Raised when an alert or incident has no operational record."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _actor(value: str) -> str:
    normalized = str(value).strip()
    if not _ACTOR_PATTERN.fullmatch(normalized):
        raise ValueError('actor must contain 1-80 safe characters')
    return normalized


def _assignee(value: str | None) -> str:
    normalized = str(value or 'unassigned').strip() or 'unassigned'
    if normalized != 'unassigned' and not _ACTOR_PATTERN.fullmatch(normalized):
        raise ValueError('assigned_to must contain at most 80 safe characters')
    return normalized


def _note(value: str | None) -> str:
    normalized = str(value or '').strip()
    if len(normalized) > 2000:
        raise ValueError('resolution_note must not exceed 2000 characters')
    return normalized


class OperationsStore:
    """Track alert and incident ownership, status, SLA, and history."""

    def __init__(
        self,
        *,
        persistent: bool,
        path: str | Path | None = None,
        clock: Callable[[], datetime] = _utc_now,
        notifier: Callable[[dict[str, Any], str], bool] = dispatch_alert_notification,
    ) -> None:
        self.persistent = persistent
        self.path = path
        self.clock = clock
        self.notifier = notifier
        self._lock = threading.RLock()
        self._alerts: dict[str, dict[str, Any]] = {}
        self._incidents: dict[str, dict[str, Any]] = {}
        self._history: deque[dict[str, Any]] = deque(maxlen=5000)
        if self.persistent:
            init_db(self.path)

    def _notify_alert(
        self,
        alert: Alert,
        state: dict[str, Any],
        reason: str,
    ) -> None:
        if not severity_is_enabled(alert.severity):
            return
        payload = alert.to_dict()
        payload.update(state)
        try:
            self.notifier(payload, reason)
        except Exception:
            # Notification failures must never interrupt detection or persistence.
            return

    def _history_record(
        self,
        object_type: str,
        object_id: str,
        action: str,
        actor: str,
        note: str,
        created_at: str,
    ) -> dict[str, Any]:
        return {
            'history_id': f'HST-{uuid4().hex[:12].upper()}',
            'object_type': object_type,
            'object_id': object_id,
            'action': action,
            'actor': actor,
            'note': note,
            'created_at': created_at,
        }

    @staticmethod
    def _insert_history(conn, record: dict[str, Any]) -> None:
        conn.execute(
            '''
            INSERT INTO operation_history
            (history_id, object_type, object_id, action, actor, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                record['history_id'],
                record['object_type'],
                record['object_id'],
                record['action'],
                record['actor'],
                record['note'],
                record['created_at'],
            ),
        )

    def sync_alerts(self, alerts: Iterable[Alert]) -> list[str]:
        """Create operational records for newly detected alerts."""
        now = self.clock()
        now_text = _iso(now)
        new_ids: list[str] = []
        with self._lock:
            if self.persistent:
                with connect(self.path) as conn:
                    for alert in alerts:
                        due_at = _iso(
                            now
                            + timedelta(
                                minutes=ALERT_SLA_MINUTES.get(alert.severity, 1440)
                            )
                        )
                        cursor = conn.execute(
                            '''
                            INSERT OR IGNORE INTO alert_operations
                            (alert_id, rule_id, title, severity, status, assigned_to,
                             resolution_note, first_seen_at, last_seen_at, due_at,
                             updated_at, occurrence_count)
                            VALUES (?, ?, ?, ?, 'open', 'unassigned', '', ?, ?, ?, ?, ?)
                            ''',
                            (
                                alert.alert_id,
                                alert.rule_id,
                                alert.title,
                                alert.severity,
                                now_text,
                                now_text,
                                due_at,
                                now_text,
                                max(1, len(alert.event_ids)),
                            ),
                        )
                        if cursor.rowcount:
                            new_ids.append(alert.alert_id)
                            self._insert_history(
                                conn,
                                self._history_record(
                                    'alert',
                                    alert.alert_id,
                                    'detected',
                                    'detection-engine',
                                    alert.title,
                                    now_text,
                                ),
                            )
                            self._notify_alert(
                                alert,
                                {
                                    'status': 'open',
                                    'assigned_to': 'unassigned',
                                    'due_at': due_at,
                                    'occurrence_count': max(1, len(alert.event_ids)),
                                },
                                'new_alert',
                            )
                        conn.execute(
                            '''
                            UPDATE alert_operations
                            SET rule_id = ?, title = ?, severity = ?, last_seen_at = ?,
                                occurrence_count = MAX(occurrence_count, ?)
                            WHERE alert_id = ?
                            ''',
                            (
                                alert.rule_id,
                                alert.title,
                                alert.severity,
                                now_text,
                                max(1, len(alert.event_ids)),
                                alert.alert_id,
                            ),
                        )
                    conn.commit()
                return new_ids

            for alert in alerts:
                record = self._alerts.get(alert.alert_id)
                if record is None:
                    record = {
                        'alert_id': alert.alert_id,
                        'rule_id': alert.rule_id,
                        'title': alert.title,
                        'severity': alert.severity,
                        'status': 'open',
                        'assigned_to': 'unassigned',
                        'resolution_note': '',
                        'first_seen_at': now_text,
                        'last_seen_at': now_text,
                        'due_at': _iso(
                            now
                            + timedelta(
                                minutes=ALERT_SLA_MINUTES.get(alert.severity, 1440)
                            )
                        ),
                        'updated_at': now_text,
                        'occurrence_count': max(1, len(alert.event_ids)),
                    }
                    self._alerts[alert.alert_id] = record
                    new_ids.append(alert.alert_id)
                    self._history.appendleft(
                        self._history_record(
                            'alert',
                            alert.alert_id,
                            'detected',
                            'detection-engine',
                            alert.title,
                            now_text,
                        )
                    )
                    self._notify_alert(alert, record, 'new_alert')
                else:
                    record.update(
                        {
                            'rule_id': alert.rule_id,
                            'title': alert.title,
                            'severity': alert.severity,
                            'last_seen_at': now_text,
                            'occurrence_count': max(
                                int(record['occurrence_count']),
                                len(alert.event_ids),
                                1,
                            ),
                        }
                    )
        return new_ids

    def sync_incidents(self, incidents: Iterable[Incident]) -> list[str]:
        """Create operational records for newly correlated incidents."""
        now = self.clock()
        now_text = _iso(now)
        new_ids: list[str] = []
        with self._lock:
            if self.persistent:
                with connect(self.path) as conn:
                    for incident in incidents:
                        due_at = _iso(
                            now
                            + timedelta(
                                minutes=INCIDENT_SLA_MINUTES.get(
                                    incident.priority, 1440
                                )
                            )
                        )
                        cursor = conn.execute(
                            '''
                            INSERT OR IGNORE INTO incident_operations
                            (incident_id, title, priority, status, assigned_to,
                             resolution_note, first_seen_at, last_seen_at, due_at,
                             updated_at)
                            VALUES (?, ?, ?, 'open', 'unassigned', '', ?, ?, ?, ?)
                            ''',
                            (
                                incident.incident_id,
                                incident.title,
                                incident.priority,
                                now_text,
                                now_text,
                                due_at,
                                now_text,
                            ),
                        )
                        if cursor.rowcount:
                            new_ids.append(incident.incident_id)
                            self._insert_history(
                                conn,
                                self._history_record(
                                    'incident',
                                    incident.incident_id,
                                    'created',
                                    'correlation-engine',
                                    incident.title,
                                    now_text,
                                ),
                            )
                        conn.execute(
                            '''
                            UPDATE incident_operations
                            SET title = ?, priority = ?, last_seen_at = ?
                            WHERE incident_id = ?
                            ''',
                            (
                                incident.title,
                                incident.priority,
                                now_text,
                                incident.incident_id,
                            ),
                        )
                    conn.commit()
                return new_ids

            for incident in incidents:
                record = self._incidents.get(incident.incident_id)
                if record is None:
                    record = {
                        'incident_id': incident.incident_id,
                        'title': incident.title,
                        'priority': incident.priority,
                        'status': 'open',
                        'assigned_to': 'unassigned',
                        'resolution_note': '',
                        'first_seen_at': now_text,
                        'last_seen_at': now_text,
                        'due_at': _iso(
                            now
                            + timedelta(
                                minutes=INCIDENT_SLA_MINUTES.get(
                                    incident.priority, 1440
                                )
                            )
                        ),
                        'updated_at': now_text,
                    }
                    self._incidents[incident.incident_id] = record
                    new_ids.append(incident.incident_id)
                    self._history.appendleft(
                        self._history_record(
                            'incident',
                            incident.incident_id,
                            'created',
                            'correlation-engine',
                            incident.title,
                            now_text,
                        )
                    )
                else:
                    record.update(
                        {
                            'title': incident.title,
                            'priority': incident.priority,
                            'last_seen_at': now_text,
                        }
                    )
        return new_ids

    def _load_alerts(self) -> dict[str, dict[str, Any]]:
        if not self.persistent:
            return {key: dict(value) for key, value in self._alerts.items()}
        with connect(self.path) as conn:
            rows = conn.execute('SELECT * FROM alert_operations').fetchall()
        return {row['alert_id']: dict(row) for row in rows}

    def _load_incidents(self) -> dict[str, dict[str, Any]]:
        if not self.persistent:
            return {key: dict(value) for key, value in self._incidents.items()}
        with connect(self.path) as conn:
            rows = conn.execute('SELECT * FROM incident_operations').fetchall()
        return {row['incident_id']: dict(row) for row in rows}

    def _sla_fields(self, record: dict[str, Any], closed: set[str]) -> dict[str, Any]:
        seconds = int((_parse_time(record['due_at']) - self.clock()).total_seconds())
        return {
            'sla_breached': record['status'] not in closed and seconds < 0,
            'seconds_to_sla': seconds,
        }

    def _record_alert_sla_breach(self, alert: Alert, state: dict[str, Any]) -> bool:
        now_text = _iso(self.clock())
        if self.persistent:
            with connect(self.path) as conn:
                exists = conn.execute(
                    '''
                    SELECT 1 FROM operation_history
                    WHERE object_type = 'alert' AND object_id = ?
                      AND action = 'sla_breached'
                    LIMIT 1
                    ''',
                    (alert.alert_id,),
                ).fetchone()
                if exists:
                    return False
                self._insert_history(
                    conn,
                    self._history_record(
                        'alert',
                        alert.alert_id,
                        'sla_breached',
                        'sla-monitor',
                        'Alert response SLA deadline exceeded',
                        now_text,
                    ),
                )
                conn.commit()
        else:
            if any(
                record['object_type'] == 'alert'
                and record['object_id'] == alert.alert_id
                and record['action'] == 'sla_breached'
                for record in self._history
            ):
                return False
            self._history.appendleft(
                self._history_record(
                    'alert',
                    alert.alert_id,
                    'sla_breached',
                    'sla-monitor',
                    'Alert response SLA deadline exceeded',
                    now_text,
                )
            )
        self._notify_alert(alert, state, 'sla_breach')
        return True

    def alert_views(self, alerts: Iterable[Alert]) -> list[dict[str, Any]]:
        with self._lock:
            states = self._load_alerts()
            views: list[dict[str, Any]] = []
            for alert in alerts:
                view = alert.to_dict()
                state = states.get(alert.alert_id)
                if state:
                    view.update(state)
                    sla = self._sla_fields(state, ALERT_CLOSED_STATUSES)
                    view.update(sla)
                    if sla['sla_breached']:
                        self._record_alert_sla_breach(alert, view)
                views.append(view)
            return views

    def incident_views(self, incidents: Iterable[Incident]) -> list[dict[str, Any]]:
        with self._lock:
            states = self._load_incidents()
            views: list[dict[str, Any]] = []
            for incident in incidents:
                view = incident.to_dict()
                state = states.get(incident.incident_id)
                if state:
                    view.update(state)
                    view['owner'] = state['assigned_to']
                    view.update(self._sla_fields(state, INCIDENT_CLOSED_STATUSES))
                views.append(view)
            return views

    @staticmethod
    def _validate_transition(
        current: str,
        requested: str,
        transitions: dict[str, set[str]],
    ) -> None:
        if requested == current:
            return
        if requested not in transitions.get(current, set()):
            raise ValueError(f'unsupported status transition: {current} -> {requested}')

    def update_alert(
        self,
        alert_id: str,
        *,
        status: str | None,
        assigned_to: str | None,
        resolution_note: str | None,
        actor: str,
    ) -> dict[str, Any]:
        actor_name = _actor(actor)
        with self._lock:
            records = self._load_alerts()
            current = records.get(alert_id)
            if current is None:
                raise OperationNotFound('Alert not found')
            next_status = str(status or current['status']).strip().lower()
            if next_status not in ALERT_STATUSES:
                raise ValueError('unsupported alert status')
            self._validate_transition(current['status'], next_status, ALERT_TRANSITIONS)
            next_assignee = (
                _assignee(assigned_to)
                if assigned_to is not None
                else current['assigned_to']
            )
            next_note = (
                _note(resolution_note)
                if resolution_note is not None
                else current['resolution_note']
            )
            if next_status in ALERT_CLOSED_STATUSES and not next_note:
                raise ValueError('resolution_note is required when closing an alert')
            now_text = _iso(self.clock())
            action = f'status:{current["status"]}->{next_status}'
            if next_status == current['status']:
                action = 'metadata_updated'
            history = self._history_record(
                'alert', alert_id, action, actor_name, next_note, now_text
            )
            if self.persistent:
                with connect(self.path) as conn:
                    conn.execute(
                        '''
                        UPDATE alert_operations
                        SET status = ?, assigned_to = ?, resolution_note = ?, updated_at = ?
                        WHERE alert_id = ?
                        ''',
                        (next_status, next_assignee, next_note, now_text, alert_id),
                    )
                    self._insert_history(conn, history)
                    conn.commit()
            else:
                current.update(
                    {
                        'status': next_status,
                        'assigned_to': next_assignee,
                        'resolution_note': next_note,
                        'updated_at': now_text,
                    }
                )
                self._alerts[alert_id] = current
                self._history.appendleft(history)
            updated = self._load_alerts()[alert_id]
            updated.update(self._sla_fields(updated, ALERT_CLOSED_STATUSES))
            return updated

    def update_incident(
        self,
        incident_id: str,
        *,
        status: str | None,
        assigned_to: str | None,
        resolution_note: str | None,
        actor: str,
    ) -> dict[str, Any]:
        actor_name = _actor(actor)
        with self._lock:
            records = self._load_incidents()
            current = records.get(incident_id)
            if current is None:
                raise OperationNotFound('Incident not found')
            next_status = str(status or current['status']).strip().lower()
            if next_status not in INCIDENT_STATUSES:
                raise ValueError('unsupported incident status')
            self._validate_transition(
                current['status'], next_status, INCIDENT_TRANSITIONS
            )
            next_assignee = (
                _assignee(assigned_to)
                if assigned_to is not None
                else current['assigned_to']
            )
            next_note = (
                _note(resolution_note)
                if resolution_note is not None
                else current['resolution_note']
            )
            if next_status in INCIDENT_CLOSED_STATUSES and not next_note:
                raise ValueError('resolution_note is required when closing an incident')
            now_text = _iso(self.clock())
            action = f'status:{current["status"]}->{next_status}'
            if next_status == current['status']:
                action = 'metadata_updated'
            history = self._history_record(
                'incident', incident_id, action, actor_name, next_note, now_text
            )
            if self.persistent:
                with connect(self.path) as conn:
                    conn.execute(
                        '''
                        UPDATE incident_operations
                        SET status = ?, assigned_to = ?, resolution_note = ?, updated_at = ?
                        WHERE incident_id = ?
                        ''',
                        (next_status, next_assignee, next_note, now_text, incident_id),
                    )
                    self._insert_history(conn, history)
                    conn.commit()
            else:
                current.update(
                    {
                        'status': next_status,
                        'assigned_to': next_assignee,
                        'resolution_note': next_note,
                        'updated_at': now_text,
                    }
                )
                self._incidents[incident_id] = current
                self._history.appendleft(history)
            updated = self._load_incidents()[incident_id]
            updated.update(self._sla_fields(updated, INCIDENT_CLOSED_STATUSES))
            return updated

    def history(
        self,
        *,
        object_type: str | None = None,
        object_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError('limit must be between 1 and 1000')
        if object_type is not None and object_type not in {'alert', 'incident'}:
            raise ValueError('object_type must be alert or incident')
        with self._lock:
            if self.persistent:
                clauses: list[str] = []
                parameters: list[Any] = []
                if object_type is not None:
                    clauses.append('object_type = ?')
                    parameters.append(object_type)
                if object_id is not None:
                    clauses.append('object_id = ?')
                    parameters.append(object_id)
                where = f" WHERE {' AND '.join(clauses)}" if clauses else ''
                parameters.append(limit)
                with connect(self.path) as conn:
                    rows = conn.execute(
                        f'''
                        SELECT history_id, object_type, object_id, action, actor, note,
                               created_at
                        FROM operation_history
                        {where}
                        ORDER BY created_at DESC
                        LIMIT ?
                        ''',
                        parameters,
                    ).fetchall()
                records = [dict(row) for row in rows]
            else:
                records = list(self._history)
                if object_type is not None:
                    records = [
                        record
                        for record in records
                        if record['object_type'] == object_type
                    ]
                if object_id is not None:
                    records = [
                        record
                        for record in records
                        if record['object_id'] == object_id
                    ]
            return records[:limit]

    def summary(self) -> dict[str, int]:
        with self._lock:
            alerts = list(self._load_alerts().values())
            incidents = list(self._load_incidents().values())
            return {
                'open_alerts': sum(
                    record['status'] not in ALERT_CLOSED_STATUSES for record in alerts
                ),
                'unassigned_alerts': sum(
                    record['status'] not in ALERT_CLOSED_STATUSES
                    and record['assigned_to'] == 'unassigned'
                    for record in alerts
                ),
                'breached_alert_slas': sum(
                    self._sla_fields(record, ALERT_CLOSED_STATUSES)['sla_breached']
                    for record in alerts
                ),
                'open_incidents': sum(
                    record['status'] not in INCIDENT_CLOSED_STATUSES
                    for record in incidents
                ),
                'breached_incident_slas': sum(
                    self._sla_fields(record, INCIDENT_CLOSED_STATUSES)['sla_breached']
                    for record in incidents
                ),
            }
