"""Secure, best-effort outbound alert notifications."""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal
from urllib.parse import urlsplit, urlunsplit

NotificationKind = Literal['webhook', 'slack']

REQUEST_TIMEOUT_SECONDS = 5
RETRY_COUNT = 3
MAX_RESPONSE_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024
_SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_IP_ADDRESS = re.compile(
    r'(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])'
)
_LOGGER = logging.getLogger(__name__)


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f'{name} must be an integer') from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f'{name} must be between {minimum} and {maximum}')
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    raise RuntimeError(f'{name} must be a boolean')


def validate_notification_url(value: str) -> str:
    """Return a normalized HTTPS webhook URL or reject unsafe input."""
    normalized = str(value).strip()
    if not normalized or len(normalized) > 2048:
        raise ValueError('Notification URL must contain 1-2048 characters')
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in normalized
    ) or '\\' in normalized:
        raise ValueError('Notification URL must not contain whitespace or controls')
    try:
        parsed = urlsplit(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Notification URL is invalid') from exc
    if parsed.scheme != 'https' or not parsed.hostname:
        raise ValueError('Notification URL must use HTTPS')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('Notification URL must not contain credentials')
    if '?' in normalized or '#' in normalized:
        raise ValueError('Notification URL must not contain a query or fragment')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Notification URL port is invalid')
    return urlunsplit(('https', parsed.netloc, parsed.path or '/', '', ''))


@dataclass(frozen=True)
class NotificationChannel:
    """One explicitly configured outbound notification destination."""

    kind: NotificationKind
    url: str
    enabled: bool


@dataclass(frozen=True)
class ChannelResult:
    """Public delivery result that never contains a destination URL."""

    kind: NotificationKind
    status: Literal['delivered', 'failed', 'skipped']
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {'kind': self.kind, 'status': self.status, 'detail': self.detail}


@dataclass(frozen=True)
class NotificationResult:
    """Aggregate result for a best-effort notification attempt."""

    channels: tuple[ChannelResult, ...]

    @property
    def delivered(self) -> int:
        return sum(result.status == 'delivered' for result in self.channels)

    @property
    def failed(self) -> int:
        return sum(result.status == 'failed' for result in self.channels)

    @property
    def skipped(self) -> int:
        return sum(result.status == 'skipped' for result in self.channels)

    def to_dict(self) -> dict[str, Any]:
        return {
            'delivered': self.delivered,
            'failed': self.failed,
            'skipped': self.skipped,
            'channels': [result.to_dict() for result in self.channels],
        }


def _channel(kind: NotificationKind, value: str) -> NotificationChannel:
    normalized = value.strip()
    return NotificationChannel(
        kind=kind,
        url=validate_notification_url(normalized) if normalized else '',
        enabled=bool(normalized),
    )


WEBHOOK_URL = os.getenv('AI_SIEM_WEBHOOK_URL', '')
SLACK_WEBHOOK_URL = os.getenv('AI_SIEM_SLACK_WEBHOOK_URL', '')
INCLUDE_RAW_TARGETS = _env_bool('AI_SIEM_NOTIFY_INCLUDE_RAW_TARGETS', False)
DEBOUNCE_SECONDS = _bounded_int(
    'AI_SIEM_NOTIFY_DEBOUNCE_SECONDS', 900, 1, 86_400
)
CIRCUIT_FAILURE_THRESHOLD = _bounded_int(
    'AI_SIEM_NOTIFY_CIRCUIT_FAILURES', 5, 1, 100
)
CIRCUIT_RESET_SECONDS = _bounded_int(
    'AI_SIEM_NOTIFY_CIRCUIT_RESET_SECONDS', 300, 1, 86_400
)
QUEUE_SIZE = _bounded_int('AI_SIEM_NOTIFY_QUEUE_SIZE', 500, 1, 10_000)
MIN_SEVERITY = os.getenv('AI_SIEM_NOTIFY_MIN_SEVERITY', 'high').strip().lower()
if MIN_SEVERITY not in _SEVERITY_RANK:
    raise RuntimeError('AI_SIEM_NOTIFY_MIN_SEVERITY must be Low, Medium, High, or Critical')

CHANNELS = (
    _channel('webhook', WEBHOOK_URL),
    _channel('slack', SLACK_WEBHOOK_URL),
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def severity_is_enabled(severity: object, minimum: str = MIN_SEVERITY) -> bool:
    normalized = str(severity or '').strip().lower()
    return _SEVERITY_RANK.get(normalized, 0) >= _SEVERITY_RANK[minimum]


def _limited_text(value: object, maximum: int) -> str:
    return str(value or '').replace('\r', ' ').replace('\n', ' ').strip()[:maximum]


def _sensitive_values(alert: dict[str, Any]) -> list[str]:
    values = []
    for key in ('asset', 'hostname', 'host', 'src_ip', 'dst_ip', 'user'):
        value = _limited_text(alert.get(key), 256)
        if value:
            values.append(value)
    return sorted(set(values), key=len, reverse=True)


def _redacted_text(value: object, sensitive: list[str], maximum: int) -> str:
    text = _limited_text(value, maximum)
    for item in sensitive:
        text = re.sub(re.escape(item), '[redacted]', text, flags=re.IGNORECASE)
    return _IP_ADDRESS.sub('[redacted-ip]', text)


def build_alert_payload(
    alert: dict[str, Any],
    *,
    include_raw_targets: bool = INCLUDE_RAW_TARGETS,
    reason: str = 'new_alert',
) -> dict[str, Any]:
    """Build a bounded alert payload with target data redacted by default."""
    sensitive = _sensitive_values(alert)
    alert_data: dict[str, Any] = {
        'alert_id': _limited_text(alert.get('alert_id'), 128),
        'rule_id': _limited_text(alert.get('rule_id'), 128),
        'title': _redacted_text(alert.get('title'), sensitive, 256),
        'severity': _limited_text(alert.get('severity'), 16).title(),
        'status': _limited_text(alert.get('status', 'open'), 32),
        'assigned_to': _redacted_text(
            alert.get('assigned_to', 'unassigned'), sensitive, 80
        ),
        'occurrence_count': max(1, int(alert.get('occurrence_count') or 1)),
        'due_at': _limited_text(alert.get('due_at'), 64),
    }
    if include_raw_targets:
        raw_targets = {
            key: _limited_text(alert.get(key), 256)
            for key in ('asset', 'hostname', 'host', 'src_ip', 'dst_ip', 'user')
            if alert.get(key)
        }
        alert_data['targets'] = raw_targets
    else:
        alert_data['targets_redacted'] = bool(sensitive)
    return {
        'schema_version': '1.0',
        'event': _limited_text(reason, 32) or 'new_alert',
        'sent_at': datetime.now(timezone.utc).isoformat(),
        'privacy': {
            'raw_targets_included': include_raw_targets,
            'evidence_included': False,
        },
        'alert': alert_data,
    }


def _slack_payload(payload: dict[str, Any]) -> dict[str, str]:
    alert = payload['alert']
    return {
        'text': (
            f"AI-SIEM {payload['event']}: "
            f"[{alert['severity']}] {alert['title']} "
            f"({alert['alert_id'] or 'unidentified alert'})"
        )[:3000]
    }


class NotificationService:
    """Deliver notifications with debounce, retries, and circuit breaking."""

    def __init__(
        self,
        channels: tuple[NotificationChannel, ...] = CHANNELS,
        *,
        include_raw_targets: bool = INCLUDE_RAW_TARGETS,
        debounce_seconds: int = DEBOUNCE_SECONDS,
        minimum_severity: str = MIN_SEVERITY,
        circuit_failure_threshold: int = CIRCUIT_FAILURE_THRESHOLD,
        circuit_reset_seconds: int = CIRCUIT_RESET_SECONDS,
        opener: Any = _OPENER,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        for channel in channels:
            if channel.enabled:
                validate_notification_url(channel.url)
        normalized_severity = str(minimum_severity).strip().lower()
        if normalized_severity not in _SEVERITY_RANK:
            raise ValueError('minimum_severity is invalid')
        if not 1 <= debounce_seconds <= 86_400:
            raise ValueError('debounce_seconds must be between 1 and 86400')
        if not 1 <= circuit_failure_threshold <= 100:
            raise ValueError('circuit_failure_threshold must be between 1 and 100')
        if not 1 <= circuit_reset_seconds <= 86_400:
            raise ValueError('circuit_reset_seconds must be between 1 and 86400')
        self.channels = channels
        self.include_raw_targets = include_raw_targets
        self.debounce_seconds = debounce_seconds
        self.minimum_severity = normalized_severity
        self.circuit_failure_threshold = circuit_failure_threshold
        self.circuit_reset_seconds = circuit_reset_seconds
        self.opener = opener
        self.clock = clock
        self.sleeper = sleeper
        self._lock = threading.RLock()
        self._last_delivered: dict[tuple[NotificationKind, str], float] = {}
        self._failures: dict[NotificationKind, int] = {}
        self._circuit_open_until: dict[NotificationKind, float] = {}

    def status(self) -> list[dict[str, Any]]:
        return [
            {'kind': channel.kind, 'enabled': channel.enabled}
            for channel in self.channels
        ]

    def _is_debounced(self, channel: NotificationChannel, alert_id: str) -> bool:
        with self._lock:
            last = self._last_delivered.get((channel.kind, alert_id))
            return last is not None and self.clock() - last < self.debounce_seconds

    def _circuit_open(self, channel: NotificationChannel) -> bool:
        with self._lock:
            until = self._circuit_open_until.get(channel.kind, 0.0)
            if until <= self.clock():
                self._circuit_open_until.pop(channel.kind, None)
                return False
            return True

    def _record_failure(self, channel: NotificationChannel) -> None:
        with self._lock:
            failures = self._failures.get(channel.kind, 0) + 1
            self._failures[channel.kind] = failures
            if failures >= self.circuit_failure_threshold:
                self._circuit_open_until[channel.kind] = (
                    self.clock() + self.circuit_reset_seconds
                )

    def _record_success(self, channel: NotificationChannel, alert_id: str) -> None:
        with self._lock:
            self._failures[channel.kind] = 0
            self._circuit_open_until.pop(channel.kind, None)
            self._last_delivered[(channel.kind, alert_id)] = self.clock()

    def _deliver_once(
        self, channel: NotificationChannel, payload: dict[str, Any]
    ) -> None:
        outbound = _slack_payload(payload) if channel.kind == 'slack' else payload
        data = json.dumps(outbound, separators=(',', ':'), ensure_ascii=False).encode(
            'utf-8'
        )
        if len(data) > MAX_PAYLOAD_BYTES:
            raise ValueError('Notification payload exceeded the safety limit')
        request = urllib.request.Request(
            channel.url,
            data=data,
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'ai-siem-notifier/1.0',
            },
        )
        with self.opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError('Notification response exceeded the safety limit')
            status = int(getattr(response, 'status', 200))
            if not 200 <= status < 300:
                raise RuntimeError('Notification endpoint rejected the payload')

    def _deliver(
        self, channel: NotificationChannel, payload: dict[str, Any], alert_id: str
    ) -> ChannelResult:
        if self._circuit_open(channel):
            return ChannelResult(channel.kind, 'skipped', 'circuit_open')
        for attempt in range(RETRY_COUNT + 1):
            if self._circuit_open(channel):
                return ChannelResult(channel.kind, 'skipped', 'circuit_open')
            try:
                self._deliver_once(channel, payload)
            except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
                self._record_failure(channel)
                if attempt < RETRY_COUNT and not self._circuit_open(channel):
                    self.sleeper(0.25 * (2**attempt))
                    continue
                _LOGGER.warning(
                    'notification delivery failed channel=%s error=%s',
                    channel.kind,
                    type(exc).__name__,
                )
                return ChannelResult(channel.kind, 'failed', 'delivery_failed')
            self._record_success(channel, alert_id)
            return ChannelResult(channel.kind, 'delivered', 'accepted')
        return ChannelResult(channel.kind, 'failed', 'delivery_failed')

    def send_alert_notification(
        self,
        alert: dict[str, Any],
        *,
        reason: str = 'new_alert',
        bypass_debounce: bool = False,
        bypass_severity: bool = False,
    ) -> NotificationResult:
        """Send without raising; failures never break alert processing."""
        try:
            alert_id = _limited_text(alert.get('alert_id'), 128) or 'unknown-alert'
            if not bypass_severity and not severity_is_enabled(
                alert.get('severity'), self.minimum_severity
            ):
                return NotificationResult(
                    tuple(
                        ChannelResult(channel.kind, 'skipped', 'below_minimum_severity')
                        for channel in self.channels
                    )
                )
            payload = build_alert_payload(
                alert,
                include_raw_targets=self.include_raw_targets,
                reason=reason,
            )
            results = []
            for channel in self.channels:
                if not channel.enabled:
                    results.append(
                        ChannelResult(channel.kind, 'skipped', 'not_configured')
                    )
                elif not bypass_debounce and self._is_debounced(channel, alert_id):
                    results.append(ChannelResult(channel.kind, 'skipped', 'debounced'))
                else:
                    results.append(self._deliver(channel, payload, alert_id))
            return NotificationResult(tuple(results))
        except Exception as exc:  # defensive boundary: alert processing must continue
            _LOGGER.warning(
                'notification processing failed error=%s', type(exc).__name__
            )
            return NotificationResult(
                tuple(
                    ChannelResult(channel.kind, 'failed', 'internal_error')
                    for channel in self.channels
                )
            )


class NotificationDispatcher:
    """Bounded daemon dispatcher so detection requests never wait on webhooks."""

    def __init__(self, service: NotificationService, queue_size: int = QUEUE_SIZE):
        self.service = service
        self._queue: queue.Queue[tuple[dict[str, Any], str]] = queue.Queue(
            maxsize=queue_size
        )
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._run,
                    name='ai-siem-notifications',
                    daemon=True,
                )
                self._worker.start()

    def enqueue(self, alert: dict[str, Any], reason: str = 'new_alert') -> bool:
        if not any(channel.enabled for channel in self.service.channels):
            return False
        self._ensure_worker()
        try:
            self._queue.put_nowait((dict(alert), reason))
            return True
        except queue.Full:
            _LOGGER.warning('notification queue full; alert notification dropped')
            return False

    def _run(self) -> None:
        while True:
            alert, reason = self._queue.get()
            try:
                self.service.send_alert_notification(alert, reason=reason)
            except Exception as exc:  # pragma: no cover - final daemon safety boundary
                _LOGGER.warning(
                    'notification worker failed error=%s', type(exc).__name__
                )
            finally:
                self._queue.task_done()


SERVICE = NotificationService()
DISPATCHER = NotificationDispatcher(SERVICE)


def send_alert_notification(alert: dict[str, Any]) -> NotificationResult:
    reason = _limited_text(alert.get('notification_reason'), 32) or 'new_alert'
    return SERVICE.send_alert_notification(alert, reason=reason)


def dispatch_alert_notification(
    alert: dict[str, Any], reason: str = 'new_alert'
) -> bool:
    """Queue one best-effort notification without blocking detection work."""
    try:
        return DISPATCHER.enqueue(alert, reason)
    except Exception as exc:  # defensive boundary: alert processing must continue
        _LOGGER.warning('notification enqueue failed error=%s', type(exc).__name__)
        return False


def send_test_notification() -> NotificationResult:
    return SERVICE.send_alert_notification(
        {
            'alert_id': 'TEST-NOTIFICATION',
            'rule_id': 'SYSTEM-TEST',
            'title': 'AI-SIEM notification channel test',
            'severity': 'high',
            'status': 'test',
            'assigned_to': 'system',
            'occurrence_count': 1,
        },
        reason='channel_test',
        bypass_debounce=True,
        bypass_severity=True,
    )


def notification_status() -> list[dict[str, Any]]:
    return SERVICE.status()
