from __future__ import annotations

import re
from collections import defaultdict, deque
from hashlib import sha256
from ipaddress import ip_address
from typing import Mapping

from .models import Alert, Event
from .rules import RULES, Rule

ACTIONS = {
    "critical": "Escalate immediately, preserve evidence, and contain if confirmed.",
    "high": "Review evidence, validate scope, and contain if unauthorized.",
    "medium": "Investigate context and monitor for progression.",
    "low": "Document and monitor.",
}
SUPPRESSION_MINUTES = 15
MIN_BASELINE_SOURCES = 3
MAX_RARE_SOURCE_ALERTS_PER_USER = 1


def _value(event: Event, field: str):
    return getattr(event, field, None)


def _group_key(event: Event, fields: list[str]) -> tuple:
    return tuple(_value(event, field) for field in fields)


def _matches_static_conditions(rule: Rule, event: Event) -> bool:
    for field, expected in rule.get("field_equals", {}).items():
        if _value(event, field) != expected:
            return False

    for field, candidates in rule.get("contains", {}).items():
        value = str(_value(event, field) or "").lower()
        if candidates and not any(
            str(candidate).lower() in value for candidate in candidates
        ):
            return False

    for field, patterns in rule.get("regex", {}).items():
        value = str(_value(event, field) or "")
        if patterns and not any(re.search(pattern, value) for pattern in patterns):
            return False

    return True


def _stable_id(prefix: str, *parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    digest = sha256(raw.encode("utf-8")).hexdigest()[:10].upper()
    return f"{prefix}-{digest}"


def _is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    )


def _entity(rule: Mapping[str, object], event: Event) -> tuple:
    return rule["rule_id"], event.src_ip, event.user, event.asset


def _suppressed(cache: dict, rule: Mapping[str, object], event: Event) -> bool:
    entity = _entity(rule, event)
    previous = cache.get(entity)
    if (
        previous
        and (event.timestamp - previous).total_seconds() < SUPPRESSION_MINUTES * 60
    ):
        return True
    cache[entity] = event.timestamp
    return False


def _alert(rule: Rule, events: list[Event]) -> Alert:
    latest = max(events, key=lambda event: event.timestamp)
    evidence = []
    for event in events[-10:]:
        fields = (
            "asset",
            "user",
            "src_ip",
            "dst_ip",
            "process_name",
            "command_line",
            "message",
        )
        evidence.append(
            "; ".join(
                f"{field}={_value(event, field)}"
                for field in fields
                if _value(event, field)
            )
        )

    return Alert(
        _stable_id("AL", rule["rule_id"], *[event.id for event in events]),
        rule["rule_id"],
        rule["name"],
        rule["severity"],
        rule["confidence"],
        rule["tactic"],
        rule["technique"],
        latest.timestamp,
        latest.asset,
        latest.user,
        latest.src_ip,
        [event.id for event in events],
        evidence,
        ACTIONS.get(rule["severity"], ACTIONS["medium"]),
    )


def _sort_alerts(alerts: list[Alert]) -> list[Alert]:
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return sorted(
        alerts,
        key=lambda alert: (
            severity_rank.get(alert.severity, 0),
            alert.confidence,
            alert.timestamp,
        ),
        reverse=True,
    )


def run_detections(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    ordered_events = sorted(events, key=lambda event: event.timestamp)
    seen_windows: set[tuple] = set()
    failures: dict[tuple[str | None, str | None], deque[Event]] = defaultdict(deque)
    rule_windows: dict[str, dict[tuple, deque[Event]]] = {
        rule["rule_id"]: defaultdict(deque) for rule in RULES
    }
    known_sources: dict[str, set[str]] = defaultdict(set)
    suppression_cache: dict[tuple, object] = {}
    rare_source_counts: dict[str, int] = defaultdict(int)
    success_after_failure_rule = next(
        (rule for rule in RULES if rule["rule_id"] == "DET-SSH-002"),
        None,
    )
    failure_retention_seconds = (
        success_after_failure_rule["time_window_minutes"] * 60
        if success_after_failure_rule
        else 10 * 60
    )

    for event in ordered_events:
        if event.event_type == "ssh_login" and event.status == "failure":
            failure_window = failures[(event.src_ip, event.user)]
            failure_window.append(event)
            while (
                failure_window
                and (event.timestamp - failure_window[0].timestamp).total_seconds()
                > failure_retention_seconds
            ):
                failure_window.popleft()

        for rule in RULES:
            if not _matches_static_conditions(rule, event):
                continue

            if rule["rule_id"] == "DET-SSH-002":
                previous_failures: list[Event] = []
                failure_keys = {(event.src_ip, event.user), (event.src_ip, None)}
                for failure_key in failure_keys:
                    grouped_failures = failures.get(failure_key)
                    if not grouped_failures:
                        continue
                    while (
                        grouped_failures
                        and (
                            event.timestamp - grouped_failures[0].timestamp
                        ).total_seconds()
                        > rule["time_window_minutes"] * 60
                    ):
                        grouped_failures.popleft()
                    previous_failures.extend(
                        failure
                        for failure in grouped_failures
                        if failure.timestamp <= event.timestamp
                    )
                previous_failures.sort(key=lambda failure: failure.timestamp)
                if len(previous_failures) >= rule["threshold"] and not _suppressed(
                    suppression_cache, rule, event
                ):
                    alerts.append(_alert(rule, previous_failures + [event]))
                continue

            group_fields = rule.get("group_by", [])
            key = _group_key(event, group_fields)
            window = rule_windows[rule["rule_id"]][key]
            window_seconds = rule.get("time_window_minutes", 1) * 60
            while (
                window
                and (event.timestamp - window[0].timestamp).total_seconds()
                > window_seconds
            ):
                window.popleft()
            window.append(event)
            distinct_field = rule.get("distinct_field")
            if distinct_field:
                count = len(
                    {
                        getattr(candidate, distinct_field)
                        for candidate in window
                        if getattr(candidate, distinct_field)
                    }
                )
            else:
                count = len(window)

            marker = (rule["rule_id"], key, event.timestamp.isoformat()[:16])
            if (
                count >= rule.get("threshold", 1)
                and marker not in seen_windows
                and not _suppressed(suppression_cache, rule, event)
            ):
                alerts.append(_alert(rule, list(window)))
                seen_windows.add(marker)

        if (
            event.event_type == "ssh_login"
            and event.status == "success"
            and event.user
            and event.src_ip
        ):
            user_sources = known_sources[event.user]
            has_baseline = len(user_sources) >= MIN_BASELINE_SOURCES
            is_new_external_source = (
                event.src_ip not in user_sources and _is_external_ip(event.src_ip)
            )
            under_limit = (
                rare_source_counts[event.user] < MAX_RARE_SOURCE_ALERTS_PER_USER
            )
            behavior_rule = {"rule_id": "DET-BEH-001", "severity": "medium"}
            if (
                has_baseline
                and is_new_external_source
                and under_limit
                and not _suppressed(suppression_cache, behavior_rule, event)
            ):
                rare_source_counts[event.user] += 1
                alerts.append(
                    Alert(
                        _stable_id("AL", "DET-BEH-001", event.user, event.src_ip),
                        "DET-BEH-001",
                        "Rare external source IP for user",
                        "medium",
                        0.80,
                        "Initial Access",
                        "T1078",
                        event.timestamp,
                        event.asset,
                        event.user,
                        event.src_ip,
                        [event.id],
                        [
                            f"user={event.user}; src_ip={event.src_ip}; "
                            f"known={sorted(user_sources)}"
                        ],
                        "Validate VPN or travel context and check for credential compromise.",
                    )
                )
            user_sources.add(event.src_ip)

        is_privileged_login = (
            event.event_type == "ssh_login"
            and event.status == "success"
            and event.user in {"root", "admin", "administrator"}
        )
        is_off_hours = event.timestamp.hour < 7 or event.timestamp.hour >= 20
        if is_privileged_login and is_off_hours:
            behavior_rule = {"rule_id": "DET-BEH-002", "severity": "medium"}
            if not _suppressed(suppression_cache, behavior_rule, event):
                alerts.append(
                    Alert(
                        _stable_id("AL", "DET-BEH-002", event.id),
                        "DET-BEH-002",
                        "Off-hours privileged activity",
                        "medium",
                        0.74,
                        "Privilege Escalation",
                        "T1078",
                        event.timestamp,
                        event.asset,
                        event.user,
                        event.src_ip,
                        [event.id],
                        [event.raw_log],
                        "Confirm approval and review session commands.",
                    )
                )

    return _sort_alerts(alerts)
