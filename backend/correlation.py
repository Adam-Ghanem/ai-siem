from __future__ import annotations

from hashlib import sha256

from .models import Alert, Incident

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CORRELATION_WINDOW_SECONDS = 30 * 60


def _related(first: Alert, second: Alert) -> bool:
    close_in_time = (
        abs((first.timestamp - second.timestamp).total_seconds())
        <= CORRELATION_WINDOW_SECONDS
    )
    if not close_in_time:
        return False
    return any(
        (
            first.asset and first.asset == second.asset,
            first.user and first.user == second.user,
            first.src_ip and first.src_ip == second.src_ip,
            first.tactic == second.tactic,
        )
    )


def _priority(group: list[Alert]) -> str:
    score = sum(SEVERITY_WEIGHT.get(alert.severity, 1) for alert in group)
    if any(alert.severity == "critical" for alert in group) or score >= 8:
        return "P1"
    if any(alert.severity == "high" for alert in group) or score >= 5:
        return "P2"
    return "P3"


def _stable_incident_id(group: list[Alert]) -> str:
    parts: list[str] = []
    for alert in sorted(group, key=lambda item: item.alert_id):
        parts.extend(
            [
                alert.alert_id,
                alert.rule_id,
                ",".join(sorted(alert.event_ids)),
                alert.asset or "",
                alert.user or "",
                alert.src_ip or "",
            ]
        )
    digest = sha256("|".join(parts).encode("utf-8")).hexdigest()[:10].upper()
    return f"INC-{digest}"


def correlate(alerts: list[Alert]) -> list[Incident]:
    used_alert_ids: set[str] = set()
    incidents: list[Incident] = []
    ordered_alerts = sorted(alerts, key=lambda alert: alert.timestamp)

    for alert in ordered_alerts:
        if alert.alert_id in used_alert_ids:
            continue

        group = [alert]
        used_alert_ids.add(alert.alert_id)
        changed = True
        while changed:
            changed = False
            for candidate in ordered_alerts:
                if candidate.alert_id in used_alert_ids:
                    continue
                if any(_related(candidate, grouped_alert) for grouped_alert in group):
                    group.append(candidate)
                    used_alert_ids.add(candidate.alert_id)
                    changed = True

        title = group[0].title
        if len(group) > 1:
            title = "Correlated SOC activity: " + ", ".join(
                sorted({item.tactic for item in group})
            )

        incidents.append(
            Incident(
                _stable_incident_id(group),
                title,
                _priority(group),
                "open",
                "unassigned",
                [item.alert_id for item in group],
                sorted({item.asset for item in group if item.asset}),
                sorted({item.user for item in group if item.user}),
                sorted({item.src_ip for item in group if item.src_ip}),
                " | ".join(sorted({item.title for item in group})),
                [
                    {
                        "timestamp": item.timestamp.isoformat(),
                        "alert_id": item.alert_id,
                        "title": item.title,
                        "severity": item.severity,
                        "asset": item.asset,
                        "user": item.user,
                        "src_ip": item.src_ip,
                        "tactic": item.tactic,
                    }
                    for item in group
                ],
                sorted({item.recommended_action for item in group}),
            )
        )

    return incidents
