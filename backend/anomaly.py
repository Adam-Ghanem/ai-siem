from __future__ import annotations

from collections import Counter, defaultdict
from ipaddress import ip_address
from statistics import mean, pstdev
from uuid import uuid4

from .models import Anomaly, Event

MIN_BASELINE_SOURCES = 3
MAX_RARE_SOURCE_ANOMALIES_PER_USER = 1
MIN_RARE_SOURCE_SCORE = 0.80


def _positive_z_score(value: int, values: list[int]) -> float:
    if len(values) < 2:
        return 0.0
    standard_deviation = pstdev(values)
    if standard_deviation == 0:
        return 0.0
    return max(0.0, (value - mean(values)) / standard_deviation)


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


def detect_anomalies(events: list[Event]) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    events_by_asset = Counter(event.asset for event in events if event.asset)
    failed_logins = Counter(
        (event.user, event.src_ip)
        for event in events
        if event.event_type == "ssh_login" and event.status == "failure"
    )
    known_sources: dict[str, set[str]] = defaultdict(set)
    known_processes: dict[str, set[str]] = defaultdict(set)
    rare_source_counts: Counter[str] = Counter()

    asset_counts = list(events_by_asset.values())
    for asset, count in events_by_asset.items():
        z_score = _positive_z_score(count, asset_counts)
        if count >= 25 and z_score >= 1:
            anomalies.append(
                Anomaly(
                    f"AN-{uuid4().hex[:10]}",
                    asset,
                    min(0.99, 0.55 + z_score / 5),
                    f"Unusual event volume for asset {asset}",
                    {"event_count": count, "z_score": round(z_score, 2)},
                    [event.id for event in events if event.asset == asset][:25],
                    "Review the asset for a scan, outage, or compromise.",
                )
            )

    failed_login_counts = list(failed_logins.values())
    for (user, source_ip), count in failed_logins.items():
        if count < 5:
            continue
        z_score = _positive_z_score(count, failed_login_counts)
        related_ids = [
            event.id
            for event in events
            if event.user == user
            and event.src_ip == source_ip
            and event.status == "failure"
        ]
        anomalies.append(
            Anomaly(
                f"AN-{uuid4().hex[:10]}",
                f"{user}@{source_ip}",
                min(0.98, 0.60 + z_score / 5),
                f"Abnormal failed-login volume for {user} from {source_ip}",
                {"failed_logins": count, "z_score": round(z_score, 2)},
                related_ids,
                "Investigate brute force or password spraying.",
            )
        )

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.user and event.src_ip and event.status == "success":
            sources = known_sources[event.user]
            has_baseline = len(sources) >= MIN_BASELINE_SOURCES
            is_new_external_source = event.src_ip not in sources and _is_external_ip(event.src_ip)
            under_limit = (
                rare_source_counts[event.user]
                < MAX_RARE_SOURCE_ANOMALIES_PER_USER
            )
            if has_baseline and is_new_external_source and under_limit:
                rare_source_counts[event.user] += 1
                anomalies.append(
                    Anomaly(
                        f"AN-{uuid4().hex[:10]}",
                        event.user,
                        MIN_RARE_SOURCE_SCORE,
                        f"Rare source IP {event.src_ip} for user {event.user}",
                        {
                            "src_ip": event.src_ip,
                            "known_sources": sorted(sources),
                            "external": True,
                        },
                        [event.id],
                        "Validate VPN or travel context and check for credential theft.",
                    )
                )
            sources.add(event.src_ip)

        is_privileged_user = event.user in {"root", "admin", "administrator"}
        is_off_hours = event.timestamp.hour < 7 or event.timestamp.hour >= 20
        if is_privileged_user and event.status == "success" and is_off_hours:
            anomalies.append(
                Anomaly(
                    f"AN-{uuid4().hex[:10]}",
                    event.user,
                    0.76,
                    "Privileged access outside business hours",
                    {
                        "hour": event.timestamp.hour,
                        "asset": event.asset,
                        "src_ip": event.src_ip,
                    },
                    [event.id],
                    "Confirm approval and review session commands.",
                )
            )

        if event.process_name and event.command_line:
            entity = event.user or event.asset or "unknown"
            process = event.process_name.lower()
            seen_processes = known_processes[entity]
            suspicious_arguments = ("-enc", "downloadstring", "frombase64string")
            if (
                seen_processes
                and process not in seen_processes
                and any(value in event.command_line.lower() for value in suspicious_arguments)
            ):
                anomalies.append(
                    Anomaly(
                        f"AN-{uuid4().hex[:10]}",
                        entity,
                        0.81,
                        f"Unusual command usage: {event.process_name}",
                        {
                            "process": event.process_name,
                            "command_line": event.command_line[:200],
                        },
                        [event.id],
                        "Collect the process tree and related endpoint telemetry.",
                    )
                )
            seen_processes.add(process)

    return sorted(
        anomalies,
        key=lambda anomaly: anomaly.anomaly_score,
        reverse=True,
    )[:20]
