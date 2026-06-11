from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean, pstdev
from uuid import uuid4

from .event_model import Anomaly, NormalizedEvent


def _score(value: float, values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    sd = pstdev(values)
    if sd == 0:
        return 0.0
    return max(0.0, (value - mean(values)) / sd)


def detect_anomalies(events: list[NormalizedEvent]) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    by_asset = Counter(e.asset for e in events if e.asset)
    failed_by_pair = Counter((e.user, e.src_ip) for e in events if e.event_type == 'ssh_login' and e.status == 'failure')
    seen_sources: dict[str, set[str]] = defaultdict(set)
    seen_processes: dict[str, set[str]] = defaultdict(set)

    asset_counts = list(by_asset.values())
    for asset, count in by_asset.items():
        z = _score(count, asset_counts)
        if count >= 25 and z >= 1.0:
            related = [e.id for e in events if e.asset == asset][:25]
            anomalies.append(Anomaly(f"AN-{uuid4().hex[:10]}", asset, min(0.99, 0.55 + z / 5), f'Unusual event volume for asset {asset}', {'event_count': count, 'z_score': round(z, 2)}, related, 'Check for scan, noisy service, outage, or active incident.'))

    fail_values = list(failed_by_pair.values())
    for (user, src_ip), count in failed_by_pair.items():
        z = _score(count, fail_values)
        if count >= 5:
            related = [e.id for e in events if e.user == user and e.src_ip == src_ip and e.status == 'failure']
            anomalies.append(Anomaly(f"AN-{uuid4().hex[:10]}", f'{user}@{src_ip}', min(0.98, 0.60 + z / 5), f'Abnormal failed-login volume for {user} from {src_ip}', {'failed_logins': count, 'z_score': round(z, 2)}, related, 'Investigate brute force or password spraying and consider blocking source.'))

    for event in sorted(events, key=lambda e: e.timestamp):
        if event.user and event.src_ip and event.status == 'success':
            known = seen_sources[event.user]
            if known and event.src_ip not in known:
                anomalies.append(Anomaly(f"AN-{uuid4().hex[:10]}", event.user, 0.72, f'Rare source IP {event.src_ip} for user {event.user}', {'src_ip': event.src_ip, 'known_sources': sorted(known)}, [event.id], 'Validate VPN/travel context and check for credential compromise.'))
            known.add(event.src_ip)
        if event.user in {'root', 'admin', 'administrator'} and event.status == 'success' and (event.timestamp.hour < 7 or event.timestamp.hour >= 20):
            anomalies.append(Anomaly(f"AN-{uuid4().hex[:10]}", event.user or 'privileged-user', 0.76, 'Privileged access outside business hours', {'hour': event.timestamp.hour, 'asset': event.asset, 'src_ip': event.src_ip}, [event.id], 'Confirm approval and review session commands.'))
        if event.process_name and event.command_line:
            known = seen_processes[event.user or event.asset or 'unknown']
            process_key = event.process_name.lower()
            if known and process_key not in known and any(x in (event.command_line or '').lower() for x in ['-enc', 'downloadstring', 'frombase64string']):
                anomalies.append(Anomaly(f"AN-{uuid4().hex[:10]}", event.user or event.asset or 'unknown', 0.81, f'Unusual command usage: {event.process_name}', {'process': event.process_name, 'command_line': event.command_line[:200]}, [event.id], 'Collect process tree and endpoint telemetry.'))
            known.add(process_key)
    return anomalies
