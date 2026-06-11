from __future__ import annotations
from collections import Counter, defaultdict
from statistics import mean, pstdev
from uuid import uuid4
from .models import NormalizedEvent, Anomaly

def _z(value: float, values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    sd = pstdev(values)
    return 0.0 if sd == 0 else (value - mean(values)) / sd

def detect_anomalies(events: list[NormalizedEvent]) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    failures = Counter()
    seen_src_by_user = defaultdict(set)
    by_asset = Counter()

    for i, e in enumerate(events):
        if e.asset:
            by_asset[e.asset] += 1
        if e.event_type == 'ssh_login' and e.status == 'failure' and e.user:
            failures[e.user] += 1
        if e.user and e.src_ip and e.status == 'success':
            if seen_src_by_user[e.user] and e.src_ip not in seen_src_by_user[e.user]:
                anomalies.append(Anomaly(anomaly_id=f"AN-{uuid4().hex[:8]}", timestamp=e.timestamp, entity=e.user, anomaly_score=0.72, reason=f"Rare source IP {e.src_ip} for user {e.user}", contributing_features={'user': e.user, 'src_ip': e.src_ip, 'known_sources': sorted(seen_src_by_user[e.user])}, recommended_analyst_action='Verify travel/VPN context and check for credential compromise.', related_event_ids=[f'EV-{i:06d}']))
            seen_src_by_user[e.user].add(e.src_ip)
        if e.user in {'root','admin','administrator'} and e.status == 'success' and (e.timestamp.hour < 7 or e.timestamp.hour > 20):
            anomalies.append(Anomaly(anomaly_id=f"AN-{uuid4().hex[:8]}", timestamp=e.timestamp, entity=e.user, anomaly_score=0.76, reason='Privileged access outside business hours', contributing_features={'hour': e.timestamp.hour, 'asset': e.asset, 'src_ip': e.src_ip}, recommended_analyst_action='Confirm approval and review session activity.', related_event_ids=[f'EV-{i:06d}']))

    values = list(failures.values())
    for user, count in failures.items():
        score = _z(count, values)
        if count >= 5 and score >= 1.0:
            anomalies.append(Anomaly(anomaly_id=f"AN-{uuid4().hex[:8]}", timestamp=max(e.timestamp for e in events if e.user == user), entity=user, anomaly_score=min(0.99, 0.55 + score/5), reason=f'Abnormal failed-login volume for {user}', contributing_features={'failed_logins': count, 'z_score': round(score, 2)}, recommended_analyst_action='Check for brute force or password spraying.'))

    asset_counts = list(by_asset.values())
    for asset, count in by_asset.items():
        score = _z(count, asset_counts)
        if count >= 25 and score >= 1.0:
            anomalies.append(Anomaly(anomaly_id=f"AN-{uuid4().hex[:8]}", timestamp=max(e.timestamp for e in events if e.asset == asset), entity=asset, anomaly_score=min(0.95, 0.5 + score/5), reason=f'Unusual event frequency for asset {asset}', contributing_features={'event_count': count, 'z_score': round(score, 2)}, recommended_analyst_action='Review whether this is scan, outage, noisy service, or incident.'))
    return anomalies
