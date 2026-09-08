from __future__ import annotations
from collections import Counter, defaultdict
from hashlib import sha256
from statistics import mean, pstdev
from ipaddress import ip_address, ip_network
from .models import Anomaly, Event

MIN_BASELINE_SOURCES = 3
MAX_RARE_SOURCE_ANOMALIES_PER_USER = 1
MIN_RARE_SOURCE_SCORE = .80
PRIVATE_NETWORKS = (
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('fc00::/7'),
)


def _z(v, vals):
    if len(vals)<2: return 0.0
    sd=pstdev(vals)
    return 0.0 if sd==0 else max(0.0,(v-mean(vals))/sd)


def _anomaly_id(kind: str, entity: str, event_ids: list[str]) -> str:
    """Return a stable identifier for the same anomaly evidence.

    Recomputing anomaly snapshots must not manufacture new identities for an
    unchanged signal. Including the detector kind, entity, and sorted evidence
    IDs keeps IDs deterministic while separating distinct detector findings.
    """
    payload = '|'.join([kind, entity, *sorted(str(event_id) for event_id in event_ids)])
    return 'AN-' + sha256(payload.encode('utf-8')).hexdigest()[:10].upper()


def _is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or any(ip.version == network.version and ip in network for network in PRIVATE_NETWORKS)
    )


def detect_anomalies(events:list[Event])->list[Anomaly]:
    out=[]; by_asset=Counter(e.asset for e in events if e.asset); fails=Counter((e.user,e.src_ip) for e in events if e.event_type=='ssh_login' and e.status=='failure'); seen_src=defaultdict(set); seen_proc=defaultdict(set); rare_src_counts=Counter()
    vals=list(by_asset.values())
    for asset,count in by_asset.items():
        z=_z(count,vals)
        if count>=25 and z>=1:
            event_ids=[e.id for e in events if e.asset==asset][:25]
            out.append(Anomaly(_anomaly_id('asset-volume',asset,event_ids),asset,min(.99,.55+z/5),f'Unusual event volume for asset {asset}',{'event_count':count,'z_score':round(z,2)},event_ids,'Review noisy asset for scan, outage, or compromise.'))
    fvals=list(fails.values())
    for (user,src),count in fails.items():
        if count>=5:
            z=_z(count,fvals); event_ids=[e.id for e in events if e.user==user and e.src_ip==src and e.status=='failure']; entity=f'{user}@{src}'; out.append(Anomaly(_anomaly_id('failed-login-volume',entity,event_ids),entity,min(.98,.60+z/5),f'Abnormal failed-login volume for {user} from {src}',{'failed_logins':count,'z_score':round(z,2)},event_ids,'Investigate brute force or password spraying.'))
    for e in sorted(events,key=lambda x:x.timestamp):
        if e.user and e.src_ip and e.status=='success':
            known=seen_src[e.user]
            is_rare_external=_is_external_ip(e.src_ip)
            has_baseline=len(known)>=MIN_BASELINE_SOURCES
            if has_baseline and is_rare_external and e.src_ip not in known and rare_src_counts[e.user]<MAX_RARE_SOURCE_ANOMALIES_PER_USER:
                rare_src_counts[e.user]+=1
                out.append(Anomaly(_anomaly_id('rare-source',f'{e.user}@{e.src_ip}',[e.id]),e.user,MIN_RARE_SOURCE_SCORE,f'Rare source IP {e.src_ip} for user {e.user} (external)',{'src_ip':e.src_ip,'known_sources':sorted(known)},[e.id],'Validate VPN/travel context and check for credential theft.'))
            known.add(e.src_ip)
        if e.user in {'root','admin','administrator'} and e.status=='success' and (e.timestamp.hour<7 or e.timestamp.hour>=20): out.append(Anomaly(_anomaly_id('privileged-off-hours',e.user,[e.id]),e.user,.76,'Privileged access outside business hours',{'hour':e.timestamp.hour,'asset':e.asset,'src_ip':e.src_ip},[e.id],'Confirm approval and review session commands.'))
        if e.process_name and e.command_line:
            ent=e.user or e.asset or 'unknown'; proc=e.process_name.lower(); known=seen_proc[ent]
            if known and proc not in known and any(x in e.command_line.lower() for x in ['-enc','downloadstring','frombase64string']): out.append(Anomaly(_anomaly_id('unusual-command',f'{ent}:{proc}',[e.id]),ent,.81,f'Unusual command usage: {e.process_name}',{'process':e.process_name,'command_line':e.command_line[:200]},[e.id],'Collect process tree and endpoint telemetry.'))
            known.add(proc)
    return sorted(out, key=lambda a: a.anomaly_score, reverse=True)[:20]
