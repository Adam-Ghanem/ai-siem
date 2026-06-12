from __future__ import annotations
from collections import Counter, defaultdict
from statistics import mean, pstdev
from uuid import uuid4
from .models import Anomaly, Event

def _z(v, vals):
    if len(vals)<2: return 0.0
    sd=pstdev(vals)
    return 0.0 if sd==0 else max(0.0,(v-mean(vals))/sd)

def detect_anomalies(events:list[Event])->list[Anomaly]:
    out=[]; by_asset=Counter(e.asset for e in events if e.asset); fails=Counter((e.user,e.src_ip) for e in events if e.event_type=='ssh_login' and e.status=='failure'); seen_src=defaultdict(set); seen_proc=defaultdict(set)
    vals=list(by_asset.values())
    for asset,count in by_asset.items():
        z=_z(count,vals)
        if count>=25 and z>=1:
            out.append(Anomaly(f"AN-{uuid4().hex[:10]}",asset,min(.99,.55+z/5),f'Unusual event volume for asset {asset}',{'event_count':count,'z_score':round(z,2)},[e.id for e in events if e.asset==asset][:25],'Review noisy asset for scan, outage, or compromise.'))
    fvals=list(fails.values())
    for (user,src),count in fails.items():
        if count>=5:
            z=_z(count,fvals); out.append(Anomaly(f"AN-{uuid4().hex[:10]}",f'{user}@{src}',min(.98,.60+z/5),f'Abnormal failed-login volume for {user} from {src}',{'failed_logins':count,'z_score':round(z,2)},[e.id for e in events if e.user==user and e.src_ip==src and e.status=='failure'],'Investigate brute force or password spraying.'))
    for e in sorted(events,key=lambda x:x.timestamp):
        if e.user and e.src_ip and e.status=='success':
            known=seen_src[e.user]
            if known and e.src_ip not in known: out.append(Anomaly(f"AN-{uuid4().hex[:10]}",e.user,.72,f'Rare source IP {e.src_ip} for user {e.user}',{'src_ip':e.src_ip,'known_sources':sorted(known)},[e.id],'Validate VPN/travel context and check for credential theft.'))
            known.add(e.src_ip)
        if e.user in {'root','admin','administrator'} and e.status=='success' and (e.timestamp.hour<7 or e.timestamp.hour>=20): out.append(Anomaly(f"AN-{uuid4().hex[:10]}",e.user,.76,'Privileged access outside business hours',{'hour':e.timestamp.hour,'asset':e.asset,'src_ip':e.src_ip},[e.id],'Confirm approval and review session commands.'))
        if e.process_name and e.command_line:
            ent=e.user or e.asset or 'unknown'; proc=e.process_name.lower(); known=seen_proc[ent]
            if known and proc not in known and any(x in e.command_line.lower() for x in ['-enc','downloadstring','frombase64string']): out.append(Anomaly(f"AN-{uuid4().hex[:10]}",ent,.81,f'Unusual command usage: {e.process_name}',{'process':e.process_name,'command_line':e.command_line[:200]},[e.id],'Collect process tree and endpoint telemetry.'))
            known.add(proc)
    return out
