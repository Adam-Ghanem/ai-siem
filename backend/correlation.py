from __future__ import annotations
from hashlib import sha1
from .models import Alert, Incident
W={'critical':4,'high':3,'medium':2,'low':1}
def _rel(a,b):
    close=abs((a.timestamp-b.timestamp).total_seconds())<=1800
    return close and any([a.asset and a.asset==b.asset,a.user and a.user==b.user,a.src_ip and a.src_ip==b.src_ip,a.tactic==b.tactic])
def _prio(group):
    s=sum(W.get(a.severity,1) for a in group)
    return 'P1' if any(a.severity=='critical' for a in group) or s>=8 else 'P2' if any(a.severity=='high' for a in group) or s>=5 else 'P3'
def _stable_incident_id(group:list[Alert])->str:
    parts=[]
    for a in sorted(group, key=lambda x: x.alert_id):
        parts.extend([a.alert_id, a.rule_id, ','.join(sorted(a.event_ids)), a.asset or '', a.user or '', a.src_ip or ''])
    return 'INC-' + sha1('|'.join(parts).encode('utf-8')).hexdigest()[:10].upper()
def correlate(alerts:list[Alert])->list[Incident]:
    used=set(); inc=[]; alerts=sorted(alerts,key=lambda a:a.timestamp)
    for a in alerts:
        if a.alert_id in used: continue
        g=[a]; used.add(a.alert_id); changed=True
        while changed:
            changed=False
            for b in alerts:
                if b.alert_id not in used and any(_rel(b,x) for x in g): g.append(b); used.add(b.alert_id); changed=True
        title=g[0].title if len(g)==1 else 'Correlated SOC activity: '+', '.join(sorted({x.tactic for x in g}))
        inc.append(Incident(_stable_incident_id(g),title,_prio(g),'open','unassigned',[x.alert_id for x in g],sorted({x.asset for x in g if x.asset}),sorted({x.user for x in g if x.user}),sorted({x.src_ip for x in g if x.src_ip}),' | '.join(sorted({x.title for x in g})),[{'timestamp':x.timestamp.isoformat(),'alert_id':x.alert_id,'title':x.title,'severity':x.severity,'asset':x.asset,'user':x.user,'src_ip':x.src_ip,'tactic':x.tactic} for x in g],sorted({x.recommended_action for x in g})))
    return inc
