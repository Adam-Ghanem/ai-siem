from __future__ import annotations
import re
from collections import defaultdict
from hashlib import sha256
from ipaddress import ip_address
from .models import Alert, Event
from .rules import RULES
ACTIONS={'critical':'Escalate immediately, preserve evidence, and contain if confirmed.','high':'Review evidence, validate scope, and contain if unauthorized.','medium':'Investigate context and monitor for progression.','low':'Document and monitor.'}
SUPPRESSION_MINUTES=15
MIN_BASELINE_SOURCES=3
MAX_AI_RARE_SOURCE_ALERTS_PER_USER=1

def _v(e:Event,f:str): return getattr(e,f,None)
def _key(e:Event,fields): return tuple(_v(e,f) for f in fields)
def _static(rule,e):
    for f,x in rule.get('field_equals',{}).items():
        if _v(e,f)!=x: return False
    for f,vals in rule.get('contains',{}).items():
        hay=str(_v(e,f) or '').lower()
        if vals and not any(str(v).lower() in hay for v in vals): return False
    for f,pats in rule.get('regex',{}).items():
        hay=str(_v(e,f) or '')
        if pats and not any(re.search(p,hay) for p in pats): return False
    return True

def _stable_id(prefix, *parts):
    raw='|'.join(str(p) for p in parts)
    return f"{prefix}-{sha256(raw.encode('utf-8')).hexdigest()[:10].upper()}"

def _is_external_ip(value):
    if not value: return False
    try: ip=ip_address(value)
    except ValueError: return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)

def _entity(rule,e): return (rule['rule_id'], e.src_ip, e.user, e.asset)
def _suppressed(cache, rule, event):
    ent=_entity(rule,event); last=cache.get(ent)
    if last and (event.timestamp-last).total_seconds()<SUPPRESSION_MINUTES*60: return True
    cache[ent]=event.timestamp; return False

def _alert(rule, events):
    latest=max(events,key=lambda e:e.timestamp); ev=[]
    for e in events[-10:]: ev.append('; '.join(f'{f}={_v(e,f)}' for f in ['asset','user','src_ip','dst_ip','process_name','command_line','message'] if _v(e,f)))
    return Alert(_stable_id('AL', rule['rule_id'], *[e.id for e in events]), rule['rule_id'], rule['name'], rule['severity'], rule['confidence'], rule['tactic'], rule['technique'], latest.timestamp, latest.asset, latest.user, latest.src_ip, [e.id for e in events], ev, ACTIONS.get(rule['severity'],ACTIONS['medium']))

def _sort_alerts(alerts):
    severity_rank={'critical':4,'high':3,'medium':2,'low':1}
    return sorted(alerts,key=lambda a:(severity_rank.get(a.severity,0),a.confidence,a.timestamp),reverse=True)

def run_detections(events:list[Event])->list[Alert]:
    out=[]; events=sorted(events,key=lambda e:e.timestamp); seen=set(); failures=defaultdict(list); known_src=defaultdict(set); suppression={}; ai_rare_counts=defaultdict(int)
    for i,e in enumerate(events):
        if e.event_type=='ssh_login' and e.status=='failure': failures[(e.src_ip,e.user)].append(e)
        for rule in RULES:
            if not _static(rule,e): continue
            if rule['rule_id']=='DET-SSH-002':
                prev=[x for (src,user),xs in failures.items() if src==e.src_ip and (user==e.user or user is None) for x in xs if 0 <= (e.timestamp-x.timestamp).total_seconds() <= rule['time_window_minutes']*60]
                if len(prev)>=rule['threshold'] and not _suppressed(suppression,rule,e): out.append(_alert(rule,prev+[e]))
                continue
            gf=rule.get('group_by',[]); key=_key(e,gf); window=[x for x in events[:i+1] if _static(rule,x) and _key(x,gf)==key and 0 <= (e.timestamp-x.timestamp).total_seconds() <= rule.get('time_window_minutes',1)*60]
            count=len({getattr(x,rule['distinct_field']) for x in window if getattr(x,rule['distinct_field'])}) if rule.get('distinct_field') else len(window)
            marker=(rule['rule_id'],key,e.timestamp.isoformat()[:16])
            if count>=rule.get('threshold',1) and marker not in seen and not _suppressed(suppression,rule,e): out.append(_alert(rule,window)); seen.add(marker)
        if e.event_type=='ssh_login' and e.status=='success' and e.user and e.src_ip:
            has_baseline=len(known_src[e.user])>=MIN_BASELINE_SOURCES
            is_rare_external=_is_external_ip(e.src_ip)
            if has_baseline and is_rare_external and e.src_ip not in known_src[e.user] and ai_rare_counts[e.user]<MAX_AI_RARE_SOURCE_ALERTS_PER_USER:
                rule={'rule_id':'DET-AI-001','severity':'medium'}
                if not _suppressed(suppression,rule,e):
                    ai_rare_counts[e.user]+=1
                    out.append(Alert(_stable_id('AL','DET-AI-001',e.user,e.src_ip),'DET-AI-001','Rare external source IP for user','medium',0.80,'Initial Access','T1078',e.timestamp,e.asset,e.user,e.src_ip,[e.id],[f'user={e.user}; src_ip={e.src_ip}; known={sorted(known_src[e.user])}'],'Validate VPN/travel context and check for credential compromise.'))
            known_src[e.user].add(e.src_ip)
        if e.event_type=='ssh_login' and e.status=='success' and e.user in {'root','admin','administrator'} and (e.timestamp.hour<7 or e.timestamp.hour>=20):
            rule={'rule_id':'DET-AI-002','severity':'medium'}
            if not _suppressed(suppression,rule,e): out.append(Alert(_stable_id('AL','DET-AI-002',e.id),'DET-AI-002','Off-hours privileged activity','medium',0.74,'Privilege Escalation','T1078',e.timestamp,e.asset,e.user,e.src_ip,[e.id],[e.raw_log],'Confirm approval and review session commands.'))
    return _sort_alerts(out)
