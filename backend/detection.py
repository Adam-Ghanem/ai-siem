from __future__ import annotations
import re
from collections import defaultdict
from uuid import uuid4
from .models import Alert, Event
from .rules import RULES

ACTIONS={'critical':'Escalate immediately, preserve evidence, and contain if confirmed.','high':'Review evidence, validate scope, and contain if unauthorized.','medium':'Investigate context and monitor for progression.','low':'Document and monitor.'}

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

def _alert(rule, events):
    latest=max(events,key=lambda e:e.timestamp)
    ev=[]
    for e in events[-10:]: ev.append('; '.join(f'{f}={_v(e,f)}' for f in ['asset','user','src_ip','dst_ip','process_name','command_line','message'] if _v(e,f)))
    return Alert(f"AL-{uuid4().hex[:10]}", rule['rule_id'], rule['name'], rule['severity'], rule['confidence'], rule['tactic'], rule['technique'], latest.timestamp, latest.asset, latest.user, latest.src_ip, [e.id for e in events], ev, ACTIONS.get(rule['severity'],ACTIONS['medium']))

def run_detections(events:list[Event])->list[Alert]:
    out=[]; events=sorted(events,key=lambda e:e.timestamp); seen=set(); failures=defaultdict(list); known_src=defaultdict(set)
    for i,e in enumerate(events):
        if e.event_type=='ssh_login' and e.status=='failure': failures[(e.src_ip,e.user)].append(e)
        for rule in RULES:
            if not _static(rule,e): continue
            if rule['rule_id']=='DET-SSH-002':
                prev=[x for (src,user),xs in failures.items() if src==e.src_ip and (user==e.user or user is None) for x in xs if 0 <= (e.timestamp-x.timestamp).total_seconds() <= rule['time_window_minutes']*60]
                if len(prev)>=rule['threshold']: out.append(_alert(rule,prev+[e]))
                continue
            gf=rule.get('group_by',[]); key=_key(e,gf); window=[x for x in events[:i+1] if _static(rule,x) and _key(x,gf)==key and 0 <= (e.timestamp-x.timestamp).total_seconds() <= rule.get('time_window_minutes',1)*60]
            count=len({getattr(x,rule['distinct_field']) for x in window if getattr(x,rule['distinct_field'])}) if rule.get('distinct_field') else len(window)
            marker=(rule['rule_id'],key,e.timestamp.isoformat()[:16])
            if count>=rule.get('threshold',1) and marker not in seen:
                out.append(_alert(rule,window)); seen.add(marker)
        if e.event_type=='ssh_login' and e.status=='success' and e.user and e.src_ip:
            if known_src[e.user] and e.src_ip not in known_src[e.user]:
                out.append(Alert(f"AL-{uuid4().hex[:10]}",'DET-AI-001','Rare source IP for user','medium',0.70,'Initial Access','T1078',e.timestamp,e.asset,e.user,e.src_ip,[e.id],[f'user={e.user}; src_ip={e.src_ip}; known={sorted(known_src[e.user])}'],'Validate VPN/travel context and check for credential compromise.'))
            known_src[e.user].add(e.src_ip)
        if e.event_type=='ssh_login' and e.status=='success' and e.user in {'root','admin','administrator'} and (e.timestamp.hour<7 or e.timestamp.hour>=20):
            out.append(Alert(f"AL-{uuid4().hex[:10]}",'DET-AI-002','Off-hours privileged activity','medium',0.74,'Privilege Escalation','T1078',e.timestamp,e.asset,e.user,e.src_ip,[e.id],[e.raw_log],'Confirm approval and review session commands.'))
    return out
