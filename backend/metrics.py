from __future__ import annotations
from collections import Counter
from .models import Alert, Event, Incident
SW={'critical':20,'high':12,'medium':6,'low':2}; PW={'P1':25,'P2':14,'P3':6}
def calculate_metrics(events:list[Event], alerts:list[Alert], incidents:list[Incident])->dict:
    risk=min(100,sum(SW.get(a.severity,1) for a in alerts)+sum(PW.get(i.priority,1) for i in incidents if i.status=='open'))
    return {'total_events':len(events),'total_alerts':len(alerts),'critical_alerts':sum(a.severity=='critical' for a in alerts),'high_alerts':sum(a.severity=='high' for a in alerts),'open_incidents':sum(i.status=='open' for i in incidents),'risk_score':risk,'top_tactics':dict(Counter(a.tactic for a in alerts).most_common(5)),'source_distribution':dict(Counter(e.source for e in events)),'event_type_distribution':dict(Counter(e.event_type for e in events))}
