from datetime import datetime, timedelta, timezone
from backend.models import Event, Alert

BASE = datetime(2026, 6, 11, 10, 0, tzinfo=timezone.utc)

def event(i=0, **kwargs):
    defaults = dict(
        id=f'evt-{i}', timestamp=BASE + timedelta(seconds=i), source='linux_auth',
        event_type='ssh_login', asset='linux-app01', user='adam', src_ip='10.0.0.10',
        dst_ip=None, process_name=None, command_line=None, status='success',
        message='test event', raw_log='synthetic test event'
    )
    defaults.update(kwargs)
    return Event(**defaults)

def alert(i=0, **kwargs):
    defaults = dict(
        alert_id=f'AL-{i}', rule_id='DET-TEST', title=f'Test alert {i}', severity='high',
        confidence=0.8, tactic='Credential Access', technique='T1110', timestamp=BASE + timedelta(minutes=i),
        asset='linux-app01', user='adam', src_ip='10.0.0.10', event_ids=[f'evt-{i}'],
        evidence=[f'evidence {i}'], recommended_action='Investigate and contain if confirmed.'
    )
    defaults.update(kwargs)
    return Alert(**defaults)
