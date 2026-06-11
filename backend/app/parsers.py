from __future__ import annotations
import re
from datetime import datetime, timezone
from .models import NormalizedEvent

LINUX = re.compile(r"(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)")
WIN = re.compile(r"WinEvent Time=(?P<time>\S+) Host=(?P<host>\S+) EventID=(?P<eid>\d+) User=(?P<user>\S+).*?(Process=(?P<proc>\S+))?.*?(CommandLine=\"(?P<cmd>.*?)\")?")
FW = re.compile(r"(?P<time>\S+)\s+(?P<host>\S+)\s+FW action=(?P<action>\S+) src=(?P<src>\S+) dst=(?P<dst>\S+) dpt=(?P<dpt>\d+) proto=(?P<proto>\S+) msg=\"(?P<msg>.*?)\"")
WEB = re.compile(r"(?P<src>\S+) .*?\[(?P<time>.*?)\] \"(?P<method>\S+) (?P<path>\S+) (?P<proto>\S+)\" (?P<status>\d+) .*?\"(?P<ua>.*?)\"")

def _linux_time(mon: str, day: str, t: str) -> datetime:
    year = datetime.now(timezone.utc).year
    return datetime.strptime(f"{year} {mon} {day} {t}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)

def parse_log(raw: str) -> NormalizedEvent:
    if m := LINUX.search(raw):
        msg = m.group('msg')
        status = 'success' if 'Accepted password' in msg else 'failure' if 'Failed password' in msg else 'unknown'
        user = None
        if 'for invalid user' in msg:
            user = re.search(r"invalid user (\S+)", msg).group(1)
        elif ' for ' in msg:
            mm = re.search(r"for (\S+) from", msg); user = mm.group(1) if mm else None
        ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", msg)
        return NormalizedEvent(timestamp=_linux_time(m.group('mon'),m.group('day'),m.group('time')),source='linux_auth',event_type='ssh_login',asset=m.group('host'),user=user,src_ip=ip.group(1) if ip else None,status=status,message=msg,raw_log=raw)
    if m := WIN.search(raw):
        eid = m.group('eid'); cmd = m.group('cmd') or ''
        etype = 'powershell' if eid == '4104' or 'powershell' in raw.lower() else 'account_change' if eid in {'4720','4732'} else 'windows_event'
        return NormalizedEvent(timestamp=datetime.fromisoformat(m.group('time').replace('Z','+00:00')),source='windows',event_type=etype,asset=m.group('host'),user=m.group('user'),process_name=m.group('proc'),command_line=cmd,status='success',message=raw,raw_log=raw)
    if m := FW.search(raw):
        return NormalizedEvent(timestamp=datetime.fromisoformat(m.group('time').replace('Z','+00:00')),source='firewall',event_type='network_flow',asset=m.group('host'),src_ip=m.group('src'),dst_ip=m.group('dst'),status=m.group('action').lower(),message=m.group('msg') + ' dpt=' + m.group('dpt'),raw_log=raw)
    if m := WEB.search(raw):
        t = datetime.strptime(m.group('time').split()[0], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
        return NormalizedEvent(timestamp=t,source='web',event_type='http_request',asset='web01',src_ip=m.group('src'),status=m.group('status'),message=m.group('path') + ' ua=' + m.group('ua'),raw_log=raw)
    return NormalizedEvent(timestamp=datetime.now(timezone.utc),source='unknown',event_type='unknown',message=raw,raw_log=raw)
