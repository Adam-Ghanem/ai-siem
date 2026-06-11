from __future__ import annotations
from datetime import datetime, timezone, timedelta

def sample_logs() -> list[str]:
    logs: list[str] = []
    base = datetime(2026, 6, 11, 9, 0, tzinfo=timezone.utc)
    users = ['adam','meryem','soc1','root']
    for i in range(80):
        t = base + timedelta(minutes=i)
        host = 'linux-app01' if i % 2 else 'jumpbox01'
        user = users[i % len(users)]
        ip = f'10.10.1.{10 + i % 60}'
        logs.append(t.strftime(f'%b %d %H:%M:%S {host} sshd[{2200+i}]: Accepted password for {user} from {ip} port {40000+i} ssh2'))
    for i in range(6):
        logs.append(f'Jun 11 11:00:0{i} linux-app01 sshd[31{i}]: Failed password for invalid user oracle from 185.199.88.10 port 5500{i} ssh2')
    logs.append('Jun 11 11:01:00 linux-app01 sshd[3200]: Accepted password for oracle from 185.199.88.10 port 55100 ssh2')
    logs.append('Jun 11 23:15:00 jumpbox01 sshd[9001]: Accepted password for root from 10.10.1.50 port 59001 ssh2')
    logs.append('WinEvent Time=2026-06-11T12:06:00Z Host=win10-fin01 EventID=4104 User=adam Process=powershell.exe CommandLine="powershell.exe -NoP -W Hidden -enc SQBFAFgA" Message="PowerShell ScriptBlock"')
    logs.append('WinEvent Time=2026-06-11T12:10:00Z Host=dc01 EventID=4720 User=administrator Process=lsass.exe CommandLine="created local admin svc-backup" Message="A user account was created and added to administrators"')
    for p in range(20, 32):
        logs.append(f'2026-06-11T14:00:{p-20:02d}Z edge-fw01 FW action=DENY src=45.83.10.23 dst=10.10.2.15 dpt={p} proto=TCP msg="blocked inbound connection dpt={p}"')
    for i in range(30):
        logs.append(f'10.10.1.{20+i} - - [11/Jun/2026:15:{i:02d}:00 +0000] "GET /api/status HTTP/1.1" 200 512 "Mozilla/5.0"')
    logs.append('203.0.113.45 - - [11/Jun/2026:15:40:00 +0000] "GET /login?user=admin%27%20or%20%271%27=%271 HTTP/1.1" 403 123 "sqlmap"')
    logs.append('203.0.113.45 - - [11/Jun/2026:15:41:00 +0000] "GET /search?q=1%20union%20select%20password%20from%20users HTTP/1.1" 403 123 "sqlmap"')
    return logs
