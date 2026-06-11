from app.parsers import parse_log
from app.detection import detect
from app.correlation import correlate
from app.anomaly import detect_anomalies

def test_linux_parser_and_bruteforce():
    logs = [f'Jun 11 10:00:0{i} host1 sshd[12{i}]: Failed password for invalid user root from 8.8.8.8 port 55{i} ssh2' for i in range(6)]
    events = [parse_log(x) for x in logs]
    assert events[0].source == 'linux_auth'
    alerts = detect(events)
    assert any(a.rule_id == 'DET-SSH-001' for a in alerts)

def test_powershell_detection():
    event = parse_log('WinEvent Time=2026-06-11T10:00:00Z Host=win01 EventID=4104 User=adam Process=powershell.exe CommandLine="powershell -NoP -enc AAA"')
    alerts = detect([event])
    assert any(a.rule_id == 'DET-PS-001' for a in alerts)

def test_correlation_and_anomaly():
    e = parse_log('Jun 11 23:01:00 jumpbox01 sshd[1]: Accepted password for root from 10.0.0.5 port 4444 ssh2')
    alerts = detect([e])
    incidents = correlate(alerts)
    anomalies = detect_anomalies([e])
    assert incidents or anomalies
