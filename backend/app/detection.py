from __future__ import annotations
from collections import defaultdict
from uuid import uuid4
from .models import NormalizedEvent, Alert
from .rules import RULES

PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')

def _alert(rule, e, evidence, title=None):
    return Alert(alert_id=f"AL-{uuid4().hex[:8]}", rule_id=rule.rule_id, title=title or rule.name, severity=rule.severity, tactic=rule.tactic, technique=rule.technique, confidence=rule.confidence, timestamp=e.timestamp, asset=e.asset, user=e.user, src_ip=e.src_ip, evidence=evidence[:8], recommended_action=_recommend(rule.rule_id))

def _recommend(rule_id: str) -> str:
    return {
        'DET-SSH-001': 'Block source IP if malicious, inspect auth logs, and enforce MFA/rate limits.',
        'DET-SSH-002': 'Validate the successful session and rotate credentials if unauthorized.',
        'DET-PS-001': 'Collect process tree, script block logs, command line, and isolate endpoint if confirmed.',
        'DET-NET-001': 'Confirm scanner ownership; otherwise block source and review firewall logs.',
        'DET-WIN-001': 'Verify change ticket and disable suspicious admin account immediately.',
        'DET-WEB-001': 'Review WAF/web logs, block source, and test vulnerable parameter.',
        'DET-AI-001': 'Verify user location/VPN and look for credential compromise.',
        'DET-AI-002': 'Confirm privileged activity was approved and review session commands.'
    }.get(rule_id, 'Review evidence and escalate if suspicious.')

def detect(events: list[NormalizedEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    failures = defaultdict(list)
    flows = defaultdict(set)

    for e in sorted(events, key=lambda x: x.timestamp):
        text = f"{e.message or ''} {e.command_line or ''} {e.raw_log}".lower()

        if e.event_type == 'ssh_login' and e.status == 'failure':
            failures[(e.src_ip, e.asset, e.user)].append(e)
            related = [x for x in failures[(e.src_ip, e.asset, e.user)] if (e.timestamp - x.timestamp).total_seconds() <= 300]
            if len(related) == 5:
                alerts.append(_alert(RULES[0], e, [x.raw_log for x in related]))

        if e.event_type == 'ssh_login' and e.status == 'success':
            prior = []
            for (src, asset, user), vals in failures.items():
                if src == e.src_ip and (user == e.user or user is None):
                    prior += [x for x in vals if 0 <= (e.timestamp - x.timestamp).total_seconds() <= 600]
            if len(prior) >= 4:
                alerts.append(_alert(RULES[1], e, [x.raw_log for x in prior] + [e.raw_log]))
            if e.src_ip and not e.src_ip.startswith(PRIVATE_PREFIXES):
                alerts.append(_alert(RULES[6], e, [e.raw_log], 'Successful login from unusual external source'))
            if e.user in {'root','admin','administrator'} and (e.timestamp.hour < 7 or e.timestamp.hour > 20):
                alerts.append(_alert(RULES[7], e, [e.raw_log], 'Off-hours privileged login'))

        if e.event_type == 'powershell' and any(k in text for k in RULES[2].keywords):
            alerts.append(_alert(RULES[2], e, [e.raw_log]))

        if e.event_type == 'network_flow' and e.src_ip and e.dst_ip:
            port = 'unknown'
            if 'dpt=' in text:
                port = text.split('dpt=')[-1].split()[0]
            key = (e.src_ip, e.dst_ip)
            flows[key].add(port)
            if len(flows[key]) == 10:
                alerts.append(_alert(RULES[3], e, [f'{e.src_ip} touched ports: {sorted(flows[key])}']))

        if e.event_type == 'account_change' and any(k in text for k in RULES[4].keywords):
            alerts.append(_alert(RULES[4], e, [e.raw_log]))

        if e.event_type == 'http_request' and any(k in text for k in RULES[5].keywords):
            alerts.append(_alert(RULES[5], e, [e.raw_log]))

    return alerts
