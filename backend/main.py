import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = '0.0.0.0'
PORT = 8000


def load_json(path, fallback):
    try:
        with open(os.path.join(ROOT, path), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return fallback


LOGS = load_json('data/sample_logs.json', [])

DETECTIONS = [
    {'id': 'DET-001', 'name': 'SSH Brute Force', 'severity': 'High', 'tactic': 'Credential Access', 'technique': 'T1110'},
    {'id': 'DET-002', 'name': 'Suspicious PowerShell', 'severity': 'High', 'tactic': 'Execution', 'technique': 'T1059.001'},
    {'id': 'DET-003', 'name': 'Port Scan', 'severity': 'Medium', 'tactic': 'Discovery', 'technique': 'T1046'},
    {'id': 'DET-004', 'name': 'Admin Account Created', 'severity': 'High', 'tactic': 'Persistence', 'technique': 'T1136'},
    {'id': 'DET-005', 'name': 'SQL Injection Attempt', 'severity': 'High', 'tactic': 'Initial Access', 'technique': 'T1190'},
]


def build_alerts():
    alerts = []
    for idx, event in enumerate(LOGS, 1):
        message = event.get('message', '').lower()
        source = event.get('source', 'unknown')
        asset = event.get('asset', 'unknown')
        if 'failed ssh' in message or 'brute force' in message:
            rule = DETECTIONS[0]
            status = 'New'
            confidence = 94
        elif 'powershell' in message:
            rule = DETECTIONS[1]
            status = 'Investigating'
            confidence = 88
        elif 'port scan' in message:
            rule = DETECTIONS[2]
            status = 'Contained'
            confidence = 76
        elif 'admin account' in message:
            rule = DETECTIONS[3]
            status = 'Escalated'
            confidence = 82
        elif 'sql injection' in message or 'sqli' in message:
            rule = DETECTIONS[4]
            status = 'New'
            confidence = 84
        else:
            continue
        alerts.append({
            'id': f'ALT-{1040 + idx}',
            'title': event.get('title', rule['name']),
            'severity': 'Critical' if rule['name'] == 'SSH Brute Force' else rule['severity'],
            'confidence': confidence,
            'source': source,
            'asset': asset,
            'tactic': rule['tactic'],
            'technique': rule['technique'],
            'status': status,
            'timestamp': event.get('timestamp'),
            'recommendation': event.get('recommendation', 'Review evidence, validate asset context, and escalate if confirmed.'),
        })
    return alerts


def build_incidents():
    return [
        {'id': 'INC-219', 'title': 'Suspected brute-force campaign', 'priority': 'P1', 'status': 'Investigating', 'owner': 'SOC L1', 'related_alerts': 14},
        {'id': 'INC-218', 'title': 'PowerShell execution chain', 'priority': 'P2', 'status': 'Containment', 'owner': 'SOC L2', 'related_alerts': 6},
        {'id': 'INC-217', 'title': 'Identity privilege change', 'priority': 'P2', 'status': 'Review', 'owner': 'IR Team', 'related_alerts': 4},
    ]


def integrations():
    return [
        {'name': 'Microsoft Defender', 'category': 'Endpoint', 'status': 'Healthy', 'events_per_second': 320},
        {'name': 'Fortinet Firewall', 'category': 'Firewall', 'status': 'Healthy', 'events_per_second': 540},
        {'name': 'Azure AD', 'category': 'Identity', 'status': 'Degraded', 'events_per_second': 180},
        {'name': 'AWS CloudTrail', 'category': 'Cloud', 'status': 'Healthy', 'events_per_second': 210},
        {'name': 'Syslog Collector', 'category': 'Custom', 'status': 'Healthy', 'events_per_second': 740},
    ]


def workflows():
    return [
        {'name': 'Block IP', 'action': 'Firewall containment', 'status': 'Ready'},
        {'name': 'Isolate Host', 'action': 'Endpoint containment', 'status': 'Ready'},
        {'name': 'Reset User Password', 'action': 'Identity response', 'status': 'Ready'},
    ]


def metrics():
    alerts = build_alerts()
    return {
        'total_events': len(LOGS) * 8500 + 700,
        'critical_alerts': len([a for a in alerts if a['severity'] == 'Critical']),
        'open_incidents': len(build_incidents()),
        'risk_score': 72,
        'mean_time_to_respond': '17m',
    }


def triage(payload):
    alerts = build_alerts()
    top = sorted(alerts, key=lambda x: (x['severity'] == 'Critical', x['confidence']), reverse=True)[0]
    return {
        'alert_id': top['id'],
        'severity': top['severity'],
        'assessment': f"{top['title']} detected on {top['asset']} from {top['source']}. Confidence is {top['confidence']}%.",
        'mitre_tactic': top['tactic'],
        'mitre_technique': top['technique'],
        'recommended_actions': [top['recommendation'], 'Validate affected asset and user context', 'Check related alerts and recent authentication activity', 'Document response actions in the incident record'],
    }


class Handler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_json({}, 200)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ['/', '/api']:
            return self.send_json({'service': 'AI-SIEM API', 'status': 'healthy', 'time': datetime.now(timezone.utc).isoformat()})
        if path == '/api/health': return self.send_json({'status': 'healthy'})
        if path == '/api/metrics': return self.send_json(metrics())
        if path == '/api/logs': return self.send_json(LOGS)
        if path == '/api/alerts': return self.send_json(build_alerts())
        if path == '/api/incidents': return self.send_json(build_incidents())
        if path == '/api/detections': return self.send_json(DETECTIONS)
        if path == '/api/parsers': return self.send_json(['linux_auth', 'windows_event', 'firewall_syslog', 'cloudtrail'])
        if path == '/api/dashboards': return self.send_json(['soc_overview', 'mitre_coverage', 'incident_response'])
        if path == '/api/workflows': return self.send_json(workflows())
        if path == '/api/integrations': return self.send_json(integrations())
        if path == '/api/rules': return self.send_json(DETECTIONS)
        if path == '/api/reports/summary': return self.send_json({'title': 'Weekly SOC Summary', 'critical_findings': 3, 'open_incidents': 3, 'top_tactic': 'Credential Access'})
        return self.send_json({'error': 'not found', 'path': path}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length).decode('utf-8') if length else '{}'
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {}
        if urlparse(self.path).path == '/api/triage':
            return self.send_json(triage(payload))
        return self.send_json({'error': 'not found'}, 404)

    def log_message(self, fmt, *args):
        return


if __name__ == '__main__':
    print('AI-SIEM backend running on http://localhost:8000')
    print('API index: http://localhost:8000/api')
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
