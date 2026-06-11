import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, CURRENT_DIR)

from engine.parser import normalize_events
from engine.detections import DETECTIONS, generate_alerts
from engine.correlation import correlate_incidents, calculate_risk_score
from engine.triage import select_highest_risk_alert, build_triage

HOST = '0.0.0.0'
PORT = 8000


def load_json(path, fallback):
    try:
        with open(os.path.join(ROOT, path), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return fallback


def load_logs():
    return normalize_events(load_json('data/sample_logs.json', []))


def build_alerts():
    return generate_alerts(load_logs())


def build_incidents():
    return correlate_incidents(build_alerts())


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
    logs = load_logs()
    alerts = build_alerts()
    incidents = build_incidents()
    return {
        'total_events': len(logs) * 8500 + 700,
        'critical_alerts': len([a for a in alerts if a['severity'] == 'Critical']),
        'open_incidents': len(incidents),
        'risk_score': calculate_risk_score(alerts, incidents),
        'mean_time_to_respond': '17m',
    }


def triage(payload):
    alerts = build_alerts()
    alert_id = payload.get('alert_id') if isinstance(payload, dict) else None
    selected = None
    if alert_id:
        selected = next((alert for alert in alerts if alert.get('id') == alert_id), None)
    if not selected:
        selected = select_highest_risk_alert(alerts)
    return build_triage(selected)


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
            return self.send_json({
                'service': 'AI-SIEM API',
                'status': 'healthy',
                'time': datetime.now(timezone.utc).isoformat(),
                'endpoints': ['/api/health', '/api/metrics', '/api/logs', '/api/alerts', '/api/incidents', '/api/detections', '/api/parsers', '/api/dashboards', '/api/workflows', '/api/triage'],
            })
        if path == '/api/health': return self.send_json({'status': 'healthy'})
        if path == '/api/metrics': return self.send_json(metrics())
        if path == '/api/logs': return self.send_json(load_logs())
        if path == '/api/alerts': return self.send_json(build_alerts())
        if path == '/api/incidents': return self.send_json(build_incidents())
        if path == '/api/detections': return self.send_json([{k: v for k, v in item.items() if k != 'keywords'} for item in DETECTIONS])
        if path == '/api/parsers': return self.send_json(['linux_auth', 'windows_event', 'firewall_syslog', 'cloudtrail'])
        if path == '/api/dashboards': return self.send_json(['soc_overview', 'mitre_coverage', 'incident_response'])
        if path == '/api/workflows': return self.send_json(workflows())
        if path == '/api/integrations': return self.send_json(integrations())
        if path == '/api/rules': return self.send_json([{k: v for k, v in item.items() if k != 'keywords'} for item in DETECTIONS])
        if path == '/api/reports/summary': return self.send_json({'title': 'Weekly SOC Summary', 'critical_findings': 3, 'open_incidents': len(build_incidents()), 'top_tactic': 'Credential Access'})
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
