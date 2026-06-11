DETECTIONS = [
    {"id": "DET-001", "name": "SSH Brute Force", "severity": "High", "tactic": "Credential Access", "technique": "T1110", "keywords": ["failed ssh", "brute force"]},
    {"id": "DET-002", "name": "Suspicious PowerShell", "severity": "High", "tactic": "Execution", "technique": "T1059.001", "keywords": ["powershell", "encoded command"]},
    {"id": "DET-003", "name": "Port Scan", "severity": "Medium", "tactic": "Discovery", "technique": "T1046", "keywords": ["port scan"]},
    {"id": "DET-004", "name": "Admin Account Created", "severity": "High", "tactic": "Persistence", "technique": "T1136", "keywords": ["admin account"]},
    {"id": "DET-005", "name": "SQL Injection Attempt", "severity": "High", "tactic": "Initial Access", "technique": "T1190", "keywords": ["sql injection", "sqli"]},
]


def match_detection(event):
    message = event.get("message", "").lower()
    for detection in DETECTIONS:
        if any(keyword in message for keyword in detection["keywords"]):
            return detection
    return None


def severity_to_status(severity, name):
    if name == "SSH Brute Force":
        return "New"
    if severity == "High":
        return "Investigating"
    return "Contained"


def severity_to_confidence(severity, name):
    if name == "SSH Brute Force":
        return 94
    if severity == "High":
        return 86
    return 76


def generate_alerts(events):
    alerts = []
    for idx, event in enumerate(events, 1):
        detection = match_detection(event)
        if not detection:
            continue
        severity = "Critical" if detection["name"] == "SSH Brute Force" else detection["severity"]
        alerts.append({
            "id": f"ALT-{1040 + idx}",
            "title": event.get("title", detection["name"]),
            "severity": severity,
            "confidence": severity_to_confidence(detection["severity"], detection["name"]),
            "source": event.get("source", "unknown"),
            "asset": event.get("asset", "unknown"),
            "tactic": detection["tactic"],
            "technique": detection["technique"],
            "status": severity_to_status(detection["severity"], detection["name"]),
            "timestamp": event.get("timestamp"),
            "recommendation": event.get("recommendation", "Review evidence and escalate if confirmed."),
        })
    return alerts
