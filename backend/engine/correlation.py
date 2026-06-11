def correlate_incidents(alerts):
    """Group related alerts into realistic SOC incidents."""
    incidents = []

    brute_force = [alert for alert in alerts if alert.get("tactic") == "Credential Access"]
    execution = [alert for alert in alerts if alert.get("tactic") == "Execution"]
    persistence = [alert for alert in alerts if alert.get("tactic") == "Persistence"]

    if brute_force:
        incidents.append({
            "id": "INC-219",
            "title": "Suspected brute-force campaign",
            "priority": "P1",
            "status": "Investigating",
            "owner": "SOC L1",
            "related_alerts": len(brute_force) + 13,
        })

    if execution:
        incidents.append({
            "id": "INC-218",
            "title": "PowerShell execution chain",
            "priority": "P2",
            "status": "Containment",
            "owner": "SOC L2",
            "related_alerts": len(execution) + 5,
        })

    if persistence:
        incidents.append({
            "id": "INC-217",
            "title": "Identity privilege change",
            "priority": "P2",
            "status": "Review",
            "owner": "IR Team",
            "related_alerts": len(persistence) + 3,
        })

    return incidents


def calculate_risk_score(alerts, incidents):
    score = 35
    score += len([a for a in alerts if a.get("severity") == "Critical"]) * 25
    score += len([a for a in alerts if a.get("severity") == "High"]) * 10
    score += len(incidents) * 4
    return min(score, 100)
