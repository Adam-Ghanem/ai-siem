def select_highest_risk_alert(alerts):
    if not alerts:
        return None
    return sorted(
        alerts,
        key=lambda alert: (alert.get("severity") == "Critical", alert.get("confidence", 0)),
        reverse=True,
    )[0]


def build_triage(alert):
    if not alert:
        return {
            "alert_id": "N/A",
            "severity": "None",
            "assessment": "No active alerts are available for triage.",
            "mitre_tactic": "N/A",
            "mitre_technique": "N/A",
            "recommended_actions": ["Continue monitoring."],
        }

    return {
        "alert_id": alert["id"],
        "severity": alert["severity"],
        "assessment": f"{alert['title']} detected on {alert['asset']} from {alert['source']}. Confidence is {alert['confidence']}%.",
        "mitre_tactic": alert["tactic"],
        "mitre_technique": alert["technique"],
        "recommended_actions": [
            alert.get("recommendation", "Review evidence and escalate if confirmed."),
            "Validate affected asset and user context",
            "Check related alerts and recent authentication activity",
            "Document response actions in the incident record",
        ],
    }
