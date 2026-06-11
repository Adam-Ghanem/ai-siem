def normalize_event(event):
    """Normalize raw SOC log event into a consistent schema."""
    return {
        "timestamp": event.get("timestamp"),
        "title": event.get("title", "Untitled event"),
        "source": event.get("source", "unknown"),
        "asset": event.get("asset", "unknown"),
        "message": event.get("message", ""),
        "recommendation": event.get("recommendation", "Review evidence and escalate if confirmed."),
    }


def normalize_events(events):
    return [normalize_event(event) for event in events]
