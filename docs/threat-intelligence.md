# Threat Intelligence Enrichment

AI-SIEM can enrich network observables from a local JSON threat-intelligence feed without sending telemetry to an external service.

## Configure the feed

By default the backend loads `data/threat_intel.json`. Override the path with:

```bash
AI_SIEM_THREAT_INTEL_FILE=/secure/path/threat_intel.json
```

The file accepts either a JSON array or an object with an `indicators` array.

```json
{
  "indicators": [
    {
      "indicator": "203.0.113.10",
      "type": "ip",
      "source": "internal-feed",
      "confidence": 90,
      "severity": "high",
      "tags": ["c2"],
      "description": "Example schema only",
      "first_seen": "2026-08-31T00:00:00Z",
      "last_seen": "2026-08-31T00:00:00Z"
    }
  ]
}
```

Do not treat the example value as a production indicator. Populate the feed from trusted internal or licensed threat-intelligence sources.

## API

- `GET /api/threat-intel/lookup?indicator=<observable>` aggregates all matches for one observable.
- `GET /api/threat-intel/stats` reports loaded indicator, entry, and source counts.
- `GET /api/events/{event_id}/threat-intel` enriches the source and destination IPs associated with one event.
- `GET /api/incidents/{incident_id}/investigation` includes `threat_intelligence` matches for the incident's supporting events.

All threat-intelligence endpoints inherit the existing API authentication and rate-limiting middleware.

## Feed behavior

Entries missing an indicator or source are ignored. Confidence values are bounded to `0..100`. Severity is normalized to `unknown`, `low`, `medium`, `high`, or `critical`. Multiple sources for the same indicator are aggregated while individual matches remain available for evidence review.
