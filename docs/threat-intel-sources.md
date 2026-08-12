# Threat Intelligence Integration Sources

## AbuseIPDB

Official APIv2 documentation: https://docs.abuseipdb.com/

The documented check endpoint is `GET https://api.abuseipdb.com/api/v2/check` with the `Key` header, `Accept: application/json`, and query parameters including `ipAddress` and optional `maxAgeInDays`. The response places indicator information under `data`, including `abuseConfidenceScore`, `countryCode`, `usageType`, `isTor`, `totalReports`, and `lastReportedAt`. The official documentation states that `maxAgeInDays` is bounded from 1 to 365 and defaults to 30. The current integration uses a bounded 90-day lookup, a fixed HTTPS endpoint, a short timeout, and returns only a small normalized subset rather than raw provider reports.

The archived API page also states that free accounts have a daily request limit and that API keys should be protected like passwords: https://www.abuseipdb.com/api.html

## AlienVault OTX / LevelBlue Open Threat Exchange

Official DirectConnect API documentation: https://otx.alienvault.com/assets/static/external_api.html

The documented indicator endpoints include `/api/v1/indicators/IPv4/{ip}/{section}` and `/api/v1/indicators/IPv6/{ip}/{section}`. The current integration uses the `general` section, selects the IPv4 or IPv6 family from validated input, optionally sends `X-OTX-API-KEY`, and normalizes pulse count, reputation, and available sections. It does not submit URLs, files, or pulses and therefore avoids side-effecting provider operations.

## Integration Security Decisions

Only globally routable IPs are sent to providers. Provider URLs are constants rather than user-controlled URLs. Requests have a short timeout, bounded response reads, a small LRU-like TTL cache, and provider failure fallback. API keys are read from environment variables and are never returned in responses or written to audit details. The feature is opt-in per provider and does not block ingestion or detection when a provider is disabled or unavailable.
