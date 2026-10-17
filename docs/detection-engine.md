# Detection Engine

The runtime rules are defined and validated in `backend/rules.py`; the YAML files under
`detections/` are currently descriptive metadata, **not** an executable Sigma runtime.

## Network scans

- `DET-NET-001`: horizontal network scan — one source to multiple destination IPs
  over a five-minute window.
- `DET-NET-002`: vertical destination port scan — one source to multiple unique
  destination ports **on the same destination IP** over five minutes.
- Firewall syslog parsing now populates `dst_port` and `protocol` on normalized
  events, enabling vertical scan detection from real collector input.
- Repeated connections to one service on one host alone should not trigger the
  vertical scan rule. Both types require eight unique entities within the window.

## Timestamp & entity correctness

- Linux SSH source extraction supports IPv4 and IPv6 with IP address validation.
- Yearless Linux syslog timestamps choose the nearest plausible year across New
  Year boundaries; future timestamps beyond allowed skew are rejected.
- Web/Apache logs preserve and normalize their numeric timezone offset to UTC.
- Rare external-source anomalies require publicly routable IP addresses, not
  merely addresses outside RFC1918 (which previously included reserved ranges).

## Operational limits

These are evidence-driven heuristics, **not** a trained ML detection lifecycle.
Rule scoring and suppression need tuning to each environment. Live rule reload,
Sigma compilation, replay/versioning, and production-scale detection workers are
future milestones. Regression tests cover the network scan dimensions, benign
connections, syslog time parsing, and special-use IP classification.
