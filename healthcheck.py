import json
import urllib.request

ENDPOINTS = [
    "http://localhost:8000/api/health",
    "http://localhost:8000/api/metrics",
    "http://localhost:8000/api/alerts",
    "http://localhost:8000/api/incidents",
]

ok = True
for url in ENDPOINTS:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
            print(f"[OK] {url} -> {type(data).__name__}")
    except Exception as exc:
        ok = False
        print(f"[FAIL] {url} -> {exc}")

if not ok:
    raise SystemExit(1)

print("AI-SIEM backend healthcheck passed.")
