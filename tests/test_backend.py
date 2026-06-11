import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend", "main.py")


def get_json(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    process = subprocess.Popen([sys.executable, BACKEND], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(1.5)
        health = get_json("http://localhost:8000/api/health")
        assert health["status"] == "healthy"

        metrics = get_json("http://localhost:8000/api/metrics")
        assert metrics["total_events"] > 0
        assert "risk_score" in metrics

        alerts = get_json("http://localhost:8000/api/alerts")
        assert isinstance(alerts, list)
        assert len(alerts) >= 3

        incidents = get_json("http://localhost:8000/api/incidents")
        assert isinstance(incidents, list)

        print("AI-SIEM backend smoke tests passed.")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    main()
