#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "[AI-SIEM] Python unavailable." >&2
  exit 1
fi
if [[ -z "${AI_SIEM_API_KEY:-}" && -z "${AI_SIEM_API_KEYS:-}" ]]; then
  echo "[AI-SIEM] Set AI_SIEM_API_KEY or AI_SIEM_API_KEYS before startup." >&2
  exit 1
fi
BACKEND_PID=""
FRONTEND_PID=""
cleanup() {
  trap - EXIT
  for pid in "$BACKEND_PID" "$FRONTEND_PID"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT INT TERM
echo "[AI-SIEM] Starting FastAPI backend..."
(cd "$ROOT_DIR" && "$PYTHON_BIN" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000) &
BACKEND_PID=$!
echo "[AI-SIEM] Starting static dashboard..."
(cd "$ROOT_DIR/frontend" && "$PYTHON_BIN" -m http.server 5173 --bind 127.0.0.1) &
FRONTEND_PID=$!
echo "Dashboard: http://localhost:5173"
echo "API: http://localhost:8000/api"
echo "Enter the API key in the dashboard Connect field."
wait -n "$BACKEND_PID" "$FRONTEND_PID"
