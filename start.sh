#!/usr/bin/env bash
set -e
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  echo ""
  echo "[AI-SIEM] Stopping services..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[AI-SIEM] Starting backend on http://localhost:8000"
(cd "$ROOT_DIR/backend" && python main.py) &
BACKEND_PID=$!

sleep 1

echo "[AI-SIEM] Starting frontend on http://localhost:5173"
(cd "$ROOT_DIR/frontend" && python -m http.server 5173) &
FRONTEND_PID=$!

echo ""
echo "AI-SIEM is running:"
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:8000/api"
echo ""
echo "Press CTRL+C to stop."
wait
