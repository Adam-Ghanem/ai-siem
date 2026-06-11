#!/usr/bin/env bash
set -e
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "[AI-SIEM] Python is not installed or not available in PATH."
  exit 1
fi

cleanup() {
  echo ""
  echo "[AI-SIEM] Stopping services..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[AI-SIEM] Using Python: $PYTHON_BIN"
echo "[AI-SIEM] Starting backend on http://localhost:8000"
(cd "$ROOT_DIR/backend" && "$PYTHON_BIN" main.py) &
BACKEND_PID=$!

sleep 1

echo "[AI-SIEM] Starting frontend on http://localhost:5173"
(cd "$ROOT_DIR/frontend" && "$PYTHON_BIN" -m http.server 5173) &
FRONTEND_PID=$!

sleep 1

echo ""
echo "AI-SIEM is running:"
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:8000/api"
echo ""
echo "Open http://localhost:5173 in your browser."
echo "Press CTRL+C to stop."
wait
