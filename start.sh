#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_PID=""
FRONTEND_PID=""

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "[AI-SIEM] Python is not installed or not available in PATH."
  exit 1
fi

if [[ -z "${AI_SIEM_API_KEY:-}" && -z "${AI_SIEM_ADMIN_KEY:-}" && -z "${AI_SIEM_OPERATOR_KEY:-}" && -z "${AI_SIEM_VIEWER_KEY:-}" ]]; then
  echo "[AI-SIEM] Configure at least one API key before starting."
  exit 1
fi

if ! "$PYTHON_BIN" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  echo "[AI-SIEM] Dependencies are missing. Run: $PYTHON_BIN -m pip install -r requirements.txt"
  exit 1
fi

cleanup() {
  echo ""
  echo "[AI-SIEM] Stopping services..."
  if [[ -n "$BACKEND_PID" ]]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
  if [[ -n "$FRONTEND_PID" ]]; then kill "$FRONTEND_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

cd "$ROOT_DIR"
BACKEND_HOST="${AI_SIEM_HOST:-127.0.0.1}"
BACKEND_PORT="${AI_SIEM_PORT:-8000}"
FRONTEND_HOST="${AI_SIEM_FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${AI_SIEM_FRONTEND_PORT:-5173}"

echo "[AI-SIEM] Using Python: $PYTHON_BIN"
echo "[AI-SIEM] Starting backend on http://$BACKEND_HOST:$BACKEND_PORT"
"$PYTHON_BIN" -m uvicorn backend.main:app \
  --host "$BACKEND_HOST" \
  --port "$BACKEND_PORT" &
BACKEND_PID=$!

for _ in {1..30}; do
  if "$PYTHON_BIN" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$BACKEND_PORT/api/health', timeout=1).read()" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "[AI-SIEM] Backend exited before becoming healthy."
    exit 1
  fi
  sleep 0.5
done

if ! "$PYTHON_BIN" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$BACKEND_PORT/api/health', timeout=1).read()" >/dev/null 2>&1; then
  echo "[AI-SIEM] Backend did not become healthy in time."
  exit 1
fi

echo "[AI-SIEM] Starting frontend on http://$FRONTEND_HOST:$FRONTEND_PORT"
"$PYTHON_BIN" -m http.server "$FRONTEND_PORT" \
  --bind "$FRONTEND_HOST" \
  --directory "$ROOT_DIR/frontend" &
FRONTEND_PID=$!

echo ""
echo "AI-SIEM is running:"
echo "Frontend: http://$FRONTEND_HOST:$FRONTEND_PORT"
echo "Backend:  http://$BACKEND_HOST:$BACKEND_PORT/api"
echo ""
echo "Press CTRL+C to stop."
wait
