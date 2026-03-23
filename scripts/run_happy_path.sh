#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$ROOT_DIR/scripts/server.log"
BASE_URL="${BASE_URL:-http://localhost:8080}"
ROUNDS="${ROUNDS:-3}"
EXPECT_MODE="${EXPECT_MODE:-plain}"
EXPECT_BACKEND="${EXPECT_BACKEND:-auto}"

# 根据 EXPECT_MODE / EXPECT_BACKEND 推导服务端真正要用的环境变量
SERVER_EVALUATOR_MODE="$EXPECT_MODE"
SERVER_SECURE_BACKEND_MODE=""

if [[ "$EXPECT_MODE" == "secure_orchestrating" ]]; then
  if [[ "$EXPECT_BACKEND" == "auto" || -z "$EXPECT_BACKEND" ]]; then
    SERVER_SECURE_BACKEND_MODE="mock_mpc"
  else
    SERVER_SECURE_BACKEND_MODE="$EXPECT_BACKEND"
  fi
fi

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "$ROOT_DIR"

if [[ "$EXPECT_MODE" == "secure_orchestrating" ]]; then
  EVALUATOR_MODE="$SERVER_EVALUATOR_MODE" \
  SECURE_BACKEND_MODE="$SERVER_SECURE_BACKEND_MODE" \
  nohup go run ./cmd/server > "$LOG_FILE" 2>&1 &
else
  EVALUATOR_MODE="$SERVER_EVALUATOR_MODE" \
  nohup go run ./cmd/server > "$LOG_FILE" 2>&1 &
fi

SERVER_PID=$!

echo "govauth server started with PID=$SERVER_PID"
echo "waiting for $BASE_URL/healthz ..."
echo "happy path expect mode: $EXPECT_MODE"
echo "happy path expect backend: $EXPECT_BACKEND"
echo "server evaluator mode: $SERVER_EVALUATOR_MODE"
if [[ -n "$SERVER_SECURE_BACKEND_MODE" ]]; then
  echo "server secure backend mode: $SERVER_SECURE_BACKEND_MODE"
fi

for _ in $(seq 1 30); do
  if curl -s "$BASE_URL/healthz" >/dev/null 2>&1; then
    echo "server is ready"
    python3 "$ROOT_DIR/scripts/happy_path_runner.py" \
      --base-url "$BASE_URL" \
      --rounds "$ROUNDS" \
      --expect-mode "$EXPECT_MODE" \
      --expect-backend "$EXPECT_BACKEND"
    exit 0
  fi
  sleep 1
done

echo "server did not become ready in time. please check $LOG_FILE"
exit 1