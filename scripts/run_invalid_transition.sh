#!/usr/bin/env bash
set -euo pipefail

# 这个脚本负责：
# 1. 在后台启动 govauth 服务；
# 2. 等待 /healthz 可访问；
# 3. 执行 invalid transition 测试脚本；
# 4. 结束后自动关闭服务。
#
# 可通过环境变量控制：
# - BASE_URL: 服务地址，默认 http://localhost:8080
# - ROUNDS:   执行轮数，默认 3
# - EXPECT_MODE: 期望 evaluator 模式，默认 plain
#                可选 plain / secure_stub / secure_orchestrating
# - EXPECT_BACKEND: 期望 backend 模式，默认 auto
#                   plain 模式下通常为 local_plain
#                   secure_orchestrating 模式下通常为 mock_mpc / real_mpc

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$ROOT_DIR/scripts/server.log"
BASE_URL="${BASE_URL:-http://localhost:8080}"
ROUNDS="${ROUNDS:-3}"
EXPECT_MODE="${EXPECT_MODE:-plain}"
EXPECT_BACKEND="${EXPECT_BACKEND:-auto}"

# 根据测试期望，推导服务端真正要使用的环境变量。
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

# 启动服务时，把 evaluator/backend 模式真正传给 Go 进程。
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
echo "invalid transition expect mode: $EXPECT_MODE"
echo "invalid transition expect backend: $EXPECT_BACKEND"
echo "server evaluator mode: $SERVER_EVALUATOR_MODE"
if [[ -n "$SERVER_SECURE_BACKEND_MODE" ]]; then
  echo "server secure backend mode: $SERVER_SECURE_BACKEND_MODE"
fi

for _ in $(seq 1 30); do
  if curl -s "$BASE_URL/healthz" >/dev/null 2>&1; then
    echo "server is ready"
    python3 "$ROOT_DIR/scripts/invalid_transition_runner.py" \
      --base-url "$BASE_URL" \
      --rounds "$ROUNDS"
    exit 0
  fi
  sleep 1
done

echo "server did not become ready in time. please check $LOG_FILE"
exit 1