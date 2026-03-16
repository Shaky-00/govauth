#!/usr/bin/env bash
set -euo pipefail

# 这个脚本负责：
# 1. 在后台启动 govauth 服务；
# 2. 等待 /healthz 可访问；
# 3. 执行 invalid transition 测试脚本；
# 4. 结束后自动关闭服务。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$ROOT_DIR/scripts/server.log"
BASE_URL="${BASE_URL:-http://localhost:8080}"
ROUNDS="${ROUNDS:-3}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "$ROOT_DIR"
nohup go run ./cmd/server > "$LOG_FILE" 2>&1 &
SERVER_PID=$!

echo "govauth server started with PID=$SERVER_PID"
echo "waiting for $BASE_URL/healthz ..."

for _ in $(seq 1 30); do
  if curl -s "$BASE_URL/healthz" >/dev/null 2>&1; then
    echo "server is ready"
    python3 "$ROOT_DIR/scripts/invalid_transition_runner.py" --base-url "$BASE_URL" --rounds "$ROUNDS"
    exit 0
  fi
  sleep 1
done

echo "server did not become ready in time. please check $LOG_FILE"
exit 1
