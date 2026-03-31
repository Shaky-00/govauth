#!/usr/bin/env bash
set -euo pipefail

export EVALUATOR_MODE="${EVALUATOR_MODE:-strict_mpc}"
export SECURE_BACKEND_MODE="${SECURE_BACKEND_MODE:-strict_mpyc}"
export GOVAUTH_BASE_URL="${GOVAUTH_BASE_URL:-http://127.0.0.1:8080}"

mkdir -p ./tmp
echo "[start] evaluator=$EVALUATOR_MODE backend=$SECURE_BACKEND_MODE"
go run ./cmd/server 2>&1 | tee ./tmp/govauth_strict.log
