.PHONY: run tidy test flow-test flow-quick flow-real-only

# 手动启动服务（默认给 real_mpc，便于你单独调接口）
run:
	EVALUATOR_MODE=secure_orchestrating SECURE_BACKEND_MODE=real_mpc go run ./cmd/server

# 依赖整理
tidy:
	go mod tidy

# Go 单测
test:
	go test ./...

# 一键全量测试：
# plain + mock + real
# happy + deny
# 每组默认 1 轮，尽量减少重复运行
flow-test:
	MPC_PYTHON_BIN=python3 \
	MPC_SCRIPT_PATH=tools/mpc/mpyc_eq_backend.py \
	MPC_BASE_PORT=11500 \
	MPC_TIMEOUT_SEC=30 \
	MPC_KEEP_ARTIFACTS=false \
	python3 ./scripts/policy_flow_matrix.py \
	  --modes plain,mock,real \
	  --scenarios happy,deny \
	  --rounds 1 \
	  --output scripts/policy_flow_matrix_result.json \
	  --log-dir scripts/logs

# 快速版：只测 plain + mock
flow-quick:
	MPC_PYTHON_BIN=python3 \
	MPC_SCRIPT_PATH=tools/mpc/mpyc_eq_backend.py \
	MPC_BASE_PORT=11500 \
	MPC_TIMEOUT_SEC=30 \
	MPC_KEEP_ARTIFACTS=false \
	python3 ./scripts/policy_flow_matrix.py \
	  --modes plain,mock \
	  --scenarios happy,deny \
	  --rounds 1 \
	  --output scripts/policy_flow_quick_result.json \
	  --log-dir scripts/logs

# 只测 real_mpc
flow-real-only:
	MPC_PYTHON_BIN=python3 \
	MPC_SCRIPT_PATH=tools/mpc/mpyc_eq_backend.py \
	MPC_BASE_PORT=11500 \
	MPC_TIMEOUT_SEC=30 \
	MPC_KEEP_ARTIFACTS=false \
	python3 ./scripts/policy_flow_matrix.py \
	  --modes real \
	  --scenarios happy,deny \
	  --rounds 1 \
	  --output scripts/policy_flow_real_result.json \
	  --log-dir scripts/logs