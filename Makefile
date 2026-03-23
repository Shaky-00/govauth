.PHONY: run tidy test happy deny invalid all

# 启动服务
run:
	EVALUATOR_MODE=secure_orchestrating SECURE_BACKEND_MODE=real_mpc go run ./cmd/server

# 清理依赖
tidy:
	go mod tidy

# Go 单元测试
test:
	go test ./...	

happy:
	EXPECT_MODE=secure_orchestrating EXPECT_BACKEND=real_mpc bash ./scripts/run_happy_path.sh

deny:
	EXPECT_MODE=secure_orchestrating EXPECT_BACKEND=real_mpc bash ./scripts/run_deny_path.sh

# Invalid Transition 测试
invalid:
	bash ./scripts/run_invalid_transition.sh

# 一次性跑全部流程测试
all: happy deny invalid