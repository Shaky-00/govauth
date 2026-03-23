.PHONY: run tidy test happy deny invalid all

# 启动服务
run:
	go run ./cmd/server

# 清理依赖
tidy:
	go mod tidy

# Go 单元测试
test:
	go test ./...

# Happy Path 测试
happy:
	EXPECT_MODE=secure_stub bash ./scripts/run_happy_path.sh

# Deny Path 测试
deny:
	EXPECT_MODE=secure_stub bash ./scripts/run_deny_path.sh	

# Invalid Transition 测试
invalid:
	bash ./scripts/run_invalid_transition.sh

# 一次性跑全部流程测试
all: happy deny invalid