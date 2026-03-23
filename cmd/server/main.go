package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"govauth/internal/api/handler"
	"govauth/internal/api/router"
	"govauth/internal/app/workflow"
	"govauth/internal/repo/memory"

	"github.com/joho/godotenv"
)

func main() {
	// 加载本地环境变量。
	_ = godotenv.Load()

	// 读取服务监听地址。
	addr := strings.TrimSpace(os.Getenv("HTTP_ADDR"))
	if addr == "" {
		addr = ":8080"
	}

	// 读取 evaluator mode。
	// 支持：
	// - plain
	// - secure_stub
	// - secure_orchestrating
	evaluatorMode := strings.TrimSpace(os.Getenv("EVALUATOR_MODE"))
	if evaluatorMode == "" {
		evaluatorMode = defaultEvaluatorMode()
	}

	// 读取 secure backend mode。
	// 仅当 evaluator_mode=secure_orchestrating 时生效。
	// 支持：
	// - mock_mpc
	// - real_mpc
	secureBackendMode := strings.TrimSpace(os.Getenv("SECURE_BACKEND_MODE"))
	if secureBackendMode == "" {
		secureBackendMode = "mock_mpc"
	}

	// 初始化最小依赖：内存仓库 -> 工作流服务 -> HTTP Handler -> Router。
	store := memory.NewStore()

	// 根据环境变量构造 evaluator。
	evaluator, err := buildEvaluator(evaluatorMode, secureBackendMode)
	if err != nil {
		log.Fatalf("failed to build evaluator: %v", err)
	}

	svc := workflow.NewServiceWithEvaluator(store, evaluator)
	h := handler.New(svc)
	r := router.New(h)

	log.Printf("govauth listening on %s", addr)
	log.Printf("govauth evaluator_mode=%s secure_backend_mode=%s", evaluatorMode, secureBackendMode)

	if err := r.Run(addr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// buildEvaluator 根据环境变量构造 evaluator。
func buildEvaluator(evaluatorMode string, secureBackendMode string) (workflow.Evaluator, error) {
	switch evaluatorMode {
	case "plain":
		return workflow.NewPlainEvaluator(), nil

	case "secure_stub":
		return workflow.NewSecureStubEvaluator(), nil

	case "secure_orchestrating":
		backend, err := buildSecureBackend(secureBackendMode)
		if err != nil {
			return nil, err
		}
		return workflow.NewSecureOrchestratingEvaluator(backend), nil

	default:
		return nil, fmt.Errorf("unsupported evaluator mode: %s", evaluatorMode)
	}
}

// buildSecureBackend 根据 backend mode 构造具体 backend。
func buildSecureBackend(mode string) (workflow.SecureBackend, error) {
	switch mode {
	case "", "mock_mpc":
		return workflow.NewMockMPCBackend(), nil
	case "real_mpc":
		return workflow.NewRealMPCBackend(), nil
	default:
		return nil, fmt.Errorf("unsupported secure backend mode: %s", mode)
	}
}

// defaultEvaluatorMode 返回默认 evaluator 模式。
func defaultEvaluatorMode() string {
	// 默认直接使用 secure_orchestrating，表示服务端优先进入 MPC-ready 主路径。
	return "secure_orchestrating"
}
