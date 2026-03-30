package main

import (
	"log"
	"os"

	"govauth/internal/api/handler"
	"govauth/internal/api/router"
	"govauth/internal/app/workflow"
	"govauth/internal/repo/memory"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	evaluatorMode := os.Getenv("EVALUATOR_MODE")
	backendMode := os.Getenv("SECURE_BACKEND_MODE")

	store := memory.NewStore()

	evaluator, err := workflow.NewEvaluatorByModeAndBackend(evaluatorMode, backendMode)
	if err != nil {
		log.Fatalf("failed to create evaluator: %v", err)
	}

	svc := workflow.NewServiceWithEvaluator(store, evaluator)
	h := handler.New(svc)
	r := router.New(h)

	log.Printf("govauth listening on %s evaluator=%s backend=%s", addr, evaluatorMode, backendMode)
	if err := r.Run(addr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
