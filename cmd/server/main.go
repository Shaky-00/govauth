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
	// 加载本地环境变量。
	_ = godotenv.Load()

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// 初始化最小依赖：内存仓库 -> 工作流服务 -> HTTP Handler -> Router。
	store := memory.NewStore()
	svc := workflow.NewService(store)
	h := handler.New(svc)
	r := router.New(h)

	log.Printf("govauth listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
