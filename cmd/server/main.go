package main

import (
	"log"
	"os"

	"govauth/internal/api/router"

	"github.com/joho/godotenv"
)

func main() {
	// 加载 .env 文件。
	// 如果不存在也不报错，便于后续兼容不同环境。
	_ = godotenv.Load()

	// 读取服务监听地址。
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// 初始化路由。
	r := router.New()

	log.Printf("govauth listening on %s", addr)

	// 启动 HTTP 服务。
	if err := r.Run(addr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}