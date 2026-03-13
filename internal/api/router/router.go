package router

import "github.com/gin-gonic/gin"

// New 创建并返回一个最小可用的 Gin 路由引擎。
// 当前阶段只提供健康检查接口，用于确认项目骨架已成功启动。
func New() *gin.Engine {
	// 使用 Gin 默认提供的日志与异常恢复中间件，
	// 便于开发阶段快速观察请求和错误。
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// 健康检查接口：
	// 用于确认服务是否已正常启动。
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "govauth",
			"phase":   "phase0",
		})
	})

	return r
}