package router

import (
	"govauth/internal/api/handler"

	"github.com/gin-gonic/gin"
)

// New 创建并注册所有 HTTP 路由。
func New(h *handler.Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// 健康检查接口。
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "govauth",
			"phase":   "phase1-happy-path",
		})
	})

	api := r.Group("/api/v1")
	{
		// Policy 相关接口。
		api.POST("/policies", h.CreatePolicy)
		api.GET("/policies/:id", h.GetPolicy)
		api.POST("/policies/:id/admit", h.AdmitPolicy)
		api.POST("/policies/:id/publish", h.PublishPolicy)
		api.POST("/policies/:id/derive-plan", h.DerivePlan)

		// Plan 查询接口。
		api.GET("/plans/:id", h.GetPlan)

		// Session / Evidence / Snapshot / Evaluation / Artifact 相关接口。
		api.POST("/sessions", h.CreateSession)
		api.GET("/sessions/:id", h.GetSession)
		api.POST("/sessions/:id/evidence", h.AdmitEvidence)
		api.POST("/sessions/:id/snapshot", h.PinSnapshot)
		api.POST("/sessions/:id/evaluate", h.Evaluate)
		api.POST("/sessions/:id/artifact", h.SealArtifact)
		api.GET("/sessions/:id/audit", h.GetAuditBundle)
		api.GET("/artifacts/:id", h.GetArtifact)
	}

	return r
}
