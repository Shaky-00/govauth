package handler

import (
	"net/http"
	"strings"

	"govauth/internal/api/dto"
	"govauth/internal/app/workflow"

	"github.com/gin-gonic/gin"
)

// Handler 封装所有 HTTP handler。
type Handler struct {
	svc *workflow.Service
}

// New 创建 handler。
func New(svc *workflow.Service) *Handler {
	return &Handler{svc: svc}
}

// CreatePolicy 创建 DraftPolicy。
func (h *Handler) CreatePolicy(c *gin.Context) {
	var req dto.CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, err)
		return
	}

	policy, err := h.svc.CreatePolicy(workflow.CreatePolicyInput{
		Name:    req.Name,
		Content: req.Content,
	})
	if err != nil {
		respondServiceError(c, err)
		return
	}

	respondOK(c, "policy created", policy)
}

// AdmitPolicy 执行 T0，进入 Admissible。
func (h *Handler) AdmitPolicy(c *gin.Context) {
	policy, err := h.svc.AdmitPolicy(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "policy admitted", policy)
}

// PublishPolicy 执行 T1，进入 Published。
func (h *Handler) PublishPolicy(c *gin.Context) {
	policy, err := h.svc.PublishPolicy(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "policy published", policy)
}

// DerivePlan 基于策略派生 Enforcement Plan。
func (h *Handler) DerivePlan(c *gin.Context) {
	plan, err := h.svc.DerivePlan(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "plan derived", plan)
}

// GetPolicy 查询策略详情。
func (h *Handler) GetPolicy(c *gin.Context) {
	policy, err := h.svc.GetPolicy(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "policy fetched", policy)
}

// GetPlan 查询执行计划详情。
func (h *Handler) GetPlan(c *gin.Context) {
	plan, err := h.svc.GetPlan(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "plan fetched", plan)
}

// CreateSession 执行 T2，建立 SessionBound。
func (h *Handler) CreateSession(c *gin.Context) {
	var req dto.CreateSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, err)
		return
	}

	session, err := h.svc.CreateSession(workflow.CreateSessionInput{
		PolicyID:   req.PolicyID,
		PlanID:     req.PlanID,
		Requester:  req.Requester,
		ResourceID: req.ResourceID,
		Context:    req.Context,
	})
	if err != nil {
		respondServiceError(c, err)
		return
	}

	respondOK(c, "session created", session)
}

// GetSession 查询会话详情。
func (h *Handler) GetSession(c *gin.Context) {
	session, err := h.svc.GetSession(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "session fetched", session)
}

// AdmitEvidence 执行 T3 的证据接纳部分。
func (h *Handler) AdmitEvidence(c *gin.Context) {
	var req dto.AdmitEvidenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, err)
		return
	}

	evidence, session, err := h.svc.AdmitEvidence(c.Param("id"), req.Payload)
	if err != nil {
		respondServiceError(c, err)
		return
	}

	respondOK(c, "evidence admitted", gin.H{
		"evidence": evidence,
		"session":  session,
	})
}

// PinSnapshot 执行 T3 的快照固定部分。
func (h *Handler) PinSnapshot(c *gin.Context) {
	var req dto.PinSnapshotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, err)
		return
	}

	snapshot, session, err := h.svc.PinSnapshot(c.Param("id"), req.Payload)
	if err != nil {
		respondServiceError(c, err)
		return
	}

	respondOK(c, "snapshot pinned", gin.H{
		"snapshot": snapshot,
		"session":  session,
	})
}

// Evaluate 执行 T4 决策。
func (h *Handler) Evaluate(c *gin.Context) {
	result, session, err := h.svc.Evaluate(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}

	respondOK(c, "evaluation completed", gin.H{
		"evaluation": result,
		"session":    session,
	})
}

// SealArtifact 执行 T5，生成 artifact 并进入 Enforced。
func (h *Handler) SealArtifact(c *gin.Context) {
	artifact, session, err := h.svc.SealArtifact(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}

	respondOK(c, "artifact sealed and enforcement completed", gin.H{
		"artifact": artifact,
		"session":  session,
	})
}

// GetArtifact 查询授权工件。
func (h *Handler) GetArtifact(c *gin.Context) {
	artifact, err := h.svc.GetArtifact(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "artifact fetched", artifact)
}

// GetAuditBundle 查询完整审计视图。
func (h *Handler) GetAuditBundle(c *gin.Context) {
	bundle, err := h.svc.GetAuditBundle(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, "audit bundle fetched", bundle)
}

// respondOK 返回统一成功响应。
func respondOK(c *gin.Context, message string, data any) {
	c.JSON(http.StatusOK, dto.APIResponse{
		Message: message,
		Data:    data,
	})
}

// respondError 返回统一错误响应。
func respondError(c *gin.Context, code int, err error) {
	c.JSON(code, dto.APIResponse{
		Message: "request failed",
		Error:   err.Error(),
	})
}

// respondServiceError 根据错误内容做一个简易分类。
func respondServiceError(c *gin.Context, err error) {
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		respondError(c, http.StatusNotFound, err)
		return
	}
	respondError(c, http.StatusBadRequest, err)
}
