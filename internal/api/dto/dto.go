package dto

import "govauth/internal/domain/model"

// CreatePolicyRequest 创建策略请求。
type CreatePolicyRequest struct {
	Name    string              `json:"name" binding:"required"`
	Content model.PolicyContent `json:"content" binding:"required"`
}

// CreateSessionRequest 创建执行会话请求。
type CreateSessionRequest struct {
	PolicyID   string         `json:"policy_id" binding:"required"`
	PlanID     string         `json:"plan_id" binding:"required"`
	Requester  string         `json:"requester" binding:"required"`
	ResourceID string         `json:"resource_id" binding:"required"`
	Context    map[string]any `json:"context"`
}

// AdmitEvidenceRequest 提交证据请求。
type AdmitEvidenceRequest struct {
	Payload map[string]any `json:"payload" binding:"required"`
}

// PinSnapshotRequest 固定快照请求。
type PinSnapshotRequest struct {
	Payload map[string]any `json:"payload" binding:"required"`
}

// APIResponse 统一响应格式。
type APIResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}
