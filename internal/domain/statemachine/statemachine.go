package statemachine

import (
	"fmt"
	"govauth/internal/domain/model"
)

// 检查策略是否可以从 DRAFT 进入 ADMISSIBLE
func ValidatePolicyAdmission(p *model.Policy) error {
	if p.Status != model.PolicyStatusDraft {
		return fmt.Errorf("policy state must be DRAFT before admission")
	}
	if p.Content.RequiredRole == "" ||
		p.Content.RequiredDepartment == "" ||
		p.Content.RequiredPurpose == "" ||
		p.Content.RequiredResourceStatus == "" {
		return fmt.Errorf("policy content is incomplete: require_role/department/purpose/resourcestatus")
	}
	return nil
}

// 检查策略是否可以从 ADMISSIBLE 进入 PUBLISHED
func ValidatePolicyPublished(p *model.Policy) error {
	if p.Status != model.PolicyStatusAdmissible {
		return fmt.Errorf("policy must be ADMISSIBLE before plan derivation")
	}
	return nil
}

// 检查策略是否允许派生执行计划
func ValidatePlanDerivation(p *model.Policy) error {
	if p.Status != model.PolicyStatusPublished {
		return fmt.Errorf("policy must be PUBLISHED before plan derivation")
	}
	return nil
}

// 检查会话是否允许接纳证据
func ValidateEvidenceAdmission(s *model.ExecutionSession) error {
	if s.State != model.SessionStateSessionBound {
		return fmt.Errorf("session state must be SESSION_BOUND before evidence admission")
	}
	return nil
}

// 检查会话是否允许固定快照
func ValidateSnapshotPinning(s *model.ExecutionSession) error {
	if s.State != model.SessionStateEvidenceBound {
		return fmt.Errorf("session state must be EVIDENCE_BOUND before snapshot pinning")
	}
	return nil
}

// 检查会话是否允许执行评估
func ValidateEvaluation(s *model.ExecutionSession) error {
	if s.State != model.SessionStateEvidenceBound {
		return fmt.Errorf("session state must be EVIDENCE_BOUND before evaluation")
	}
	if s.EvidenceID == "" {
		return fmt.Errorf("evidence must exist before evaluation")
	}
	if s.SnapshotID == "" {
		return fmt.Errorf("snapshot must be pinned before evaluation")
	}
	return nil
}

// 检查会话是否允许生成 Artifact 并进入执行完成态
func ValidateArtifactSealing(s *model.ExecutionSession) error {
	if s.State != model.SessionStateDecided {
		return fmt.Errorf("session state must be DECIDED before artifact sealing")
	}
	if s.EvaluationID == "" {
		return fmt.Errorf("evaluation result must exist before artifact sealing")
	}
	return nil
}
