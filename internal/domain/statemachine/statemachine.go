package statemachine

import (
	"fmt"
	"govauth/internal/domain/model"
	"strings"
)

// 检查策略是否可以从 DRAFT 进入 ADMISSIBLE
func ValidatePolicyAdmission(p *model.Policy) error {
	if p.Status != model.PolicyStatusDraft {
		return fmt.Errorf("policy state must be DRAFT before admission")
	}

	// 模式1：兼容旧字段模式
	// if p.Content.RequiredRole != "" &&
	// 	p.Content.RequiredDepartment != "" &&
	// 	p.Content.RequiredPurpose != "" &&
	// 	p.Content.RequiredResourceStatus != "" {
	// 	return nil
	// }

	// 模式2：Clause 模式
	if len(p.Content.Clauses) == 0 {
		return fmt.Errorf("policy content is incomplete: require legacy fields or non-empty clauses")
	}

	for i, clause := range p.Content.Clauses {
		if strings.TrimSpace(clause.Source) == "" {
			return fmt.Errorf("clause[%d] source is required", i)
		}
		if strings.TrimSpace(clause.Field) == "" {
			return fmt.Errorf("clause[%d] field is required", i)
		}
		if strings.TrimSpace(clause.Op) == "" {
			return fmt.Errorf("clause[%d] op is required", i)
		}

		switch strings.ToLower(strings.TrimSpace(clause.Source)) {
		case model.ClauseSourceEvidence, model.ClauseSourceSnapshot, model.ClauseSourceContext:
		default:
			return fmt.Errorf("clause[%d] source %q is invalid", i, clause.Source)
		}

		switch strings.ToLower(strings.TrimSpace(clause.Op)) {
		case model.ClauseOpEq:
		default:
			return fmt.Errorf("clause[%d] op %q is unsupported", i, clause.Op)
		}

		if clause.Owner != "" {
			switch strings.ToLower(strings.TrimSpace(clause.Owner)) {
			case model.ClauseOwnerRequester, model.ClauseOwnerProvider, model.ClauseOwnerAuthority:
			default:
				return fmt.Errorf("clause[%d] owner %q is invalid", i, clause.Owner)
			}
		}
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
