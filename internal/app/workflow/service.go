package workflow

import (
	"fmt"
	"govauth/internal/domain/model"
	"govauth/internal/domain/statemachine"
	"govauth/internal/pkg/hash"
	"govauth/internal/pkg/id"
	"govauth/internal/repo/memory"
	"strings"
	"time"
)

// Service 负责把 GASM/PES 所需的对象流编排成一个可运行 happy path。
type Service struct {
	store     *memory.Store
	evaluator Evaluator
}

// 创建工作流服务
func NewService(store *memory.Store) *Service {
	return &Service{
		store:     store,
		evaluator: NewPlainEvaluator(),
	}
}

// 创建策略的输入
type CreatePolicyInput struct {
	Name    string
	Content model.PolicyContent
}

// 创建会话的输入
type CreateSessionInput struct {
	PolicyID   string
	PlanID     string
	Requester  string
	ResourceID string
	Context    map[string]any
}

// 汇总一次完整授权执行链相关的关键对象与事件
type AuditBundle struct {
	Policy     *model.Policy                `json:"policy,omitempty"`
	Plan       *model.EnforcementPlan       `json:"plan,omitempty"`
	Session    *model.ExecutionSession      `json:"session,omitempty"`
	Evidence   *model.EvidenceRecord        `json:"evidence,omitempty"`
	Snapshot   *model.PinnedSnapshot        `json:"snapshot,omitempty"`
	Evaluation *model.EvaluationResult      `json:"evaluation,omitempty"`
	Artifact   *model.AuthorizationArtifact `json:"artifact,omitempty"`
	Events     []*model.TransitionEvent     `json:"events"`
}

// 创建一份 DraftPolicy
func (s *Service) CreatePolicy(in CreatePolicyInput) (*model.Policy, error) {
	now := time.Now()

	policy := &model.Policy{
		ID:        id.New("policy"),
		Name:      in.Name,
		Version:   1,
		Status:    model.PolicyStatusDraft,
		Content:   in.Content,
		Digest:    hash.AnySHA256Hex(in.Content),
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.store.SavePolicy(policy)
	return policy, nil
}

// 对 DraftPolicy 执行治理验证，并进入 ADMISSIBLE
func (s *Service) AdmitPolicy(policyID string) (*model.Policy, error) {
	policy, err := s.store.GetPolicy(policyID)
	if err != nil {
		return nil, err
	}

	if err := statemachine.ValidatePolicyAdmission(policy); err != nil {
		_ = s.rejectPolicy(policy, "T0_POLICY_ADMISSION", err)
		return policy, err
	}

	from := string(policy.Status)
	policy.Status = model.PolicyStatusAdmissible
	policy.UpdatedAt = time.Now()
	s.store.SavePolicy(policy)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  policy.ID,
		Action:    "T0_POLICY_ADMISSION",
		FromState: from,
		ToState:   string(policy.Status),
		Note:      "策略通过治理校验，进入 ADMISSIBLE 状态",
		At:        time.Now(),
	})

	return policy, nil
}

// 将策略发布为可执行状态
func (s *Service) PublishPolicy(policyID string) (*model.Policy, error) {
	policy, err := s.store.GetPolicy(policyID)
	if err != nil {
		return nil, err
	}

	if err := statemachine.ValidatePolicyPublished(policy); err != nil {
		_ = s.rejectPolicy(policy, "T1_POLICY_PUBLICATION", err)
		return policy, err
	}

	from := string(policy.Status)
	policy.Status = model.PolicyStatusPublished
	policy.UpdatedAt = time.Now()
	s.store.SavePolicy(policy)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  policy.ID,
		Action:    "T1_POLICY_PUBLICATION",
		FromState: from,
		ToState:   string(policy.Status),
		Note:      "策略已发布，可进入动态执行阶段",
		At:        time.Now(),
	})

	return policy, nil
}

// 基于 Published 策略生成执行计划
func (s *Service) DerivePlan(policyID string) (*model.EnforcementPlan, error) {
	policy, err := s.store.GetPolicy(policyID)
	if err != nil {
		return nil, err
	}

	if err := statemachine.ValidatePlanDerivation(policy); err != nil {
		return nil, err
	}

	legacyClauses := make([]model.Clause, 0)

	rawClauses := legacyClauses
	if len(policy.Content.Clauses) > 0 {
		rawClauses = policy.Content.Clauses
	}
	clauses := normalizeClauses(rawClauses)

	admissibleEvidenceKeys := collectClauseFieldsBySource(clauses, model.ClauseSourceEvidence)
	admissibleEvidenceKeys = mergeStringKeys(admissibleEvidenceKeys, []string{"holder", "credential_id"})

	requiredSnapshotKeys := collectClauseFieldsBySource(clauses, model.ClauseSourceSnapshot)
	requiredSnapshotKeys = mergeStringKeys(requiredSnapshotKeys, []string{"lifecycle", "owner_domain", "version"})

	plan := &model.EnforcementPlan{
		ID:                     id.New("plan"),
		PolicyID:               policy.ID,
		PolicyVersion:          policy.Version,
		Clauses:                clauses,
		AdmissibleEvidenceKeys: admissibleEvidenceKeys,
		RequiredSnapshotKeys:   requiredSnapshotKeys,
		ReleaseBindingRequired: true,
		ExecutionHints: map[string]any{
			"canonical_policy": "clauses",
			"clause_count":     len(clauses),
		},
		DerivedFromPolicyDigest: policy.Digest,
		CreatedAt:               time.Now(),
	}

	s.store.SavePlan(plan)
	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  policy.ID,
		Action:    "PLAN_DERIVATION",
		FromState: string(policy.Status),
		ToState:   string(policy.Status),
		Note:      "系统已从 Published Policy 派生出 Enforcement Plan",
		Meta: map[string]any{
			"plan_id": plan.ID,
		},
		At: time.Now(),
	})
	return plan, nil
}

// 创建一条新的执行会话，并进入 SessionBound
func (s *Service) CreateSession(in CreateSessionInput) (*model.ExecutionSession, error) {
	policy, err := s.store.GetPolicy(in.PolicyID)
	if err != nil {
		return nil, err
	}

	if policy.Status != model.PolicyStatusPublished {
		return nil, fmt.Errorf("policy must be PUBLISHED before session creation")
	}

	plan, err := s.store.GetPlan(in.PlanID)
	if err != nil {
		return nil, err
	}
	if plan.PolicyID != policy.ID || plan.PolicyVersion != policy.Version {
		return nil, fmt.Errorf("plan is not bound to the specified published policy")
	}

	now := time.Now()
	session := &model.ExecutionSession{
		ID:         id.New("session"),
		PolicyID:   in.PolicyID,
		PlanID:     in.PlanID,
		Requester:  in.Requester,
		ResourceID: in.ResourceID,
		Context:    in.Context,
		State:      model.SessionStateSessionBound,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	s.store.SaveSession(session)

	s.store.AppendEvent((&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  in.PolicyID,
		SessionID: session.ID,
		Action:    "T2_SESSION_BINDING",
		FromState: string(policy.Status),
		ToState:   string(session.State),
		Note:      "系统已建立执行会话，并完成上下文绑定",
		Meta: map[string]any{
			"resource_id": session.ResourceID,
			"requester":   session.Requester,
		},
		At: time.Now(),
	}))

	return session, nil
}

// 将证据接纳到当前会话，并进入 EvidenceBound
func (s *Service) AdmitEvidence(sessionID string, payload map[string]any) (*model.EvidenceRecord, *model.ExecutionSession, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if err := ensureSessionActive(session); err != nil {
		return nil, session, err
	}
	if err := statemachine.ValidateEvidenceAdmission(session); err != nil {
		return nil, session, s.rejectSession(session, "T3_EVIDENCE_BINDING", err, nil)
	}

	plan, err := s.store.GetPlan(session.PlanID)
	if err != nil {
		return nil, session, s.rejectSession(session, "T3_EVIDENCE_BINDING", err, nil)
	}

	admittedView := make(map[string]any)
	for _, key := range plan.AdmissibleEvidenceKeys {
		if v, ok := payload[key]; ok {
			admittedView[key] = v
		}
	}

	evidence := &model.EvidenceRecord{
		ID:             id.New("evidence"),
		SessionID:      session.ID,
		Payload:        payload,
		AdmittedView:   admittedView,
		EvidenceDigest: hash.AnySHA256Hex(admittedView),
		Admitted:       true,
		CreatedAt:      time.Now(),
	}

	s.store.SaveEvidence(evidence)

	from := string(session.State)
	session.EvidenceID = evidence.ID
	session.State = model.SessionStateEvidenceBound
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T3_EVIDENCE_BINDING",
		FromState: from,
		ToState:   string(session.State),
		Note:      "证据已接纳并绑定到当前会话",
		Meta: map[string]any{
			"evidence_id": evidence.ID,
		},
		At: time.Now(),
	})

	return evidence, session, nil
}

// 固定当前生命周期快照
func (s *Service) PinSnapshot(sessionID string, payload map[string]any) (*model.PinnedSnapshot, *model.ExecutionSession, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if err := ensureSessionActive(session); err != nil {
		return nil, session, err
	}
	if err := statemachine.ValidateSnapshotPinning(session); err != nil {
		return nil, session, s.rejectSession(session, "T3_SNAPSHOT_PINNING", err, nil)
	}

	snapshot := &model.PinnedSnapshot{
		ID:             id.New("snapshot"),
		SessionID:      session.ID,
		Payload:        payload,
		SnapshotDigest: hash.AnySHA256Hex(payload),
		PinnedAt:       time.Now(),
	}

	s.store.SaveSnapshot(snapshot)

	session.SnapshotID = snapshot.ID
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T3_SNAPSHOT_PINNING",
		FromState: string(session.State),
		ToState:   string(session.State),
		Note:      "生命周期快照已固定并绑定到当前会话",
		Meta: map[string]any{
			"snapshot_id": snapshot.ID,
		},
		At: time.Now(),
	})

	return snapshot, session, nil
}

// 执行一次最小可运行的策略评估
func (s *Service) Evaluate(sessionID string) (*model.EvaluationResult, *model.ExecutionSession, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if err := ensureSessionActive(session); err != nil {
		return nil, session, err
	}
	if err := statemachine.ValidateEvaluation(session); err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", err, nil)
	}

	plan, err := s.store.GetPlan(session.PlanID)
	if err != nil {
		return nil, nil, err
	}
	if len(plan.Clauses) == 0 {
		return nil, session, s.rejectSession(session, "T4_DECISION", fmt.Errorf("plan clauses missing"), nil)
	}

	evidence, err := s.store.GetEvidence(session.EvidenceID)
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", fmt.Errorf("bound evidence missing: %w", err), nil)
	}

	snapshot, err := s.store.GetSnapshot(session.SnapshotID)
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", fmt.Errorf("bound snapshot missing: %w", err), nil)
	}

	// decision, reasons := evaluateClauses(plan.Clauses, evidence, snapshot, session)

	// if len(reasons) == 0 {
	// 	reasons = append(reasons, fmt.Sprintf("plan %s verified all clauses successfully", plan.ID))
	// }

	// result := &model.EvaluationResult{
	// 	ID:            id.New("eval"),
	// 	SessionID:     session.ID,
	// 	Decision:      decision,
	// 	Reason:        strings.Join(reasons, "; "),
	// 	EvaluatorMode: model.EvaluatorModePlain,
	// 	EvaluatedAt:   time.Now(),
	// }

	result, err := s.evaluator.Evaluate(EvaluationInput{
		Plan:     plan,
		Evidence: evidence,
		Snapshot: snapshot,
		Session:  session,
	})
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", err, map[string]any{
			"mode": s.evaluator.Mode(),
		})
	}

	if result.ID == "" {
		result.ID = id.New("eval")
	}
	if result.SessionID == "" {
		result.SessionID = session.ID
	}
	if strings.TrimSpace(result.EvaluatorMode) == "" {
		result.EvaluatorMode = s.evaluator.Mode()
	}
	if result.EvaluatedAt.IsZero() {
		result.EvaluatedAt = time.Now()
	}

	s.store.SaveEvaluation(result)

	from := string(session.State)
	session.EvaluationID = result.ID
	session.State = model.SessionStateDecided
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		Action:    "T4_DECISION",
		FromState: from,
		ToState:   string(session.State),
		Note:      fmt.Sprintf("策略评估完成，决策结果为 %s", result.Decision),
		Meta: map[string]any{
			"evaluation_id": result.ID,
			"decision":      result.Decision,
			"mode":          result.EvaluatorMode,
		},
		At: time.Now(),
	})

	return result, session, nil
}

// 生成授权工件，并将会话推进到 Enforced
func (s *Service) SealArtifact(sessionID string) (*model.AuthorizationArtifact, *model.ExecutionSession, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if err := statemachine.ValidateArtifactSealing(session); err != nil {
		return nil, nil, err
	}

	policy, err := s.store.GetPolicy(session.PolicyID)
	if err != nil {
		return nil, nil, err
	}

	evidence, err := s.store.GetEvidence(session.EvidenceID)
	if err != nil {
		return nil, nil, err
	}

	snapshot, err := s.store.GetSnapshot(session.SnapshotID)
	if err != nil {
		return nil, nil, err
	}

	evaluation, err := s.store.GetEvaluation(session.EvaluationID)
	if err != nil {
		return nil, nil, err
	}

	artifact := &model.AuthorizationArtifact{
		ID:                    id.New("artifact"),
		SessionID:             session.ID,
		PolicyDigest:          policy.Digest,
		EvidenceDigest:        evidence.EvidenceDigest,
		LifecycleDigest:       snapshot.SnapshotDigest,
		AuthorizationDecision: evaluation.Decision,
		Context:               session.Context,
		CreatedAt:             time.Now(),
	}

	artifact.Signature = hash.AnySHA256Hex(map[string]any{
		"session_id":       artifact.SessionID,
		"policy_digest":    artifact.PolicyDigest,
		"evidence_digest":  artifact.EvidenceDigest,
		"lifecycle_digest": artifact.LifecycleDigest,
		"decision":         artifact.AuthorizationDecision,
		"context":          artifact.Context,
	})
	artifact.ArtifactDigest = hash.AnySHA256Hex(artifact)

	s.store.SaveArtifact(artifact)

	from := string(session.State)
	session.ArtifactID = artifact.ID
	session.State = model.SessionStateEnforced
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T5_ARTIFACT_AND_ENFORCEMENT",
		FromState: from,
		ToState:   string(session.State),
		Note:      "授权工件已生成，结果已可被数据服务呈现/记录",
		Meta: map[string]any{
			"artifact_id": artifact.ID,
		},
		At: time.Now(),
	})

	return artifact, session, nil
}

// GetPolicy 查询策略。
func (s *Service) GetPolicy(policyID string) (*model.Policy, error) {
	return s.store.GetPolicy(policyID)
}

// GetPlan 查询执行计划。
func (s *Service) GetPlan(planID string) (*model.EnforcementPlan, error) {
	return s.store.GetPlan(planID)
}

// GetSession 查询会话。
func (s *Service) GetSession(sessionID string) (*model.ExecutionSession, error) {
	return s.store.GetSession(sessionID)
}

// GetArtifact 查询授权工件。
func (s *Service) GetArtifact(artifactID string) (*model.AuthorizationArtifact, error) {
	return s.store.GetArtifact(artifactID)
}

// 汇总某次会话的核心对象与状态迁移日志
func (s *Service) GetAuditBundle(sessionID string) (*AuditBundle, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	bundle := &AuditBundle{
		Session: session,
		Events:  s.store.ListEvents(session.ID, session.PolicyID),
	}

	bundle.Policy, _ = s.store.GetPolicy(session.PolicyID)
	bundle.Plan, _ = s.store.GetPlan(session.PlanID)
	if session.EvidenceID != "" {
		bundle.Evidence, _ = s.store.GetEvidence(session.EvidenceID)
	}
	if session.SnapshotID != "" {
		bundle.Snapshot, _ = s.store.GetSnapshot(session.SnapshotID)
	}
	if session.EvaluationID != "" {
		bundle.Evaluation, _ = s.store.GetEvaluation(session.EvaluationID)
	}
	if session.ArtifactID != "" {
		bundle.Artifact, _ = s.store.GetArtifact(session.ArtifactID)
	}

	return bundle, nil
}

func ensureSessionActive(session *model.ExecutionSession) error {
	switch session.State {
	case model.SessionStateRejected:
		return fmt.Errorf("session already rejected: %s", session.RejectedReason)
	case model.SessionStateEnforced:
		return fmt.Errorf("session already enforced")
	default:
		return nil
	}
}

func (s *Service) rejectPolicy(policy *model.Policy, action string, cause error) error {
	now := time.Now()
	from := string(policy.Status)

	policy.Status = model.PolicyStatusRejected
	policy.UpdatedAt = now
	s.store.SavePolicy(policy)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  policy.ID,
		Action:    action,
		FromState: from,
		ToState:   string(model.PolicyStatusRejected),
		Note:      "policy rejected",
		Meta: map[string]any{
			"rejected": true,
			"reason":   cause.Error(),
		},
		At: now,
	})

	return cause
}

func (s *Service) rejectSession(session *model.ExecutionSession, action string, cause error, extraMeta map[string]any) error {
	now := time.Now()
	from := string(session.State)

	session.State = model.SessionStateRejected
	session.RejectedReason = cause.Error()
	session.RejectedByAction = action
	session.RejectedAt = &now
	session.UpdatedAt = now
	s.store.SaveSession(session)

	meta := map[string]any{
		"rejected": true,
		"reason":   cause.Error(),
	}
	for k, v := range extraMeta {
		meta[k] = v
	}

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    action,
		FromState: from,
		ToState:   string(model.SessionStateRejected),
		Note:      "session rejected due to governance/state-machine violation",
		Meta:      meta,
		At:        now,
	})

	return cause
}

// 将原始 Clause 规范化：
// 1. 统一 source / op / owner 大小写；
// 2. 若 owner 为空，则按 source 自动补默认值。
func normalizeClauses(raw []model.Clause) []model.Clause {
	out := make([]model.Clause, 0, len(raw))
	for _, clause := range raw {
		normalized := clause
		normalized.Source = strings.ToLower(strings.TrimSpace(clause.Source))
		normalized.Field = strings.TrimSpace(clause.Field)
		normalized.Op = strings.ToLower(strings.TrimSpace(clause.Op))
		normalized.Owner = strings.ToLower(strings.TrimSpace(clause.Owner))

		if normalized.Owner == "" {
			switch normalized.Source {
			case model.ClauseSourceEvidence, model.ClauseSourceContext:
				normalized.Owner = model.ClauseOwnerRequester
			case model.ClauseSourceSnapshot:
				normalized.Owner = model.ClauseOwnerProvider
			}
		}

		out = append(out, normalized)
	}
	return out
}

func collectClauseFieldsBySource(clauses []model.Clause, source string) []string {
	result := make([]string, 0)
	seen := make(map[string]struct{})

	for _, clause := range clauses {
		if clause.Source != source {
			continue
		}
		if clause.Field == "" {
			continue
		}
		if _, ok := seen[clause.Field]; ok {
			continue
		}
		seen[clause.Field] = struct{}{}
		result = append(result, clause.Field)
	}

	return result
}

func mergeStringKeys(base []string, extra []string) []string {
	result := make([]string, 0, len(base)+len(extra))
	seen := make(map[string]struct{})

	for _, item := range base {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}

	for _, item := range extra {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}

	return result
}
