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

// Service 负责把 GASM / PES 所需的对象流编排成一个可运行 strict MPC 原型。
type Service struct {
	store     *memory.Store
	evaluator Evaluator
}

// 创建工作流服务
func NewService(store *memory.Store) *Service {
	return NewServiceWithEvaluator(store, nil)
}

func NewServiceWithEvaluator(store *memory.Store, evaluator Evaluator) *Service {
	if evaluator == nil {
		evaluator = NewPlainEvaluator()
	}

	return &Service{
		store:     store,
		evaluator: evaluator,
	}
}

// 运行时切换 Evaluator
func (s *Service) SetEvaluator(evaluator Evaluator) {
	if evaluator == nil {
		s.evaluator = NewPlainEvaluator()
		return
	}
	s.evaluator = evaluator
}

// 返回当前 Evaluator 模式
func (s *Service) CurrentEvaluatorMode() string {
	if s == nil || s.evaluator == nil {
		return model.EvaluatorModePlain
	}
	return s.evaluator.Mode()
}

// NewEvaluatorByMode 保留旧接口，兼容原有调用方式。
func NewEvaluatorByMode(mode string) (Evaluator, error) {
	return NewEvaluatorByModeAndBackend(mode, "")
}

// NewEvaluatorByModeAndBackend 是新的推荐入口。
func NewEvaluatorByModeAndBackend(mode string, backendMode string) (Evaluator, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", model.EvaluatorModePlain:
		return NewPlainEvaluator(), nil

	// 兼容旧模式名：原 secure_orchestrating 现在映射成真正 strict_mpc。
	case model.EvaluatorModeStrictMPC, model.EvaluatorModeSecureOrchestrating:
		backend, err := NewSecureBackendByMode(backendMode)
		if err != nil {
			return nil, err
		}
		return NewStrictMPCEvaluator(backend), nil

	// secure_stub 保留为 plain baseline，避免旧脚本直接炸掉。
	case model.EvaluatorModeSecureStub:
		return NewPlainEvaluator(), nil

	default:
		return nil, fmt.Errorf("unknown evaluator mode: %s", mode)
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
	Context    map[string]any // strict MPC 下这里应仅放 public context / digest / ref
}

// AuditBundle 汇总一次完整授权执行链相关的关键对象与事件。
type AuditBundle struct {
	Policy     *model.Policy                `json:"policy,omitempty"`
	Plan       *model.EnforcementPlan       `json:"plan,omitempty"`
	Session    *model.ExecutionSession      `json:"session,omitempty"`
	Evidence   *model.EvidenceRecord        `json:"evidence,omitempty"`
	Snapshot   *model.PinnedSnapshot        `json:"snapshot,omitempty"`
	TaskSpec   *model.StrictMPCTaskSpec     `json:"task_spec,omitempty"`
	Evaluation *model.EvaluationResult      `json:"evaluation,omitempty"`
	Artifact   *model.AuthorizationArtifact `json:"artifact,omitempty"`
	Events     []*model.TransitionEvent     `json:"events"`
}

// ------------------------------------------------------------
// 静态治理阶段
// ------------------------------------------------------------

// CreatePolicy 创建一份 DraftPolicy。
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

// AdmitPolicy 对 DraftPolicy 执行治理验证，并进入 ADMISSIBLE。
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

// PublishPolicy 将策略发布为可执行状态。
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

// DerivePlan 基于 Published 策略生成执行计划。
// 这里会显式构造 Π_P = <K_E, K_S, D, f_P, B>。
func (s *Service) DerivePlan(policyID string) (*model.EnforcementPlan, error) {
	policy, err := s.store.GetPolicy(policyID)
	if err != nil {
		return nil, err
	}

	if err := statemachine.ValidatePlanDerivation(policy); err != nil {
		return nil, err
	}

	rawClauses := policy.Content.Clauses
	clauses := normalizeClauses(rawClauses)

	kE := collectClauseFieldsBySource(clauses, model.ClauseSourceEvidence)
	kS := mergeStringKeys(
		collectClauseFieldsBySource(clauses, model.ClauseSourceSnapshot),
		collectClauseFieldsBySource(clauses, model.ClauseSourceContext),
	)
	partition := buildOwnershipPartition(clauses)

	plan := &model.EnforcementPlan{
		ID:                         id.New("plan"),
		PolicyID:                   policy.ID,
		PolicyVersion:              policy.Version,
		Clauses:                    clauses,
		PolicyRelevantEvidenceKeys: kE,
		RequiredStateDependencies:  kS,
		OwnershipPartition:         partition,
		CompiledFunction:           "compiled_clause_predicate_v1",
		BindingTemplate: map[string]any{
			"bind_policy_digest":    true,
			"bind_evidence_digest":  true,
			"bind_snapshot_digest":  true,
			"bind_context_digest":   true,
			"bind_result_receipt":   true,
			"artifact_sealing":      true,
			"transcript_digest_min": true,
		},
		// 兼容旧字段
		AdmissibleEvidenceKeys: kE,
		RequiredSnapshotKeys:   collectClauseFieldsBySource(clauses, model.ClauseSourceSnapshot),
		ReleaseBindingRequired: true,
		ExecutionHints: map[string]any{
			"canonical_policy": "clauses",
			"clause_count":     len(clauses),
			"strict_mpc_ready": true,
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
		Note:      "系统已从 Published Policy 派生出 Enforcement Plan（Π_P）",
		Meta: map[string]any{
			"plan_id":             plan.ID,
			"k_e":                 plan.PolicyRelevantEvidenceKeys,
			"k_s":                 plan.RequiredStateDependencies,
			"compiled_function":   plan.CompiledFunction,
			"ownership_partition": plan.OwnershipPartition,
		},
		At: time.Now(),
	})
	return plan, nil
}

// ------------------------------------------------------------
// 动态执行阶段：绑定 public digests / 发布 task / 接收 receipt
// ------------------------------------------------------------

// CreateSession 创建一条新的执行会话，并进入 SessionBound。
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

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  in.PolicyID,
		SessionID: session.ID,
		Action:    "T2_SESSION_BINDING",
		FromState: string(policy.Status),
		ToState:   string(session.State),
		Note:      "系统已建立执行会话，并完成上下文/public binding 绑定",
		Meta: map[string]any{
			"resource_id": session.ResourceID,
			"requester":   session.Requester,
		},
		At: time.Now(),
	})

	return session, nil
}

// AdmitEvidence 将证据接纳到当前会话。
// strict MPC 模式下 payload 应仅包含 private_digest / reference / public_meta。
// plain baseline 下也允许直接传明文字段。
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

	admittedView := buildAdmittedViewForPlainBaseline(payload, plan.PolicyRelevantEvidenceKeys)
	evidenceDigest := firstNonEmpty(
		readString(payload, "private_digest"),
		readString(payload, "evidence_digest"),
	)

	// 没给显式 digest，则退化为 plain baseline 的 admitted view 哈希。
	if evidenceDigest == "" {
		evidenceDigest = hash.AnySHA256Hex(admittedView)
	}

	evidence := &model.EvidenceRecord{
		ID:             id.New("evidence"),
		SessionID:      session.ID,
		Payload:        payload,
		AdmittedView:   admittedView,
		EvidenceDigest: evidenceDigest,
		EvidenceRef:    readString(payload, "reference"),
		Admitted:       true,
		CreatedAt:      time.Now(),
	}

	s.store.SaveEvidence(evidence)

	from := session.State
	session.EvidenceID = evidence.ID
	session.State = model.SessionStateEvidenceBound
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T3_EVIDENCE_BINDING",
		FromState: string(from),
		ToState:   string(session.State),
		Note:      "证据已接纳并绑定到当前会话（strict 模式下仅绑定 digest/ref）",
		Meta: map[string]any{
			"evidence_id":     evidence.ID,
			"evidence_digest": evidence.EvidenceDigest,
			"evidence_ref":    evidence.EvidenceRef,
		},
		At: time.Now(),
	})

	return evidence, session, nil
}

// PinSnapshot 固定当前生命周期快照。
// strict MPC 模式下 payload 应仅包含 private_digest / reference / public_meta。
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

	snapshotDigest := firstNonEmpty(
		readString(payload, "private_digest"),
		readString(payload, "snapshot_digest"),
	)
	if snapshotDigest == "" {
		// plain baseline / fallback
		snapshotDigest = hash.AnySHA256Hex(payload)
	}

	snapshot := &model.PinnedSnapshot{
		ID:             id.New("snapshot"),
		SessionID:      session.ID,
		Payload:        payload,
		SnapshotDigest: snapshotDigest,
		SnapshotRef:    readString(payload, "reference"),
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
		Note:      "生命周期快照已固定并绑定到当前会话（strict 模式下仅绑定 digest/ref）",
		Meta: map[string]any{
			"snapshot_id":     snapshot.ID,
			"snapshot_digest": snapshot.SnapshotDigest,
			"snapshot_ref":    snapshot.SnapshotRef,
		},
		At: time.Now(),
	})

	return snapshot, session, nil
}

// Evaluate 执行 plain baseline 的同步评估。
// strict MPC 模式请调用 PrepareEvaluationTask + SubmitMPCResult。
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

	plan, evidence, snapshot, err := s.loadEvaluationBindings(session)
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", err, nil)
	}

	syncEvaluator, ok := s.evaluator.(SyncEvaluator)
	if !ok {
		return nil, session, fmt.Errorf("current evaluator mode=%s is not a sync evaluator; use PrepareEvaluationTask instead", s.CurrentEvaluatorMode())
	}

	result, err := syncEvaluator.Evaluate(EvaluationInput{
		Plan:     plan,
		Evidence: evidence,
		Snapshot: snapshot,
		Session:  session,
	})
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", err, map[string]any{"mode": s.evaluator.Mode()})
	}

	return s.persistEvaluationResult(session, result)
}

// PrepareEvaluationTask 在 strict MPC 模式下发布 public task spec。
func (s *Service) PrepareEvaluationTask(sessionID string) (*model.StrictMPCTaskSpec, *model.ExecutionSession, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if err := ensureSessionActive(session); err != nil {
		return nil, session, err
	}
	if err := statemachine.ValidateEvaluation(session); err != nil {
		return nil, session, s.rejectSession(session, "T4_TASK_ISSUED", err, nil)
	}
	if session.TaskSpecID != "" {
		task, taskErr := s.store.GetTaskSpec(session.TaskSpecID)
		if taskErr == nil {
			return task, session, nil
		}
	}

	plan, evidence, snapshot, err := s.loadEvaluationBindings(session)
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_TASK_ISSUED", err, nil)
	}

	asyncEvaluator, ok := s.evaluator.(AsyncTaskEvaluator)
	if !ok {
		return nil, session, fmt.Errorf("current evaluator mode=%s is not an async strict evaluator", s.CurrentEvaluatorMode())
	}

	task, err := asyncEvaluator.Prepare(EvaluationInput{
		Plan:     plan,
		Evidence: evidence,
		Snapshot: snapshot,
		Session:  session,
	})
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_TASK_ISSUED", err, map[string]any{"mode": s.evaluator.Mode()})
	}

	s.store.SaveTaskSpec(task)

	session.TaskSpecID = task.ID
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T4_TASK_ISSUED",
		FromState: string(session.State),
		ToState:   string(session.State),
		Note:      "strict MPC public task spec 已发布，等待 3 个 party agents 本地执行 MPC",
		Meta: map[string]any{
			"task_id":           task.ID,
			"request_id":        task.RequestID,
			"task_manifest":     task.ManifestDigest,
			"result_submit_url": task.ResultCallback.SubmitURL,
		},
		At: time.Now(),
	})

	return task, session, nil
}

// SubmitMPCResult 接收 strict MPC runtime 的最小结果回执，校验后正式进入 DECIDED。
func (s *Service) SubmitMPCResult(sessionID string, receipt *model.StrictMPCResultReceipt) (*model.EvaluationResult, *model.ExecutionSession, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if err := ensureSessionActive(session); err != nil {
		return nil, session, err
	}
	if session.TaskSpecID == "" {
		return nil, session, fmt.Errorf("session has no issued strict MPC task")
	}
	if session.EvaluationID != "" {
		eval, evalErr := s.store.GetEvaluation(session.EvaluationID)
		if evalErr == nil {
			return eval, session, nil
		}
	}

	task, err := s.store.GetTaskSpec(session.TaskSpecID)
	if err != nil {
		return nil, session, err
	}
	plan, evidence, snapshot, err := s.loadEvaluationBindings(session)
	if err != nil {
		return nil, session, err
	}

	asyncEvaluator, ok := s.evaluator.(AsyncTaskEvaluator)
	if !ok {
		return nil, session, fmt.Errorf("current evaluator mode=%s is not an async strict evaluator", s.CurrentEvaluatorMode())
	}

	result, err := asyncEvaluator.Complete(EvaluationInput{
		Plan:     plan,
		Evidence: evidence,
		Snapshot: snapshot,
		Session:  session,
	}, task, receipt)
	if err != nil {
		return nil, session, s.rejectSession(session, "T4_DECISION", err, map[string]any{"mode": s.evaluator.Mode()})
	}

	return s.persistEvaluationResult(session, result)
}

func (s *Service) persistEvaluationResult(session *model.ExecutionSession, result *model.EvaluationResult) (*model.EvaluationResult, *model.ExecutionSession, error) {
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

	from := session.State
	session.EvaluationID = result.ID
	session.State = model.SessionStateDecided
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T4_DECISION",
		FromState: string(from),
		ToState:   string(session.State),
		Note:      fmt.Sprintf("策略评估完成，决策结果为 %s", result.Decision),
		Meta: map[string]any{
			"evaluation_id": result.ID,
			"decision":      result.Decision,
			"mode":          result.EvaluatorMode,
			"backend_mode":  result.BackendMode,
		},
		At: time.Now(),
	})

	return result, session, nil
}

// SealArtifact 生成授权工件，并将会话推进到 Enforced。
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

	var taskManifestDigest string
	var receiptDigest string
	if session.TaskSpecID != "" {
		if task, taskErr := s.store.GetTaskSpec(session.TaskSpecID); taskErr == nil {
			taskManifestDigest = task.ManifestDigest
		}
	}
	if evaluation.SecureExecution != nil && evaluation.SecureExecution.Receipt != nil {
		receiptDigest = evaluation.SecureExecution.Receipt.ResultDigest
	}

	contextDigest := hash.AnySHA256Hex(session.Context)

	artifact := &model.AuthorizationArtifact{
		ID:                    id.New("artifact"),
		SessionID:             session.ID,
		PolicyDigest:          policy.Digest,
		EvidenceDigest:        evidence.EvidenceDigest,
		LifecycleDigest:       snapshot.SnapshotDigest,
		ContextDigest:         contextDigest,
		TaskManifestDigest:    taskManifestDigest,
		ResultReceiptDigest:   receiptDigest,
		AuthorizationDecision: evaluation.Decision,
		Context:               session.Context,
		CreatedAt:             time.Now(),
	}

	artifact.Signature = hash.AnySHA256Hex(map[string]any{
		"session_id":           artifact.SessionID,
		"policy_digest":        artifact.PolicyDigest,
		"evidence_digest":      artifact.EvidenceDigest,
		"lifecycle_digest":     artifact.LifecycleDigest,
		"context_digest":       artifact.ContextDigest,
		"task_manifest_digest": artifact.TaskManifestDigest,
		"result_receipt":       artifact.ResultReceiptDigest,
		"decision":             artifact.AuthorizationDecision,
		"context":              artifact.Context,
	})
	artifact.ArtifactDigest = hash.AnySHA256Hex(artifact)

	s.store.SaveArtifact(artifact)

	from := session.State
	session.ArtifactID = artifact.ID
	session.State = model.SessionStateEnforced
	session.UpdatedAt = time.Now()
	s.store.SaveSession(session)

	s.store.AppendEvent(&model.TransitionEvent{
		ID:        id.New("event"),
		PolicyID:  session.PolicyID,
		SessionID: session.ID,
		Action:    "T5_ARTIFACT_AND_ENFORCEMENT",
		FromState: string(from),
		ToState:   string(session.State),
		Note:      "授权工件已生成，结果已可被数据服务呈现/记录",
		Meta: map[string]any{
			"artifact_id":           artifact.ID,
			"artifact_digest":       artifact.ArtifactDigest,
			"result_receipt_digest": artifact.ResultReceiptDigest,
		},
		At: time.Now(),
	})

	return artifact, session, nil
}

// ------------------------------------------------------------
// 查询接口
// ------------------------------------------------------------

func (s *Service) GetPolicy(policyID string) (*model.Policy, error) {
	return s.store.GetPolicy(policyID)
}

func (s *Service) GetPlan(planID string) (*model.EnforcementPlan, error) {
	return s.store.GetPlan(planID)
}

func (s *Service) GetSession(sessionID string) (*model.ExecutionSession, error) {
	return s.store.GetSession(sessionID)
}

func (s *Service) GetTaskSpecBySession(sessionID string) (*model.StrictMPCTaskSpec, error) {
	session, err := s.store.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.TaskSpecID == "" {
		return nil, fmt.Errorf("session has no task spec")
	}
	return s.store.GetTaskSpec(session.TaskSpecID)
}

func (s *Service) GetArtifact(artifactID string) (*model.AuthorizationArtifact, error) {
	return s.store.GetArtifact(artifactID)
}

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
	if session.TaskSpecID != "" {
		bundle.TaskSpec, _ = s.store.GetTaskSpec(session.TaskSpecID)
	}
	if session.EvaluationID != "" {
		bundle.Evaluation, _ = s.store.GetEvaluation(session.EvaluationID)
	}
	if session.ArtifactID != "" {
		bundle.Artifact, _ = s.store.GetArtifact(session.ArtifactID)
	}

	return bundle, nil
}

// ------------------------------------------------------------
// 内部辅助函数
// ------------------------------------------------------------

func (s *Service) loadEvaluationBindings(session *model.ExecutionSession) (*model.EnforcementPlan, *model.EvidenceRecord, *model.PinnedSnapshot, error) {
	plan, err := s.store.GetPlan(session.PlanID)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(plan.Clauses) == 0 {
		return nil, nil, nil, fmt.Errorf("plan clauses missing")
	}

	evidence, err := s.store.GetEvidence(session.EvidenceID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bound evidence missing: %w", err)
	}

	snapshot, err := s.store.GetSnapshot(session.SnapshotID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bound snapshot missing: %w", err)
	}

	return plan, evidence, snapshot, nil
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
	from := session.State

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
		FromState: string(from),
		ToState:   string(model.SessionStateRejected),
		Note:      "session rejected due to governance/state-machine violation",
		Meta:      meta,
		At:        now,
	})

	return cause
}

// normalizeClauses：
// 1. 统一 source / op / owner 大小写；
// 2. 若 owner 为空，则按 source 自动补默认值；
// 3. 这里把 context 默认 owner 改成 authority，更符合 strict MPC 的三方划分。
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
			case model.ClauseSourceEvidence:
				normalized.Owner = model.ClauseOwnerRequester
			case model.ClauseSourceSnapshot:
				normalized.Owner = model.ClauseOwnerProvider
			case model.ClauseSourceContext:
				normalized.Owner = model.ClauseOwnerAuthority
			}
		}

		out = append(out, normalized)
	}
	return out
}

func buildOwnershipPartition(clauses []model.Clause) map[string][]model.OwnedField {
	result := map[string][]model.OwnedField{
		model.ClauseOwnerRequester: {},
		model.ClauseOwnerProvider:  {},
		model.ClauseOwnerAuthority: {},
	}
	seen := map[string]map[string]struct{}{
		model.ClauseOwnerRequester: {},
		model.ClauseOwnerProvider:  {},
		model.ClauseOwnerAuthority: {},
	}

	for _, clause := range clauses {
		owner := strings.TrimSpace(clause.Owner)
		key := clause.Source + "." + clause.Field
		if _, ok := result[owner]; !ok {
			result[owner] = []model.OwnedField{}
			seen[owner] = map[string]struct{}{}
		}
		if _, ok := seen[owner][key]; ok {
			continue
		}
		seen[owner][key] = struct{}{}
		result[owner] = append(result[owner], model.OwnedField{
			Source: clause.Source,
			Field:  clause.Field,
		})
	}

	return result
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

func buildAdmittedViewForPlainBaseline(payload map[string]any, allowedKeys []string) map[string]any {
	admittedView := make(map[string]any)
	for _, key := range allowedKeys {
		if v, ok := payload[key]; ok {
			admittedView[key] = v
		}
	}
	return admittedView
}

func readString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
