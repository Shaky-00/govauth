package workflow

import (
	"fmt"
	"govauth/internal/domain/model"
	"govauth/internal/pkg/hash"
	"os"
	"strings"
	"time"
)

type StrictMPCBackend interface {
	Mode() string
	PrepareTask(req *model.SecureExecutionRequest) (*model.StrictMPCTaskSpec, error)
	VerifyReceipt(task *model.StrictMPCTaskSpec, receipt *model.StrictMPCResultReceipt) (*model.SecureExecutionResult, error)
}

// 兼容old version
func NewSecureBackendByMode(mode string) (StrictMPCBackend, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", model.SecureBackendModeStrictMPyC, model.SecureBackendModeRealMPC:
		return NewStrictMPyCBackend(), nil
	default:
		return nil, fmt.Errorf("unknown secure backend mode: %s", mode)
	}
}

// ------------------------------------------------------------
// StrictMPyCBackend
// ------------------------------------------------------------

// StrictMPyCBackend 的职责：
// 1. 根据已绑定的 plan/evidence_digest/snapshot_digest/context_digest 生成 public task spec；
// 2. 在 receipt 回传后做绑定一致性校验；
// 3. 生成 GovAuth 侧的 SecureExecutionResult；
// 4. 它不启动 MPC，不接触 party 私有值，不生成 party input 文件。
type StrictMPyCBackend struct {
	baseURL string
}

func NewStrictMPyCBackend() *StrictMPyCBackend {
	return &StrictMPyCBackend{
		baseURL: getenvDefault("GOVAUTH_BASE_URL", "http://127.0.0.1:8080"),
	}
}

func (b *StrictMPyCBackend) Mode() string {
	return model.SecureBackendModeStrictMPyC
}

func (b *StrictMPyCBackend) PrepareTask(req *model.SecureExecutionRequest) (*model.StrictMPCTaskSpec, error) {
	if req == nil {
		return nil, fmt.Errorf("secure execution request is nil")
	}
	if req.Plan == nil {
		return nil, fmt.Errorf("secure execution request missing plan")
	}
	if len(req.Clauses) == 0 {
		return nil, fmt.Errorf("secure execution request missing clauses")
	}
	if strings.TrimSpace(req.EvidenceDigest) == "" {
		return nil, fmt.Errorf("strict MPC requires bound evidence digest")
	}
	if strings.TrimSpace(req.SnapshotDigest) == "" {
		return nil, fmt.Errorf("strict MPC requires bound snapshot digest")
	}
	if strings.TrimSpace(req.ContextDigest) == "" {
		return nil, fmt.Errorf("strict MPC requires bound context digest")
	}

	task := &model.StrictMPCTaskSpec{
		ID:                 "task-" + hash.AnySHA256Hex(map[string]any{"request_id": req.RequestID, "time": time.Now().UnixNano()})[:16],
		RequestID:          req.RequestID,
		SessionID:          req.SessionID,
		PolicyID:           req.PolicyID,
		PlanID:             req.PlanID,
		EvaluatorMode:      req.EvaluatorMode,
		BackendMode:        b.Mode(),
		Clauses:            make([]model.StrictMPCTaskClause, 0, len(req.Clauses)),
		OwnershipPartition: req.Plan.OwnershipPartition,
		BindingInfo: map[string]any{
			"policy_digest":     req.Plan.DerivedFromPolicyDigest,
			"evidence_digest":   req.EvidenceDigest,
			"snapshot_digest":   req.SnapshotDigest,
			"context_digest":    req.ContextDigest,
			"binding_template":  req.Plan.BindingTemplate,
			"complied_function": req.Plan.CompiledFunction,
			"resource_id":       req.BindingInfo["resource_id"],
		},
		ResultCallback: model.ResultCallbackSpec{
			SubmitURL: fmt.Sprintf("%s/api/v1/sessions/%s/mpc-result", strings.TrimRight(b.baseURL, "/"), req.SessionID),
		},
		Metadata: map[string]any{
			"policy_relevant_evidence_keys": req.Plan.PolicyRelevantEvidenceKeys,
			"required_state_dependencies":   req.Plan.RequiredStateDependencies,
			"clause_count":                  len(req.Clauses),
			"party_count":                   len(req.Plan.OwnershipPartition),
			"supported_ops": []string{
				model.ClauseOpEq,
				model.ClauseOpNeq,
				model.ClauseOpGt,
				model.ClauseOpGte,
				model.ClauseOpLt,
				model.ClauseOpLte,
			},
		},
		CreatedAt: time.Now(),
	}

	for idx, clause := range req.Clauses {
		owner := strings.ToLower(strings.TrimSpace(clause.Owner))
		ownerIndex, err := ownerToIndex(owner)
		if err != nil {
			return nil, err
		}

		expectedValue := fmt.Sprintf("%v", clause.Value)
		expectedEncoding, err := expectedEncodingForOp(clause.Op)
		if err != nil {
			return nil, err
		}

		task.Clauses = append(task.Clauses, model.StrictMPCTaskClause{
			ClauseID:         fmt.Sprintf("clause_%d", idx),
			Owner:            owner,
			OwnerIndex:       ownerIndex,
			Source:           strings.ToLower(strings.TrimSpace(clause.Source)),
			Field:            strings.TrimSpace(clause.Field),
			Op:               strings.ToLower(strings.TrimSpace(clause.Op)),
			ExpectedValue:    expectedValue,
			ExpectedEncoding: expectedEncoding,
		})
	}

	task.ManifestDigest = hash.AnySHA256Hex(map[string]any{
		"id":                  task.ID,
		"request_id":          task.RequestID,
		"session_id":          task.SessionID,
		"policy_id":           task.PolicyID,
		"plan_id":             task.PlanID,
		"clauses":             task.Clauses,
		"ownership_partition": task.OwnershipPartition,
		"binding_info":        task.BindingInfo,
		"metadata":            task.Metadata,
	})

	return task, nil
}

func (b *StrictMPyCBackend) VerifyReceipt(
	task *model.StrictMPCTaskSpec,
	receipt *model.StrictMPCResultReceipt,
) (*model.SecureExecutionResult, error) {
	if task == nil {
		return nil, fmt.Errorf("strict receipt verification missing task spec")
	}
	if receipt == nil {
		return nil, fmt.Errorf("strict receipt verification missing receipt")
	}

	if strings.TrimSpace(receipt.TaskID) != task.ID {
		return nil, fmt.Errorf("receipt task_id mismatch")
	}
	if strings.TrimSpace(receipt.RequestID) != task.RequestID {
		return nil, fmt.Errorf("receipt request_id mismatch")
	}
	if strings.TrimSpace(receipt.SessionID) != task.SessionID {
		return nil, fmt.Errorf("receipt session_id mismatch")
	}
	if strings.TrimSpace(receipt.PlanID) != task.PlanID {
		return nil, fmt.Errorf("receipt plan_id mismatch")
	}
	if receipt.ClauseCount != len(task.Clauses) {
		return nil, fmt.Errorf("receipt clause_count mismatch")
	}
	if strings.TrimSpace(receipt.TranscriptDigest) == "" {
		return nil, fmt.Errorf("receipt transcript_digest is required")
	}
	if receipt.Decision != model.DecisionAllow && receipt.Decision != model.DecisionDeny {
		return nil, fmt.Errorf("receipt decision invalid: %s", receipt.Decision)
	}
	if receipt.SubmittedAt.IsZero() {
		receipt.SubmittedAt = time.Now()
	}
	if strings.TrimSpace(receipt.ResultDigest) == "" {
		receipt.ResultDigest = hash.AnySHA256Hex(map[string]any{
			"task_id":           receipt.TaskID,
			"request_id":        receipt.RequestID,
			"session_id":        receipt.SessionID,
			"plan_id":           receipt.PlanID,
			"decision":          receipt.Decision,
			"clause_count":      receipt.ClauseCount,
			"transcript_digest": receipt.TranscriptDigest,
			"metadata":          receipt.Metadata,
		})
	}
	if strings.TrimSpace(receipt.ProofReceipt) == "" {
		receipt.ProofReceipt = hash.AnySHA256Hex(map[string]any{
			"result_digest": receipt.ResultDigest,
			"task_digest":   task.ManifestDigest,
		})
	}

	reason := "strict MPC result receipt verified and bound to task spec"
	if receipt.Decision == model.DecisionDeny {
		reason = "strict MPC result receipt verified with DENY outcome"
	}

	return &model.SecureExecutionResult{
		ExecutionID:      "secure-exec-" + hash.AnySHA256Hex(map[string]any{"task_id": task.ID, "time": time.Now().UnixNano()})[:16],
		TaskID:           task.ID,
		SessionID:        task.SessionID,
		BackendMode:      b.Mode(),
		Decision:         receipt.Decision,
		Reason:           reason,
		TranscriptDigest: receipt.TranscriptDigest,
		Receipt:          receipt,
		Steps: []model.SecureExecutionStep{
			{
				Name:   "verify_task_binding",
				Status: "ok",
				Detail: "task_id / request_id / session_id / plan_id are consistent",
			},
			{
				Name:   "verify_result_receipt",
				Status: "ok",
				Detail: "decision / clause_count / transcript_digest are structurally valid",
			},
			{
				Name:   "materialize_secure_result",
				Status: "ok",
				Detail: fmt.Sprintf("decision=%s", receipt.Decision),
			},
		},
		Metadata: map[string]any{
			"task_manifest_digest": task.ManifestDigest,
			"proof_receipt":        receipt.ProofReceipt,
			"result_digest":        receipt.ResultDigest,
			"submitted_by":         receipt.SubmittedBy,
		},
		ExecutedAt: time.Now(),
	}, nil
}

func ownerToIndex(owner string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(owner)) {
	case model.ClauseOwnerRequester:
		return 0, nil
	case model.ClauseOwnerProvider:
		return 1, nil
	case model.ClauseOwnerAuthority:
		return 2, nil
	default:
		return 0, fmt.Errorf("unsupported owner: %s", owner)
	}
}

func expectedEncodingForOp(op string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case model.ClauseOpEq, model.ClauseOpNeq:
		return "eq_hash", nil
	case model.ClauseOpGt, model.ClauseOpGte, model.ClauseOpLt, model.ClauseOpLte:
		return "int_compare", nil
	default:
		return "", fmt.Errorf("unsupported op: %s", op)
	}
}

// getenvDefault
// 读取环境变量，如果为空则返回默认值
func getenvDefault(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}
