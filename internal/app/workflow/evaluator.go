package workflow

import (
	"fmt"
	"govauth/internal/domain/model"
	"govauth/internal/pkg/hash"
	"math"
	"strconv"
	"strings"
	"time"
)

type EvaluationInput struct {
	Plan     *model.EnforcementPlan
	Evidence *model.EvidenceRecord
	Snapshot *model.PinnedSnapshot
	Session  *model.ExecutionSession
}

type Evaluator interface {
	Mode() string
}

// SyncEvaluator 表示“在 GovAuth 内同步完成决策”的 evaluator。
// 目前只有 plain baseline 使用。
type SyncEvaluator interface {
	Evaluator
	Evaluate(in EvaluationInput) (*model.EvaluationResult, error)
}

// AsyncTaskEvaluator 表示两阶段 strict MPC evaluator：
// 1. GovAuth 先prepare一个public task spec
// 2. 外部 party agents 运行MPC
// 3. GovAuth 再用 Complete 对最小 receipt 做绑定校验并落盘
type AsyncTaskEvaluator interface {
	Evaluator
	Prepare(in EvaluationInput) (*model.StrictMPCTaskSpec, error)
	Complete(in EvaluationInput, task *model.StrictMPCTaskSpec, receipt *model.StrictMPCResultReceipt) (*model.EvaluationResult, error)
}

// ------------------------------------------------------------
// PlainEvaluator：仅作为 baseline 保留
// ------------------------------------------------------------

type PlainEvaluator struct{}

func NewPlainEvaluator() *PlainEvaluator {
	return &PlainEvaluator{}
}

func (e *PlainEvaluator) Mode() string {
	return model.EvaluatorModePlain
}

func (e *PlainEvaluator) Evaluate(in EvaluationInput) (*model.EvaluationResult, error) {
	if err := validateEvaluationInput(in); err != nil {
		return nil, err
	}

	decision, reasons := evaluateClauses(in.Plan.Clauses, in.Evidence, in.Snapshot, in.Session)

	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("plan %s verified all clauses successfully", in.Plan.ID))
	}

	return &model.EvaluationResult{
		SessionID:     in.Session.ID,
		Decision:      decision,
		Reason:        strings.Join(reasons, "; "),
		EvaluatorMode: e.Mode(),
		BackendMode:   model.SecureBackendModeLocalPlain,
		EvaluatedAt:   time.Now(),
	}, nil
}

// ------------------------------------------------------------
// StrictMPCEvaluator：GovAuth 不再接触私有输入明文
// ------------------------------------------------------------

type StrictMPCEvaluator struct {
	backend StrictMPCBackend
}

func NewStrictMPCEvaluator(backend StrictMPCBackend) *StrictMPCEvaluator {
	return &StrictMPCEvaluator{backend: backend}
}

func (e *StrictMPCEvaluator) Mode() string {
	return model.EvaluatorModeStrictMPC
}

// Prepare 只生成公开 task spec，不读取也不拼接各方私有值
func (e *StrictMPCEvaluator) Prepare(in EvaluationInput) (*model.StrictMPCTaskSpec, error) {
	if err := validateEvaluationInput(in); err != nil {
		return nil, err
	}
	if e.backend == nil {
		return nil, fmt.Errorf("strict MPC evaluator missing backend")
	}

	req := assembleStrictExecutionRequest(in, e.backend.Mode())
	return e.backend.PrepareTask(req)
}

// Complete 只对 MPC receipt 做绑定校验与结构化落盘
func (e *StrictMPCEvaluator) Complete(
	in EvaluationInput,
	task *model.StrictMPCTaskSpec,
	receipt *model.StrictMPCResultReceipt,
) (*model.EvaluationResult, error) {
	if err := validateEvaluationInput(in); err != nil {
		return nil, err
	}
	if task == nil {
		return nil, fmt.Errorf("strict MPC completion missing task spec")
	}
	if receipt == nil {
		return nil, fmt.Errorf("strict MPC completion missing receipt")
	}
	if e.backend == nil {
		return nil, fmt.Errorf("strict MPC evaluator missing backend")
	}

	secureResult, err := e.backend.VerifyReceipt(task, receipt)
	if err != nil {
		return nil, err
	}

	return &model.EvaluationResult{
		SessionID:       in.Session.ID,
		Decision:        secureResult.Decision,
		Reason:          secureResult.Reason,
		EvaluatorMode:   e.Mode(),
		BackendMode:     secureResult.BackendMode,
		SecureExecution: secureResult,
		EvaluatedAt:     secureResult.ExecutedAt,
	}, nil
}

// assembleStrictExecutionRequest 构造 strict backend 所需的公共任务描述。
// 这里显式只传 digest / binding，不传 party 私有值。
func assembleStrictExecutionRequest(in EvaluationInput, backendMode string) *model.SecureExecutionRequest {
	contextDigest := hash.AnySHA256Hex(in.Session.Context)

	return &model.SecureExecutionRequest{
		RequestID: "req-" + hash.AnySHA256Hex(map[string]any{
			"session_id":   in.Session.ID,
			"plan_id":      in.Plan.ID,
			"backend_mode": backendMode,
			"time":         time.Now().UnixNano(),
		})[:16],
		SessionID:      in.Session.ID,
		PolicyID:       in.Session.PolicyID,
		PlanID:         in.Plan.ID,
		EvaluatorMode:  model.EvaluatorModeStrictMPC,
		BackendMode:    backendMode,
		Plan:           in.Plan,
		Clauses:        in.Plan.Clauses,
		EvidenceDigest: safeDigestOrEmpty(in.Evidence.EvidenceDigest),
		SnapshotDigest: safeDigestOrEmpty(in.Snapshot.SnapshotDigest),
		ContextDigest:  contextDigest,
		BindingInfo: map[string]any{
			"policy_digest":             in.Plan.DerivedFromPolicyDigest,
			"evidence_digest":           safeDigestOrEmpty(in.Evidence.EvidenceDigest),
			"snapshot_digest":           safeDigestOrEmpty(in.Snapshot.SnapshotDigest),
			"context_digest":            contextDigest,
			"release_binding_required":  in.Plan.ReleaseBindingRequired,
			"compiled_function":         in.Plan.CompiledFunction,
			"ownership_partition":       in.Plan.OwnershipPartition,
			"resource_id":               in.Session.ResourceID,
			"session_public_context":    in.Session.Context,
			"policy_relevant_evidence":  in.Plan.PolicyRelevantEvidenceKeys,
			"required_state_dependency": in.Plan.RequiredStateDependencies,
		},
		RequestedAt: time.Now(),
	}
}

func safeDigestOrEmpty(v string) string {
	return strings.TrimSpace(v)
}

// ------------------------------------------------------------
// Plain baseline 下的最小 clause evaluator
// ------------------------------------------------------------

// 最小可运行 clause evaluator
func evaluateClauses(
	clauses []model.Clause,
	evidence *model.EvidenceRecord,
	snapshot *model.PinnedSnapshot,
	session *model.ExecutionSession,
) (model.Decision, []string) {
	decision := model.DecisionAllow
	reasons := make([]string, 0)

	for _, clause := range clauses {
		expected := toString(clause.Value)

		actual, err := resolveClauseActualValue(clause, evidence, snapshot, session)
		if err != nil {
			decision = model.DecisionDeny
			reasons = append(reasons, err.Error())
			continue
		}

		ok, cmpErr := compareClauseValues(clause.Op, actual, expected)
		if cmpErr != nil {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("invalid clause at %s.%s (owner=%s, op=%s): %v",
					clause.Source, clause.Field, clause.Owner, clause.Op, cmpErr))
			continue
		}

		if !ok {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("%s.%s mismatch (owner=%s, op=%s, actual=%s, expected=%s)",
					clause.Source, clause.Field, clause.Owner, clause.Op, actual, expected))
		}
	}

	return decision, reasons
}

// 校验统一输入
func validateEvaluationInput(in EvaluationInput) error {
	if in.Plan == nil {
		return fmt.Errorf("evaluation input missing plan")
	}
	if in.Evidence == nil {
		return fmt.Errorf("evaluation input missing evidence")
	}
	if in.Snapshot == nil {
		return fmt.Errorf("evaluation input missing snapshot")
	}
	if in.Session == nil {
		return fmt.Errorf("evaluation input missing session")
	}
	if len(in.Plan.Clauses) == 0 {
		return fmt.Errorf("plan clauses missing")
	}
	return nil
}

// 根据clause的source从对应视图取值
func resolveClauseActualValue(
	clause model.Clause,
	evidence *model.EvidenceRecord,
	snapshot *model.PinnedSnapshot,
	session *model.ExecutionSession,
) (string, error) {
	switch clause.Source {
	case model.ClauseSourceEvidence:
		return toString(evidence.AdmittedView[clause.Field]), nil
	case model.ClauseSourceSnapshot:
		return toString(snapshot.Payload[clause.Field]), nil
	case model.ClauseSourceContext:
		return toString(session.Context[clause.Field]), nil
	default:
		return "", fmt.Errorf("unknown source %s", clause.Source)
	}
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// compareClauseValues
// 规则：
// 1. eq / neq 支持字符串大小写无关比较；
// 2. gt / gte / lt / lte 仅支持整数语义；
// 3. 若比较类操作碰到非整数值，则返回错误。
func compareClauseValues(op string, actual string, expected string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case model.ClauseOpEq:
		return strings.EqualFold(actual, expected), nil
	case model.ClauseOpNeq:
		return !strings.EqualFold(actual, expected), nil
	case model.ClauseOpGt, model.ClauseOpGte, model.ClauseOpLt, model.ClauseOpLte:
		actualInt, err := parseIntegerString(actual)
		if err != nil {
			return false, fmt.Errorf("actual value %q is not an integer", actual)
		}

		expectedInt, err := parseIntegerString(expected)
		if err != nil {
			return false, fmt.Errorf("expected value %q is not an integer", expected)
		}

		switch strings.ToLower(strings.TrimSpace(op)) {
		case model.ClauseOpGt:
			return actualInt > expectedInt, nil
		case model.ClauseOpGte:
			return actualInt >= expectedInt, nil
		case model.ClauseOpLt:
			return actualInt < expectedInt, nil
		case model.ClauseOpLte:
			return actualInt <= expectedInt, nil
		}
	}

	return false, fmt.Errorf("unsupported op %s", op)
}

func parseIntegerString(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, fmt.Errorf("empty numeric value")
	}

	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse integer from %q", raw)
	}

	if math.Trunc(f) != f {
		return 0, fmt.Errorf("non-integer numeric value %q", raw)
	}

	if f > math.MaxInt64 || f < math.MinInt64 {
		return 0, fmt.Errorf("integer out of int64 range: %q", raw)
	}

	return int64(f), nil
}
