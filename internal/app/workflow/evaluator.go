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
	Mode() string // 当前evaluator模式（plain / secure_stub）

	Evaluate(in EvaluationInput) (*model.EvaluationResult, error)
}

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

// SecureOrchestratingEvaluator 正式的安全执行编排器
// 主要负责：
// 1. build secure input package
// 2. assemble secure execution request
// 3. call secure backend
// 4. map backend result to evaluation result
type SecureOrchestratingEvaluator struct {
	mode    string
	backend SecureBackend
}

func NewSecureOrchestratingEvaluator(backend SecureBackend) *SecureOrchestratingEvaluator {
	if backend == nil {
		backend = NewMockMPCBackend()
	}
	return &SecureOrchestratingEvaluator{
		mode:    model.EvaluatorModeSecureOrchestrating,
		backend: backend,
	}
}

// 兼容 Secure_stub

// SecureStubEvaluator: 按照owner拆分输入，构造多方输入视图，先本地模拟安全求值、
// type SecureStubEvaluator struct{}

func NewSecureStubEvaluator() *SecureOrchestratingEvaluator {
	return &SecureOrchestratingEvaluator{
		mode:    model.EvaluatorModeSecureStub,
		backend: NewMockMPCBackend(),
	}
}

func (e *SecureOrchestratingEvaluator) Mode() string {
	if e == nil || strings.TrimSpace(e.mode) == "" {
		return model.EvaluatorModeSecureOrchestrating
	}
	return e.mode
}

func (e *SecureOrchestratingEvaluator) Evaluate(in EvaluationInput) (*model.EvaluationResult, error) {
	if err := validateEvaluationInput(in); err != nil {
		return nil, err
	}
	if e.backend == nil {
		return nil, fmt.Errorf("secure orchestrating evaluator missing backend")
	}

	pkg, err := buildSecureInputPackage(in)
	if err != nil {
		return nil, err
	}

	req := assembleSecureExecutionRequest(in, e.mode, e.backend.Mode(), pkg)

	secureResult, err := e.backend.Execute(req)
	if err != nil {
		return nil, err
	}

	return mapSecureExecutionToEvaluationResult(in, e.mode, secureResult), nil
}

// Warning：当前GovAuth能够看到多party的输入
func buildSecureInputPackage(in EvaluationInput) (*model.SecureInputPackage, error) {
	partyView := buildSecurePartyView(in)
	parties := make([]model.SecurePartyInput, 0, len(partyView))
	totalFieldCount := 0

	orderedOwners := []string{
		model.ClauseOwnerRequester,
		model.ClauseOwnerProvider,
		model.ClauseOwnerAuthority,
	}

	partyCount := len(orderedOwners)
	threshold := 1
	if partyCount >= 3 {
		// MPyC 的经典半诚实门限通常要求 t < m/2。
		// 在 3 方时，t=1 是自然选择。
		threshold = 1
	}

	for _, owner := range orderedOwners {
		sourceView := partyView[owner]
		if sourceView == nil {
			sourceView = map[string]map[string]any{}
		}

		encodedInputs := encodeSecureInputs(owner, sourceView, partyCount)
		shareMap := flattenEncodedInputMap(encodedInputs)
		fieldCount := countSecureFields(sourceView)

		parties = append(parties, model.SecurePartyInput{
			Party:         owner,
			Inputs:        sourceView,
			EncodedInputs: encodedInputs,
			ShareMap:      shareMap,
			Meta: map[string]any{
				"field_count": fieldCount,
				"share_count": len(shareMap),
				"threshold":   threshold,
				"share_ready": true,
			},
		})
		totalFieldCount += fieldCount
	}

	return &model.SecureInputPackage{
		PackageID: "pkd-" + hash.AnySHA256Hex(map[string]any{
			"session_id":  in.Session.ID,
			"plan_id":     in.Plan.ID,
			"built_at":    time.Now().UnixNano(),
			"party_count": len(parties),
		})[:16],
		SessionID:       in.Session.ID,
		PolicyID:        in.Session.PolicyID,
		PlanID:          in.Session.PlanID,
		Parties:         parties,
		PartyCount:      partyCount,
		Threshold:       threshold,
		ClauseCount:     len(in.Plan.Clauses),
		TotalFieldCount: totalFieldCount,
		BuiltAt:         time.Now(),
	}, nil
}

func assembleSecureExecutionRequest(
	in EvaluationInput,
	evaluatorMode string,
	backendMode string,
	pkg *model.SecureInputPackage,
) *model.SecureExecutionRequest {
	return &model.SecureExecutionRequest{
		RequestID: "req-" + hash.AnySHA256Hex(map[string]any{
			"session_id":     in.Session.ID,
			"plan_id":        in.Plan.ID,
			"evaluator_mode": evaluatorMode,
			"backend_mode":   backendMode,
			"time":           time.Now().UnixNano(),
		})[:16],
		SessionID:     in.Session.ID,
		PolicyID:      in.Session.PolicyID,
		PlanID:        in.Plan.ID,
		EvaluatorMode: evaluatorMode,
		BackendMode:   backendMode,
		Clauses:       in.Plan.Clauses,
		InputPackage:  pkg,
		ExecutionHints: map[string]any{
			"resource_id":              in.Session.ResourceID,
			"release_binding_required": in.Plan.ReleaseBindingRequired,
			"canonical_policy":         in.Plan.ExecutionHints["canonical_policy"],
			"clause_count":             len(in.Plan.Clauses),
			"party_count":              pkg.PartyCount,
			"threshold":                pkg.Threshold,
		},
		RequestedAt: time.Now(),
	}
}

func mapSecureExecutionToEvaluationResult(
	in EvaluationInput,
	evaluatorMode string,
	secureResult *model.SecureExecutionResult,
) *model.EvaluationResult {
	reason := ""
	backendMode := ""
	evaluatedAt := time.Now()
	decision := model.DecisionDeny

	if secureResult != nil {
		reason = secureResult.Reason
		backendMode = secureResult.BackendMode
		decision = secureResult.Decision
		if !secureResult.ExecutedAt.IsZero() {
			evaluatedAt = secureResult.ExecutedAt
		}
	}

	return &model.EvaluationResult{
		SessionID:       in.Session.ID,
		Decision:        decision,
		Reason:          reason,
		EvaluatorMode:   evaluatorMode,
		BackendMode:     backendMode,
		SecureExecution: secureResult,
		EvaluatedAt:     evaluatedAt,
	}
}

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

		// switch clause.Op {
		// case model.ClauseOpEq:
		// 	if !strings.EqualFold(actual, expected) {
		// 		decision = model.DecisionDeny
		// 		reasons = append(reasons, fmt.Sprintf("%s.%s mismatch (owner=%s)", clause.Source, clause.Field, clause.Owner))
		// 	}
		// default:
		// 	decision = model.DecisionDeny
		// 	reasons = append(reasons, fmt.Sprintf("unsupported op %s", clause.Op))
		// }
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

// 构造secure stub的多方输入视图
// 结构含义：owner -> source -> field -> value
func buildSecurePartyView(in EvaluationInput) map[string]map[string]map[string]any {
	view := map[string]map[string]map[string]any{
		model.ClauseOwnerRequester: {},
		model.ClauseOwnerProvider:  {},
		model.ClauseOwnerAuthority: {},
	}

	for _, clause := range in.Plan.Clauses {
		owner := strings.TrimSpace(clause.Owner)
		source := strings.TrimSpace(clause.Source)
		field := strings.TrimSpace(clause.Field)

		if owner == "" || source == "" || field == "" {
			continue
		}

		if _, ok := view[owner]; !ok {
			view[owner] = map[string]map[string]any{}
		}
		if _, ok := view[owner][source]; !ok {
			view[owner][source] = map[string]any{}
		}

		actual, err := resolveClauseActualValue(clause, in.Evidence, in.Snapshot, in.Session)
		if err != nil {
			continue
		}

		view[owner][source][field] = actual
	}

	return view
}

// 统计某个owner视图下总共装了多少个字段，便于输出调试信息
func countSecureFields(ownerView map[string]map[string]any) int {
	total := 0
	for _, sourceView := range ownerView {
		total += len(sourceView)
	}
	return total
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
