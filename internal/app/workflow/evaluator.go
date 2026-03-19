package workflow

import (
	"fmt"
	"govauth/internal/domain/model"
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
	if in.Plan == nil {
		return nil, fmt.Errorf("evaluation input missing plan")
	}
	if in.Evidence == nil {
		return nil, fmt.Errorf("evaluation input missing evidence")
	}
	if in.Snapshot == nil {
		return nil, fmt.Errorf("evaluation input missing snapshot")
	}
	if in.Session == nil {
		return nil, fmt.Errorf("evaluation input missing session")
	}
	if len(in.Plan.Clauses) == 0 {
		return nil, fmt.Errorf("plan clauses missing")
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
		EvaluatedAt:   time.Now(),
	}, nil
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

		var actual string
		switch clause.Source {
		case model.ClauseSourceEvidence:
			actual = toString(evidence.AdmittedView[clause.Field])
		case model.ClauseSourceSnapshot:
			actual = toString(snapshot.Payload[clause.Field])
		case model.ClauseSourceContext:
			actual = toString(session.Context[clause.Field])

		default:
			decision = model.DecisionDeny
			reasons = append(reasons, fmt.Sprintf("unknown source %s", clause.Source))
			continue
		}

		switch clause.Op {
		case model.ClauseOpEq:
			if !strings.EqualFold(actual, expected) {
				decision = model.DecisionDeny
				reasons = append(reasons, fmt.Sprintf("%s.%s mismatch (owner=%s)", clause.Source, clause.Field, clause.Owner))
			}
		default:
			decision = model.DecisionDeny
			reasons = append(reasons, fmt.Sprintf("unsupported op %s", clause.Op))
		}
	}

	return decision, reasons
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
