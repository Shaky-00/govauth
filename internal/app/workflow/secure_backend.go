package workflow

import (
	"fmt"
	"govauth/internal/domain/model"
	"govauth/internal/pkg/hash"
	"strings"
	"time"
)

// MPC / 隐私计算后端的统一边界
type SecureBackend interface {
	Mode() string
	Execute(req *model.SecureExecutionRequest) (*model.SecureExecutionResult, error)
}

// 当前阶段模拟安全计算后端：MockMPCBackend
// 不执行真实 MPC 协议，显式模拟：1) 接收分方输入；2) 发起一次安全计算任务；3) 返回结构化执行结果
type MockMPCBackend struct{}

func NewMockMPCBackend() *MockMPCBackend {
	return &MockMPCBackend{}
}

func (b *MockMPCBackend) Mode() string {
	return model.SecureBackendModeMockMPC
}

func (b *MockMPCBackend) Execute(req *model.SecureExecutionRequest) (*model.SecureExecutionResult, error) {
	if req == nil {
		return nil, fmt.Errorf("secure execution request is nil")
	}
	if req.InputPackage == nil {
		return nil, fmt.Errorf("secure execution request missing input package")
	}
	if len(req.Clauses) == 0 {
		return nil, fmt.Errorf("secure execution request missing clauses")
	}

	transcript := make([]string, 0)
	steps := make([]model.SecureExecutionStep, 0)

	transcript = append(transcript,
		fmt.Sprintf("mock_mpc received request=%s session=%s", req.RequestID, req.SessionID),
		fmt.Sprintf("mock_mpc loaded %d parties and %d clauses", len(req.InputPackage.Parties), len(req.Clauses)),
	)

	steps = append(steps, model.SecureExecutionStep{
		Name:   "receive_party_inputs",
		Status: "ok",
		Detail: fmt.Sprintf("received %d party inputs", len(req.InputPackage.Parties)),
	})

	steps = append(steps, model.SecureExecutionStep{
		Name:   "assemble_secure_task",
		Status: "ok",
		Detail: fmt.Sprintf("assembled mock secure task for plan %s", req.PlanID),
	})

	decision := model.DecisionAllow
	reasons := make([]string, 0)

	for _, clause := range req.Clauses {
		expected := toString(clause.Value)
		actual, ok := resolveSecureActualValue(req.InputPackage, clause)
		if !ok {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("mock_mpc missing input at owner=%s source=%s field=%s", clause.Owner, clause.Source, clause.Field))
			continue
		}

		switch clause.Op {
		case model.ClauseOpEq:
			if !strings.EqualFold(actual, expected) {
				decision = model.DecisionDeny
				reasons = append(reasons,
					fmt.Sprintf("mock_mpc mismatch at owner=%s source=%s field=%s", clause.Owner, clause.Source, clause.Field))
			}
		default:
			decision = model.DecisionDeny
			reasons = append(reasons, fmt.Sprintf("mock_mpc unsupported op %s", clause.Op))
		}
	}

	steps = append(steps, model.SecureExecutionStep{
		Name:   "execute_secure_computation",
		Status: "ok",
		Detail: fmt.Sprintf("computed decision=%s", decision),
	})

	if len(reasons) == 0 {
		reasons = append(reasons,
			fmt.Sprintf("mock_mpc verified all %d clauses across %d parties", len(req.Clauses), len(req.InputPackage.Parties)))
	}

	proofStub := hash.AnySHA256Hex(map[string]any{
		"request_id":   req.RequestID,
		"session_id":   req.SessionID,
		"plan_id":      req.PlanID,
		"backend_mode": b.Mode(),
		"decision":     decision,
		"clauses":      req.Clauses,
		"package_id":   req.InputPackage.PackageID,
	})

	transcript = append(transcript,
		fmt.Sprintf("mock_mpc produced decision=%s", decision),
		fmt.Sprintf("mock_mpc generated proof_stub=%s", proofStub),
	)

	steps = append(steps, model.SecureExecutionStep{
		Name:   "generate_proof_stub",
		Status: "ok",
		Detail: "generated deterministic mock proof stub",
	})

	return &model.SecureExecutionResult{
		ExecutionID: "secure-exec-" + hash.AnySHA256Hex(map[string]any{
			"request_id": req.RequestID,
			"executed":   time.Now().UnixNano(),
		})[:16],
		SessionID:   req.SessionID,
		BackendMode: b.Mode(),
		Decision:    decision,
		Reason:      strings.Join(reasons, "; "),
		ProofStub:   proofStub,
		Transcript:  transcript,
		Steps:       steps,
		Metadata: map[string]any{
			"party_count":       len(req.InputPackage.Parties),
			"clause_count":      len(req.Clauses),
			"total_field_count": req.InputPackage.TotalFieldCount,
			"package_id":        req.InputPackage.PackageID,
		},
		ExecutedAt: time.Now(),
	}, nil
}

func resolveSecureActualValue(pkg *model.SecureInputPackage, clause model.Clause) (string, bool) {
	if pkg == nil {
		return "", false
	}

	for _, party := range pkg.Parties {
		if strings.TrimSpace(party.Party) != strings.TrimSpace(clause.Owner) {
			continue
		}

		sourceView := party.Inputs[clause.Source]
		if sourceView == nil {
			return "", false
		}

		value, ok := sourceView[clause.Field]
		if !ok {
			return "", false
		}

		return toString(value), true
	}

	return "", false
}
