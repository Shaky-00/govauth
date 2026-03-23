package workflow

import (
	"encoding/hex"
	"fmt"
	"govauth/internal/domain/model"
	"govauth/internal/pkg/hash"
	"sort"
	"strings"
	"time"
)

// MPC / 隐私计算后端统一边界
type SecureBackend interface {
	Mode() string
	Execute(req *model.SecureExecutionRequest) (*model.SecureExecutionResult, error)
}

// ------------------------------------------------------------
// MockMPCBackend
// ------------------------------------------------------------

// MockMPCBackend 是最早的模拟后端。
// 它仍然直接读取原始 Inputs，代表“占位式安全执行”。
// 这个 backend 保留不删，便于你继续做对照测试。
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

// ------------------------------------------------------------
// RealMPCBackend
// ------------------------------------------------------------

// RealMPCBackend 是“最小可运行的伪 MPC backend”。
// 它不是密码学 MPC 实现，但它具备：
// 1. 输入装载阶段
// 2. secret sharing 模拟阶段
// 3. secure evaluation 阶段
// 4. reconstruct 阶段
// 5. proof / transcript 生成阶段
//
// 未来如果接 SPDZ / ABY / TEE / 远端 MPC runtime，
// 主要替换的就是这个 backend 的内部执行细节。
type RealMPCBackend struct {
	defaultThreshold int
}

func NewRealMPCBackend() *RealMPCBackend {
	return &RealMPCBackend{
		defaultThreshold: 2,
	}
}

func (b *RealMPCBackend) Mode() string {
	return model.SecureBackendModeRealMPC
}

func (b *RealMPCBackend) Execute(req *model.SecureExecutionRequest) (*model.SecureExecutionResult, error) {
	if req == nil {
		return nil, fmt.Errorf("secure execution request is nil")
	}
	if req.InputPackage == nil {
		return nil, fmt.Errorf("secure execution request missing input package")
	}
	if len(req.Clauses) == 0 {
		return nil, fmt.Errorf("secure execution request missing clauses")
	}

	now := time.Now()
	pkg := b.ensureShareRepresentation(req.InputPackage)

	transcript := make([]string, 0, 16)
	steps := make([]model.SecureExecutionStep, 0, 5)

	// --------------------------------------------------------
	// Step 1: load party inputs
	// 这是 MPC 抽象中的输入接收/载入阶段
	// --------------------------------------------------------
	transcript = append(transcript,
		fmt.Sprintf("real_mpc receive request=%s session=%s", req.RequestID, req.SessionID),
		fmt.Sprintf("real_mpc load package=%s parties=%d clauses=%d", pkg.PackageID, len(pkg.Parties), len(req.Clauses)),
	)
	steps = append(steps, model.SecureExecutionStep{
		Name:   "receive_inputs",
		Status: "ok",
		Detail: fmt.Sprintf("loaded secure package %s with %d parties", pkg.PackageID, len(pkg.Parties)),
	})

	// --------------------------------------------------------
	// Step 2: simulate secret sharing
	// 这里是 mock/模拟逻辑，不是真实秘密分享协议
	// 但结构上明确区分“原始输入”和“共享表示”
	// --------------------------------------------------------
	transcript = append(transcript,
		fmt.Sprintf("real_mpc simulate secret sharing party_count=%d threshold=%d", pkg.PartyCount, pkg.Threshold),
	)
	steps = append(steps, model.SecureExecutionStep{
		Name:   "secret_sharing",
		Status: "ok",
		Detail: fmt.Sprintf("prepared pseudo shares for %d parties with threshold=%d", pkg.PartyCount, pkg.Threshold),
	})

	// --------------------------------------------------------
	// Step 3: secure evaluation
	// 不直接使用原始 value，而是：
	// 1. 从 share 表示取出 shares
	// 2. 做伪 reconstruction
	// 3. 在“secure context”里比较
	// --------------------------------------------------------
	decision, reasons, evalTrace := b.secureEvaluateClauses(req.Clauses, pkg)
	transcript = append(transcript, "real_mpc start secure clause evaluation")
	transcript = append(transcript, evalTrace...)
	steps = append(steps, model.SecureExecutionStep{
		Name:   "secure_evaluation",
		Status: "ok",
		Detail: fmt.Sprintf("evaluated %d clauses in pseudo secure context", len(req.Clauses)),
	})

	// --------------------------------------------------------
	// Step 4: reconstruct result
	// 这里对应 MPC 输出重构阶段
	// --------------------------------------------------------
	finalReason := strings.Join(reasons, "; ")
	if len(reasons) == 0 {
		finalReason = fmt.Sprintf("real_mpc verified all %d clauses across %d parties", len(req.Clauses), pkg.PartyCount)
	}
	transcript = append(transcript, fmt.Sprintf("real_mpc reconstruct final decision=%s", decision))
	steps = append(steps, model.SecureExecutionStep{
		Name:   "reconstruct",
		Status: "ok",
		Detail: fmt.Sprintf("reconstructed final decision=%s", decision),
	})

	// --------------------------------------------------------
	// Step 5: generate proof stub + transcript
	// proof_stub 依旧是模拟逻辑，但预留真实证明/执行证明的位置
	// --------------------------------------------------------
	proofStub := hash.AnySHA256Hex(map[string]any{
		"request_id":   req.RequestID,
		"session_id":   req.SessionID,
		"plan_id":      req.PlanID,
		"backend_mode": b.Mode(),
		"decision":     decision,
		"package_id":   pkg.PackageID,
		"party_count":  pkg.PartyCount,
		"threshold":    pkg.Threshold,
		"clauses":      req.Clauses,
	})
	transcript = append(transcript, fmt.Sprintf("real_mpc generate proof_stub=%s", proofStub))
	steps = append(steps, model.SecureExecutionStep{
		Name:   "generate_proof",
		Status: "ok",
		Detail: "generated pseudo MPC proof stub",
	})

	return &model.SecureExecutionResult{
		ExecutionID: "secure-exec-" + hash.AnySHA256Hex(map[string]any{
			"request_id": req.RequestID,
			"executed":   now.UnixNano(),
			"backend":    b.Mode(),
		})[:16],
		SessionID:   req.SessionID,
		BackendMode: b.Mode(),
		Decision:    decision,
		Reason:      finalReason,
		ProofStub:   proofStub,
		Transcript:  transcript,
		Steps:       steps,
		Metadata: map[string]any{
			"package_id":        pkg.PackageID,
			"party_count":       pkg.PartyCount,
			"threshold":         pkg.Threshold,
			"clause_count":      len(req.Clauses),
			"total_field_count": pkg.TotalFieldCount,
			"share_ready":       true,
		},
		ExecutedAt: now,
	}, nil
}

// secureEvaluateClauses 在“伪 secure context”中对 clauses 求值。
// 这里仍然是本地逻辑，但求值使用的是 shares -> reconstruct -> compare 的流程。
// 这就是 MPC 抽象；不是密码学安全。
func (b *RealMPCBackend) secureEvaluateClauses(
	clauses []model.Clause,
	pkg *model.SecureInputPackage,
) (model.Decision, []string, []string) {
	decision := model.DecisionAllow
	reasons := make([]string, 0)
	trace := make([]string, 0, len(clauses))

	for _, clause := range clauses {
		expected := toString(clause.Value)

		shares, ok := resolveSharesForClause(pkg, clause)
		if !ok {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("real_mpc missing shares at owner=%s source=%s field=%s", clause.Owner, clause.Source, clause.Field))
			trace = append(trace,
				fmt.Sprintf("real_mpc clause owner=%s source=%s field=%s -> missing shares", clause.Owner, clause.Source, clause.Field))
			continue
		}

		// 这里的 reconstruct 是 mock/模拟逻辑：
		// 它把本地 shares 拼回原始值，表示“安全计算输出重构前的内部恢复”。
		actual, err := reconstructValueFromShares(shares)
		if err != nil {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("real_mpc failed to reconstruct owner=%s source=%s field=%s", clause.Owner, clause.Source, clause.Field))
			trace = append(trace,
				fmt.Sprintf("real_mpc reconstruct failed owner=%s source=%s field=%s err=%v", clause.Owner, clause.Source, clause.Field, err))
			continue
		}

		switch clause.Op {
		case model.ClauseOpEq:
			if !strings.EqualFold(actual, expected) {
				decision = model.DecisionDeny
				reasons = append(reasons,
					fmt.Sprintf("real_mpc mismatch at owner=%s source=%s field=%s", clause.Owner, clause.Source, clause.Field))
				trace = append(trace,
					fmt.Sprintf("real_mpc secure compare failed owner=%s source=%s field=%s actual=%s expected=%s",
						clause.Owner, clause.Source, clause.Field, actual, expected))
			} else {
				trace = append(trace,
					fmt.Sprintf("real_mpc secure compare passed owner=%s source=%s field=%s",
						clause.Owner, clause.Source, clause.Field))
			}
		default:
			decision = model.DecisionDeny
			reasons = append(reasons, fmt.Sprintf("real_mpc unsupported op %s", clause.Op))
			trace = append(trace, fmt.Sprintf("real_mpc unsupported op=%s", clause.Op))
		}
	}

	return decision, reasons, trace
}

// ensureShareRepresentation 确保输入包中有 shares。
// 如果上游没有生成，就在 backend 内兜底生成。
func (b *RealMPCBackend) ensureShareRepresentation(pkg *model.SecureInputPackage) *model.SecureInputPackage {
	if pkg == nil {
		return nil
	}

	if pkg.PartyCount <= 0 {
		pkg.PartyCount = len(pkg.Parties)
	}
	if pkg.Threshold <= 0 {
		if b.defaultThreshold > 0 && b.defaultThreshold <= pkg.PartyCount {
			pkg.Threshold = b.defaultThreshold
		} else {
			pkg.Threshold = pkg.PartyCount
		}
	}

	for i := range pkg.Parties {
		party := &pkg.Parties[i]

		if party.EncodedInputs == nil {
			party.EncodedInputs = encodeSecureInputs(party.Party, party.Inputs, pkg.PartyCount)
		}
		if party.ShareMap == nil {
			party.ShareMap = flattenEncodedInputMap(party.EncodedInputs)
		}
		if party.Meta == nil {
			party.Meta = map[string]any{}
		}
		party.Meta["share_ready"] = true
		party.Meta["share_count"] = len(party.ShareMap)
		party.Meta["threshold"] = pkg.Threshold
	}

	return pkg
}

// ------------------------------------------------------------
// Share 编码 / 解码辅助逻辑
// ------------------------------------------------------------

// encodeSecureInputs 将原始输入编码为 shares。
// 这是 mock/模拟逻辑，不是真实 MPC secret sharing。
// 这里的思路是：
// 1. 先把值转成 hex 字符串
// 2. 再拆成固定数量的 share 片段
// 3. 后续 reconstruct 时再拼回
func encodeSecureInputs(
	party string,
	inputs map[string]map[string]any,
	partyCount int,
) map[string]map[string][]string {
	out := make(map[string]map[string][]string)

	sourceKeys := make([]string, 0, len(inputs))
	for source := range inputs {
		sourceKeys = append(sourceKeys, source)
	}
	sort.Strings(sourceKeys)

	for _, source := range sourceKeys {
		if out[source] == nil {
			out[source] = map[string][]string{}
		}

		fieldKeys := make([]string, 0, len(inputs[source]))
		for field := range inputs[source] {
			fieldKeys = append(fieldKeys, field)
		}
		sort.Strings(fieldKeys)

		for _, field := range fieldKeys {
			raw := toString(inputs[source][field])
			out[source][field] = makePseudoShares(party, source, field, raw, partyCount)
		}
	}

	return out
}

// makePseudoShares 生成伪 shares。
// 注意：这里只是“结构上像秘密分享”，不是密码学安全。
// 每个 share 形如：
// share|party|source|field|idx|total|chunk
func makePseudoShares(
	party string,
	source string,
	field string,
	value string,
	shareCount int,
) []string {
	if shareCount <= 0 {
		shareCount = 1
	}

	hexValue := hex.EncodeToString([]byte(value))
	chunks := splitStringEvenly(hexValue, shareCount)

	shares := make([]string, 0, shareCount)
	for i, chunk := range chunks {
		shares = append(shares, fmt.Sprintf(
			"share|%s|%s|%s|%d|%d|%s",
			party, source, field, i, shareCount, chunk,
		))
	}
	return shares
}

// splitStringEvenly 将字符串尽量均匀地拆成 n 段。
func splitStringEvenly(s string, n int) []string {
	if n <= 1 {
		return []string{s}
	}
	if s == "" {
		out := make([]string, n)
		for i := 0; i < n; i++ {
			out[i] = ""
		}
		return out
	}

	out := make([]string, 0, n)
	base := len(s) / n
	rem := len(s) % n

	start := 0
	for i := 0; i < n; i++ {
		size := base
		if i < rem {
			size++
		}
		end := start + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[start:end])
		start = end
	}

	return out
}

// reconstructValueFromShares 将 shares 拼回原始值。
// 这一步是“伪 reconstruct”，模拟 MPC 最后的恢复阶段。
func reconstructValueFromShares(shares []string) (string, error) {
	if len(shares) == 0 {
		return "", fmt.Errorf("empty shares")
	}

	type sharePiece struct {
		Index int
		Total int
		Chunk string
	}

	pieces := make([]sharePiece, 0, len(shares))
	for _, share := range shares {
		part := strings.SplitN(share, "|", 7)
		if len(part) != 7 {
			return "", fmt.Errorf("invalid share format")
		}

		var idx int
		var total int
		_, err := fmt.Sscanf(part[4], "%d", &idx)
		if err != nil {
			return "", fmt.Errorf("invalid share index")
		}
		_, err = fmt.Sscanf(part[5], "%d", &total)
		if err != nil {
			return "", fmt.Errorf("invalid share total")
		}

		pieces = append(pieces, sharePiece{
			Index: idx,
			Total: total,
			Chunk: part[6],
		})
	}

	sort.Slice(pieces, func(i, j int) bool {
		return pieces[i].Index < pieces[j].Index
	})

	var builder strings.Builder
	for _, p := range pieces {
		builder.WriteString(p.Chunk)
	}

	rawHex := builder.String()
	if rawHex == "" {
		return "", nil
	}

	data, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// flattenEncodedInputMap 将结构化 shares 扁平化。
func flattenEncodedInputMap(encoded map[string]map[string][]string) map[string][]string {
	out := make(map[string][]string)
	for source, fieldMap := range encoded {
		for field, shares := range fieldMap {
			out[buildShareKey(source, field)] = shares
		}
	}
	return out
}

func buildShareKey(source string, field string) string {
	return strings.TrimSpace(source) + "." + strings.TrimSpace(field)
}

// resolveSharesForClause 按 clause 定位对应 shares。
func resolveSharesForClause(pkg *model.SecureInputPackage, clause model.Clause) ([]string, bool) {
	if pkg == nil {
		return nil, false
	}

	for _, party := range pkg.Parties {
		if strings.TrimSpace(party.Party) != strings.TrimSpace(clause.Owner) {
			continue
		}

		if party.EncodedInputs != nil {
			sourceView := party.EncodedInputs[clause.Source]
			if sourceView != nil {
				if shares, ok := sourceView[clause.Field]; ok && len(shares) > 0 {
					return shares, true
				}
			}
		}

		if party.ShareMap != nil {
			key := buildShareKey(clause.Source, clause.Field)
			if shares, ok := party.ShareMap[key]; ok && len(shares) > 0 {
				return shares, true
			}
		}
	}

	return nil, false
}

// resolveSecureActualValue 是 Mock backend 用的。
// 它直接读取原始 Inputs，因此属于 mock 占位逻辑。
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
