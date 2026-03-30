package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"govauth/internal/domain/model"
	"govauth/internal/pkg/hash"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MPC / 隐私计算后端统一边界
type SecureBackend interface {
	Mode() string
	Execute(req *model.SecureExecutionRequest) (*model.SecureExecutionResult, error)
}

// NewSecureBackendByMode 统一创建 backend。
// 这样 service/main 层不需要知道 backend 的具体类型。
func NewSecureBackendByMode(mode string) (SecureBackend, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", model.SecureBackendModeMockMPC:
		return NewMockMPCBackend(), nil
	case model.SecureBackendModeRealMPC:
		return NewRealMPCBackend(), nil
	default:
		return nil, fmt.Errorf("unknown secure backend mode: %s", mode)
	}
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

		passed, err := compareClauseValues(clause.Op, actual, expected)
		if err != nil {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("mock_mpc invalid clause at owner=%s source=%s field=%s op=%s: %v",
					clause.Owner, clause.Source, clause.Field, clause.Op, err))
			continue
		}

		if !passed {
			decision = model.DecisionDeny
			reasons = append(reasons,
				fmt.Sprintf("mock_mpc mismatch at owner=%s source=%s field=%s op=%s actual=%s expected=%s",
					clause.Owner, clause.Source, clause.Field, clause.Op, actual, expected))
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
			"supported_ops": []string{
				model.ClauseOpEq,
				model.ClauseOpNeq,
				model.ClauseOpGt,
				model.ClauseOpGte,
				model.ClauseOpLt,
				model.ClauseOpLte,
			},
		},
		ExecutedAt: time.Now(),
	}, nil
}

// ------------------------------------------------------------
// RealMPCBackend
// ------------------------------------------------------------

// 新的初级Backend，不再伪装安全计算，而是：
// 1. 由 Go 侧编排任务；
// 2. 写出公共 task 文件和各 party 私有输入文件；
// 3. 拉起多个 MPyC party 进程；
// 4. 等待 MPC 输出最终决策；
// 5. 把结果映射回 GovAuth 的 SecureExecutionResult。

// 这不是工业级分布式 MPC 编排器，
// 但它已经是真实的多进程、多方输入、秘密共享、联合计算。
type RealMPCBackend struct {
	pythonBin      string
	scriptPath     string
	basePort       int
	partyCount     int
	timeout        time.Duration
	keepArtifacts  bool
	bitLength      int
	commandWorkDir string
}

func NewRealMPCBackend() *RealMPCBackend {
	return &RealMPCBackend{
		pythonBin:      getenvDefault("MPC_PYTHON_BIN", "python3"),
		scriptPath:     getenvDefault("MPC_SCRIPT_PATH", "tools/mpc/mpyc_eq_backend.py"),
		basePort:       getenvIntDefault("MPC_BASE_PORT", 11500),
		partyCount:     3,
		timeout:        time.Duration(getenvIntDefault("MPC_TIMEOUT_SEC", 30)) * time.Second,
		keepArtifacts:  getenvBoolDefault("MPC_KEEP_ARTIFACTS", false),
		bitLength:      61,
		commandWorkDir: getenvDefault("MPC_WORK_DIR", ""),
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
	if b.partyCount != 3 {
		return nil, fmt.Errorf("real_mpc backend currently requires exactly 3 parties")
	}

	startAt := time.Now()

	taskDoc, partyDocs, err := b.buildMPYCTask(req)
	if err != nil {
		return nil, err
	}

	workDir, cleanup, err := b.prepareWorkDir()
	if cleanup != nil {
		defer cleanup()
	}

	taskPath := filepath.Join(workDir, "task.json")
	if err := writeJSONFile(taskPath, taskDoc); err != nil {
		return nil, err
	}

	inputPaths := make(map[string]string)
	tracePaths := make(map[string]string)
	stderrByParty := make(map[string]string)

	partyOrder := []string{
		model.ClauseOwnerRequester,
		model.ClauseOwnerProvider,
		model.ClauseOwnerAuthority,
	}

	for _, role := range partyOrder {
		inputPath := filepath.Join(workDir, role+"_input.json")
		tracePath := filepath.Join(workDir, role+"_trace.log")

		if err := writeJSONFile(inputPath, partyDocs[role]); err != nil {
			return nil, err
		}

		inputPaths[role] = inputPath
		tracePaths[role] = tracePath
	}

	resultPath := filepath.Join(workDir, "result.json")

	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	type partyExecResult struct {
		role   string
		stderr string
		err    error
	}

	resultCh := make(chan partyExecResult, len(partyOrder))
	var wg sync.WaitGroup

	for idx, role := range partyOrder {
		wg.Add(1)

		go func(partyIndex int, partyRole string) {
			defer wg.Done()

			stderr, runErr := b.runOneParty(ctx, partyIndex, partyRole, taskPath, inputPaths[partyRole], resultPath, tracePaths[partyRole])
			resultCh <- partyExecResult{
				role:   partyRole,
				stderr: stderr,
				err:    runErr,
			}
		}(idx, role)
	}

	wg.Wait()
	close(resultCh)

	for item := range resultCh {
		stderrByParty[item.role] = item.stderr
		if item.err != nil {
			return nil, fmt.Errorf("real_mpc party %s failed: %w; stderr=%s", item.role, item.err, item.stderr)
		}
	}

	resultDoc := &mpycResultDocument{}
	if err := readJSONFile(resultPath, resultDoc); err != nil {
		return nil, fmt.Errorf("real_mpc result file missing or invalid: %w", err)
	}

	transcript := make([]string, 0, 32)
	transcript = append(transcript,
		fmt.Sprintf("real_mpc request=%s session=%s", req.RequestID, req.SessionID),
		fmt.Sprintf("real_mpc workdir=%s", workDir),
		fmt.Sprintf("real_mpc launched %d MPyC parties", len(partyOrder)),
	)
	transcript = append(transcript, resultDoc.Transcript...)

	// 把各party的本地trace也并进去
	// 这样在 audit bundle 里就能非常直观看到：
	// requester/provider/authority 是分别启动的、分别输入的。
	for _, role := range partyOrder {
		content, _ := os.ReadFile(tracePaths[role])
		if len(content) > 0 {
			transcript = append(transcript,
				fmt.Sprintf("party_trace[%s]=BEGIN", role),
				strings.TrimSpace(string(content)),
				fmt.Sprintf("party_trace[%s]=END", role),
			)
		}
	}

	steps := []model.SecureExecutionStep{
		{
			Name:   "prepare_party_inputs",
			Status: "ok",
			Detail: fmt.Sprintf("prepared task.json and %d party input files", len(partyOrder)),
		},
		{
			Name:   "launch_mpyc_parties",
			Status: "ok",
			Detail: fmt.Sprintf("launched %d local MPyC processes", len(partyOrder)),
		},
		{
			Name:   "secure_evaluation",
			Status: "ok",
			Detail: fmt.Sprintf("finished MPyC secure equality evaluation for %d clauses", len(req.Clauses)),
		},
		{
			Name:   "collect_result",
			Status: "ok",
			Detail: fmt.Sprintf("decision=%s", resultDoc.Decision),
		},
	}

	decision := model.DecisionDeny
	switch strings.ToUpper(strings.TrimSpace(resultDoc.Decision)) {
	case string(model.DecisionAllow):
		decision = model.DecisionAllow
	case string(model.DecisionDeny):
		decision = model.DecisionDeny
	}

	reasons := make([]string, 0)
	for _, c := range resultDoc.ClauseResults {
		if !c.Passed {
			reasons = append(reasons,
				fmt.Sprintf("real_mpc mismatch at owner=%s source=%s field=%s", c.Owner, c.Source, c.Field))
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons,
			fmt.Sprintf("real_mpc verified all %d clauses across %d parties", len(req.Clauses), len(partyOrder)))
	}

	proofStub := hash.AnySHA256Hex(map[string]any{
		"request_id":   req.RequestID,
		"session_id":   req.SessionID,
		"plan_id":      req.PlanID,
		"backend_mode": b.Mode(),
		"decision":     decision,
		"package_id":   req.InputPackage.PackageID,
		"party_count":  len(partyOrder),
		"base_port":    b.basePort,
		"clause_count": len(req.Clauses),
	})

	return &model.SecureExecutionResult{
		ExecutionID: "secure-exec-" + hash.AnySHA256Hex(map[string]any{
			"request_id": req.RequestID,
			"executed":   startAt.UnixNano(),
			"backend":    b.Mode(),
		})[:16],
		SessionID:   req.SessionID,
		BackendMode: b.Mode(),
		Decision:    decision,
		Reason:      strings.Join(reasons, "; "),
		ProofStub:   proofStub,
		Transcript:  transcript,
		Steps:       steps,
		Metadata: map[string]any{
			"package_id":        req.InputPackage.PackageID,
			"party_count":       len(partyOrder),
			"clause_count":      len(req.Clauses),
			"total_field_count": req.InputPackage.TotalFieldCount,
			"mpc_runtime":       "mpyc",
			"bit_length":        b.bitLength,
			"base_port":         b.basePort,
			"work_dir":          workDir,
			"party_stderr":      stderrByParty,
			"supported_ops": []string{
				model.ClauseOpEq,
				model.ClauseOpNeq,
				model.ClauseOpGt,
				model.ClauseOpGte,
				model.ClauseOpLt,
				model.ClauseOpLte,
			},
		},
		ExecutedAt: time.Now(),
	}, nil
}

// runOneParty 启动一个本地 MPyC party 进程。
// 这里故意让每个 party 都是独立进程，避免继续停留在“函数内模拟多方”的层面。
func (b *RealMPCBackend) runOneParty(
	ctx context.Context,
	partyIndex int,
	role string,
	taskPath string,
	inputPath string,
	resultPath string,
	tracePath string,
) (string, error) {
	scriptPath := b.scriptPath
	if !filepath.IsAbs(scriptPath) && b.commandWorkDir != "" {
		scriptPath = filepath.Join(b.commandWorkDir, scriptPath)
	}

	args := []string{
		scriptPath,
		"-M", strconv.Itoa(b.partyCount),
		"-I", strconv.Itoa(partyIndex),
		"-B", strconv.Itoa(b.basePort),
		"--no-log",
	}

	cmd := exec.CommandContext(ctx, b.pythonBin, args...)

	if b.commandWorkDir != "" {
		cmd.Dir = b.commandWorkDir
	}

	// 自定义参数不走 argv，避免和 MPyC 自带参数解析发生冲突。
	cmd.Env = append(os.Environ(),
		"GOVAUTH_MPC_TASK="+taskPath,
		"GOVAUTH_MPC_INPUT="+inputPath,
		"GOVAUTH_MPC_RESULT="+resultPath,
		"GOVAUTH_MPC_TRACE="+tracePath,
		"GOVAUTH_MPC_ROLE="+role,
	)

	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (b *RealMPCBackend) prepareWorkDir() (string, func(), error) {
	baseDir := ""
	if strings.TrimSpace(b.commandWorkDir) != "" {
		baseDir = b.commandWorkDir
	}

	workDir, err := os.MkdirTemp(baseDir, "govauth-mpyc-*")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		if b.keepArtifacts {
			return
		}
		_ = os.RemoveAll(workDir)
	}

	return workDir, cleanup, nil
}

// buildMPYCTask 把 SecureExecutionRequest 转成：
// 1. 公共 task 文档
// 2. 每个 party 的私有输入文档
//
// 这一步是本次接入里最关键的“桥接层”：
// 它把 GovAuth 的 clause 模型，变成了 MPyC 能直接消费的最小 MPC 任务。
func (b *RealMPCBackend) buildMPYCTask(req *model.SecureExecutionRequest) (*mpycTaskDocument, map[string]*mpycPartyInputDocument, error) {
	partyOrder := []string{
		model.ClauseOwnerRequester,
		model.ClauseOwnerProvider,
		model.ClauseOwnerAuthority,
	}
	partyIndexMap := map[string]int{
		model.ClauseOwnerRequester: 0,
		model.ClauseOwnerProvider:  1,
		model.ClauseOwnerAuthority: 2,
	}

	task := &mpycTaskDocument{
		RequestID:   req.RequestID,
		SessionID:   req.SessionID,
		PlanID:      req.PlanID,
		PartyOrder:  partyOrder,
		PartyCount:  len(partyOrder),
		BitLength:   b.bitLength,
		ClauseCount: len(req.Clauses),
		Clauses:     make([]mpycClauseDocument, 0, len(req.Clauses)),
	}

	partyDocs := map[string]*mpycPartyInputDocument{
		model.ClauseOwnerRequester: {
			Role:       model.ClauseOwnerRequester,
			PartyIndex: 0,
			Inputs:     make([]int64, len(req.Clauses)),
		},
		model.ClauseOwnerProvider: {
			Role:       model.ClauseOwnerProvider,
			PartyIndex: 1,
			Inputs:     make([]int64, len(req.Clauses)),
		},
		model.ClauseOwnerAuthority: {
			Role:       model.ClauseOwnerAuthority,
			PartyIndex: 2,
			Inputs:     make([]int64, len(req.Clauses)),
		},
	}

	for i, clause := range req.Clauses {
		op := strings.ToLower(strings.TrimSpace(clause.Op))
		switch op {
		case model.ClauseOpEq, model.ClauseOpNeq, model.ClauseOpGt, model.ClauseOpGte, model.ClauseOpLt, model.ClauseOpLte:
			// 当前支持的最小可用操作集
		default:
			return nil, nil, fmt.Errorf("real_mpc backend unsupported op %s", clause.Op)
		}

		owner := strings.ToLower(strings.TrimSpace(clause.Owner))
		ownerIndex, ok := partyIndexMap[owner]
		if !ok {
			return nil, nil, fmt.Errorf("real_mpc unsupported owner %s", clause.Owner)
		}

		actual, ok := resolveSecureActualValue(req.InputPackage, clause)
		if !ok {
			return nil, nil, fmt.Errorf("real_mpc missing actual value for owner=%s source=%s field=%s", clause.Owner, clause.Source, clause.Field)
		}

		expected := toString(clause.Value)

		expectedEncoded, comparisonMode, err := encodeClauseValueForMPC(op, expected)
		if err != nil {
			return nil, nil, fmt.Errorf("real_mpc expected value encode failed at owner=%s source=%s field=%s op=%s: %w",
				clause.Owner, clause.Source, clause.Field, clause.Op, err)
		}

		actualEncoded, actualMode, err := encodeClauseValueForMPC(op, actual)
		if err != nil {
			return nil, nil, fmt.Errorf("real_mpc actual value encode failed at owner=%s source=%s field=%s op=%s: %w",
				clause.Owner, clause.Source, clause.Field, clause.Op, err)
		}

		if actualMode != comparisonMode {
			return nil, nil, fmt.Errorf("real_mpc comparison mode mismatch at owner=%s source=%s field=%s op=%s",
				clause.Owner, clause.Source, clause.Field, clause.Op)
		}

		task.Clauses = append(task.Clauses, mpycClauseDocument{
			ClauseID:         fmt.Sprintf("clause_%d", i),
			Owner:            owner,
			OwnerIndex:       ownerIndex,
			Source:           clause.Source,
			Field:            clause.Field,
			Op:               op,
			ComparisonMode:   comparisonMode,
			ExpectedValue:    expectedEncoded,
			ExpectedReadable: expected,
		})

		// 只有 owner 对应的 party 文档里，才放真实输入值。
		// 其他 party 保持 0。
		partyDocs[owner].Inputs[i] = actualEncoded
	}

	return task, partyDocs, nil
}

// ------------------------------------------------------------
// MPyC 文档模型
// ------------------------------------------------------------

type mpycTaskDocument struct {
	RequestID   string               `json:"request_id"`
	SessionID   string               `json:"session_id"`
	PlanID      string               `json:"plan_id"`
	PartyOrder  []string             `json:"party_order"`
	PartyCount  int                  `json:"party_count"`
	BitLength   int                  `json:"bit_length"`
	ClauseCount int                  `json:"clause_count"`
	Clauses     []mpycClauseDocument `json:"clauses"`
}

type mpycClauseDocument struct {
	ClauseID         string `json:"clause_id"`
	Owner            string `json:"owner"`
	OwnerIndex       int    `json:"owner_index"`
	Source           string `json:"source"`
	Field            string `json:"field"`
	Op               string `json:"op"`
	ComparisonMode   string `json:"comparison_mode"`
	ExpectedValue    int64  `json:"expected_value"`
	ExpectedReadable string `json:"expected_readable,omitempty"`
}

type mpycPartyInputDocument struct {
	Role       string  `json:"role"`
	PartyIndex int     `json:"party_index"`
	Inputs     []int64 `json:"inputs"`
}

type mpycResultDocument struct {
	RequestID     string                     `json:"request_id"`
	SessionID     string                     `json:"session_id"`
	Decision      string                     `json:"decision"`
	ClauseResults []mpycClauseResultDocument `json:"clause_results"`
	Transcript    []string                   `json:"transcript"`
}

type mpycClauseResultDocument struct {
	ClauseID string `json:"clause_id"`
	Owner    string `json:"owner"`
	Source   string `json:"source"`
	Field    string `json:"field"`
	Op       string `json:"op"`
	Passed   bool   `json:"passed"`
}

// ------------------------------------------------------------
// 共享辅助函数
// ------------------------------------------------------------

const (
	mpcComparisonModeEqHash     = "eq_hash"
	mpcComparisonModeIntCompare = "int_compare"
)

// encodeClauseValueForMPC 根据op选择编码方式
// 1. eq / neq：允许字符串，统一做哈希编码；
// 2. gt / gte / lt / lte：仅允许整数，直接保留整数语义。
func encodeClauseValueForMPC(op string, raw string) (int64, string, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case model.ClauseOpEq, model.ClauseOpNeq:
		return encodeStringForMPCEq(raw), mpcComparisonModeEqHash, nil

	case model.ClauseOpGt, model.ClauseOpGte, model.ClauseOpLt, model.ClauseOpLte:
		n, err := parseIntegerString(raw)
		if err != nil {
			return 0, "", err
		}
		if err := validateMPCIntRange(n); err != nil {
			return 0, "", err
		}
		return n, mpcComparisonModeIntCompare, nil
	}
	return 0, "", fmt.Errorf("unsupported op %s", op)
}

func encodeStringForMPCEq(v string) int64 {
	sum := sha256.Sum256([]byte(v))
	x := binary.BigEndian.Uint64(sum[:8])

	x &= (1 << 61) - 1

	if x == 0 {
		x = 1
	}
	return int64(x)
}

func validateMPCIntRange(v int64) error {
	const maxSigned61 = int64(1<<60) - 1
	const minSigned61 = -1 << 60

	if v < minSigned61 || v > maxSigned61 {
		return fmt.Errorf("integer %d out of signed-61-bit range", v)
	}
	return nil
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func getenvDefault(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getenvIntDefault(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getenvBoolDefault(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

// resolveSecureActualValue 是 mock 和 real_mpc 共用的定位函数。
// 它从 SecureInputPackage 里找到 owner/source/field 对应的原始值。
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

	for source, fieldMap := range inputs {
		if out[source] == nil {
			out[source] = map[string][]string{}
		}

		for field, value := range fieldMap {
			raw := toString(value)
			out[source][field] = []string{
				fmt.Sprintf("pseudo-share|%s|%s|%s|0|%d|%s", party, source, field, partyCount, raw),
			}
		}
	}

	return out
}

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
