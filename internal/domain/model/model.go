package model

import "time"

// 静态治理阶段的策略状态
type PolicyStatus string

const (
	PolicyStatusDraft      PolicyStatus = "DRAFT"
	PolicyStatusAdmissible PolicyStatus = "ADMISSIBLE"
	PolicyStatusPublished  PolicyStatus = "PUBLISHED"
	PolicyStatusRejected   PolicyStatus = "REJECTED"
)

// 动态阶段的会话推进状态
type SessionState string

const (
	SessionStateSessionBound  SessionState = "SESSION_BOUND"
	SessionStateEvidenceBound SessionState = "EVIDENCE_BOUND"
	SessionStateDecided       SessionState = "DECIDED"
	SessionStateEnforced      SessionState = "ENFORCED"
	SessionStateRejected      SessionState = "REJECTED"
)

// 表示评估决策结果
type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionDeny  Decision = "DENY"
)

// Clause 的 source 常量
const (
	ClauseSourceEvidence = "evidence"
	ClauseSourceSnapshot = "snapshot"
	ClauseSourceContext  = "context"
)

// Clause 的 owner 常量
const (
	ClauseOwnerRequester = "requester"
	ClauseOwnerProvider  = "provider"
	ClauseOwnerAuthority = "authority"
)

// Clause 的 op 常量
const (
	ClauseOpEq = "eq"
)

// Evaluator 模式常量
const (
	EvaluatorModePlain               = "plain"
	EvaluatorModeSecureStub          = "secure_stub"
	EvaluatorModeSecureOrchestrating = "secure_orchestrating" // 新的正式模式名
)

// Secure backend 模式常量
const (
	SecureBackendModeLocalPlain = "local_plain"
	SecureBackendModeMockMPC    = "mock_mpc"
	SecureBackendModeRealMPC    = "real_mpc"
)

type Clause struct {
	Source string `json:"source"`          // evidence / snapshot / context
	Field  string `json:"field"`           // 字段名
	Op     string `json:"op"`              // 当前版本仅支持 eq
	Value  any    `json:"value,omitempty"` // 期望值
	Owner  string `json:"owner,omitempty"` // requester / provider / authority
}

// 描述一个最小可执行策略所需的核心约束
type PolicyContent struct {
	Clauses []Clause `json:"clauses"`

	Description string `json:"description"`
}

// 策略对象
type Policy struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Version   int           `json:"version"`
	Status    PolicyStatus  `json:"status"`
	Content   PolicyContent `json:"content"`
	Digest    string        `json:"digest"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// 由策略导出的执行计划对象
type EnforcementPlan struct {
	ID                      string         `json:"id"`
	PolicyID                string         `json:"policy_id"`
	PolicyVersion           int            `json:"policy_version"`
	Clauses                 []Clause       `json:"clauses"`
	AdmissibleEvidenceKeys  []string       `json:"admissible_evidence_keys"`
	RequiredSnapshotKeys    []string       `json:"required_snapshot_keys"`
	ReleaseBindingRequired  bool           `json:"release_binding_required"`
	ExecutionHints          map[string]any `json:"execution_hints"`
	DerivedFromPolicyDigest string         `json:"derived_from_policy_digest"`
	CreatedAt               time.Time      `json:"created_at"`
}

// 一次具体授权执行实例
type ExecutionSession struct {
	ID               string         `json:"id"`
	PolicyID         string         `json:"policy_id"`
	PlanID           string         `json:"plan_id"`
	Requester        string         `json:"requester"`
	ResourceID       string         `json:"resource_id"`
	Context          map[string]any `json:"context"`
	State            SessionState   `json:"state"`
	EvidenceID       string         `json:"evidence_id,omitempty"`
	SnapshotID       string         `json:"snapshot_id,omitempty"`
	EvaluationID     string         `json:"evaluation_id,omitempty"`
	ArtifactID       string         `json:"artifact_id,omitempty"`
	RejectedReason   string         `json:"rejected_reason,omitempty"`
	RejectedByAction string         `json:"rejected_by_action,omitempty"`
	RejectedAt       *time.Time     `json:"rejected_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// 被接纳的证据对象
type EvidenceRecord struct {
	ID             string         `json:"id"`
	SessionID      string         `json:"session_id"`
	Payload        map[string]any `json:"payload"`
	AdmittedView   map[string]any `json:"admitted_view"`
	EvidenceDigest string         `json:"evidence_digest"`
	Admitted       bool           `json:"admitted"`
	CreatedAt      time.Time      `json:"created_at"`
}

// 绑定到当前执行上下文的生命周期快照
type PinnedSnapshot struct {
	ID             string         `json:"id"`
	SessionID      string         `json:"session_id"`
	Payload        map[string]any `json:"payload"`
	SnapshotDigest string         `json:"snapshot_digest"`
	PinnedAt       time.Time      `json:"pinned_at"`
}

// --------- 新增：MPC-orioented 核心模型
// Input 的结构：source -> field -> value
type SecurePartyInput struct {
	Party         string                         `json:"party"`
	Inputs        map[string]map[string]any      `json:"inputs"`
	EncodedInputs map[string]map[string][]string `json:"encoded_inputs,omitempty"`
	ShareMap      map[string][]string            `json:"share_map,omitempty"`
	Meta          map[string]any                 `json:"meta,omitempty"`
}

// 一次安全计算任务所需的完整多方输入包
type SecureInputPackage struct {
	PackageID       string             `json:"package_id"`
	SessionID       string             `json:"session_id"`
	PolicyID        string             `json:"policy_id"`
	PlanID          string             `json:"plan_id"`
	Parties         []SecurePartyInput `json:"parties"`
	PartyCount      int                `json:"party_count,omitempty"`
	Threshold       int                `json:"threshold,omitempty"`
	ClauseCount     int                `json:"clause_count"`
	TotalFieldCount int                `json:"total_field_count"`
	BuiltAt         time.Time          `json:"built_at"`
}

// 发给 SecureBackend 的正式执行请求
type SecureExecutionRequest struct {
	RequestID      string              `json:"request_id"`
	SessionID      string              `json:"session_id"`
	PolicyID       string              `json:"policy_id"`
	PlanID         string              `json:"plan_id"`
	EvaluatorMode  string              `json:"evaluator_mode"`
	BackendMode    string              `json:"backend_mode"`
	Clauses        []Clause            `json:"clauses"`
	InputPackage   *SecureInputPackage `json:"input_package"`
	ExecutionHints map[string]any      `json:"execution_hints,omitempty"`
	RequestedAt    time.Time           `json:"requested_at"`
}

// 安全执行过程中的步骤记录
type SecureExecutionStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SecureBackend 返回的结构化执行结果
type SecureExecutionResult struct {
	ExecutionID string                `json:"execution_id"`
	SessionID   string                `json:"session_id"`
	BackendMode string                `json:"backend_mode"`
	Decision    Decision              `json:"decision"`
	Reason      string                `json:"reason"`
	ProofStub   string                `json:"proof_stub,omitempty"`
	Transcript  []string              `json:"transcript,omitempty"`
	Steps       []SecureExecutionStep `json:"steps,omitempty"`
	Metadata    map[string]any        `json:"metadata,omitempty"`
	ExecutedAt  time.Time             `json:"executed_at"`
}

// 执行评估结果
type EvaluationResult struct {
	ID              string                 `json:"id"`
	SessionID       string                 `json:"session_id"`
	Decision        Decision               `json:"decision"`
	Reason          string                 `json:"reason"`
	EvaluatorMode   string                 `json:"evaluator_mode"`
	BackendMode     string                 `json:"backend_mode,omitempty"`
	SecureExecution *SecureExecutionResult `json:"secure_execution,omitempty"`
	EvaluatedAt     time.Time              `json:"evaluated_at"`
}

// 最终授权工件
type AuthorizationArtifact struct {
	ID                    string         `json:"id"`
	SessionID             string         `json:"session_id"`
	PolicyDigest          string         `json:"policy_digest"`
	EvidenceDigest        string         `json:"evidence_digest"`
	LifecycleDigest       string         `json:"lifecycle_digest"`
	AuthorizationDecision Decision       `json:"authorization_decision"`
	Context               map[string]any `json:"context"`
	Signature             string         `json:"signature"`
	ArtifactDigest        string         `json:"artifact_digest"`
	CreatedAt             time.Time      `json:"created_at"`
}

// 状态迁移或关键执行动作
type TransitionEvent struct {
	ID        string         `json:"id"`
	PolicyID  string         `json:"policy_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Action    string         `json:"action"`
	FromState string         `json:"from_state"`
	ToState   string         `json:"to_state"`
	Note      string         `json:"note"`
	Meta      map[string]any `json:"meta,omitempty"`
	At        time.Time      `json:"at"`
}
