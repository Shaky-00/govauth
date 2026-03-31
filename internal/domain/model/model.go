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
	ClauseOpEq  = "eq"
	ClauseOpNeq = "neq"
	ClauseOpGt  = "gt"
	ClauseOpGte = "gte"
	ClauseOpLt  = "lt"
	ClauseOpLte = "lte"
)

// Evaluator 模式常量
const (
	EvaluatorModePlain               = "plain"
	EvaluatorModeStrictMPC           = "strict_mpc"
	EvaluatorModeSecureStub          = "secure_stub"
	EvaluatorModeSecureOrchestrating = "secure_orchestrating" // 新的正式模式名
)

// Secure backend 模式常量
const (
	SecureBackendModeLocalPlain = "local_plain"
	SecureBackendModeStrictMPyC = "strict_mpyc"

	SecureBackendModeRealMPC = "real_mpc" // 保持兼容 但不太用了
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

type OwnedField struct {
	Source string `json:"source"`
	Field  string `json:"field"`
}

// 由策略导出的执行计划对象
type EnforcementPlan struct {
	ID            string   `json:"id"`
	PolicyID      string   `json:"policy_id"`
	PolicyVersion int      `json:"policy_version"`
	Clauses       []Clause `json:"clauses"`

	// K_E: policy-relevant evidence keys
	PolicyRelevantEvidenceKeys []string `json:"k_e"`

	// K_S: required state dependencies
	RequiredStateDependencies []string `json:"k_s"`

	// D: ownership-aware partition
	OwnershipPartition map[string][]OwnedField `json:"d"`

	// f_P：编译后的安全求值函数标识
	CompiledFunction string `json:"f_p"`

	// B：绑定模板
	BindingTemplate map[string]any `json:"b"`

	// 以下仅做兼容
	AdmissibleEvidenceKeys []string       `json:"admissible_evidence_keys,omitempty"`
	RequiredSnapshotKeys   []string       `json:"required_snapshot_keys,omitempty"`
	ReleaseBindingRequired bool           `json:"release_binding_required"`
	ExecutionHints         map[string]any `json:"execution_hints"`

	DerivedFromPolicyDigest string    `json:"derived_from_policy_digest"`
	CreatedAt               time.Time `json:"created_at"`
}

// 一次具体授权执行实例
type ExecutionSession struct {
	ID         string         `json:"id"`
	PolicyID   string         `json:"policy_id"`
	PlanID     string         `json:"plan_id"`
	Requester  string         `json:"requester"`
	ResourceID string         `json:"resource_id"`
	Context    map[string]any `json:"context"`
	State      SessionState   `json:"state"`

	EvidenceID   string `json:"evidence_id,omitempty"`
	SnapshotID   string `json:"snapshot_id,omitempty"`
	TaskSpecID   string `json:"task_spec_id,omitempty"`
	EvaluationID string `json:"evaluation_id,omitempty"`
	ArtifactID   string `json:"artifact_id,omitempty"`

	RejectedReason   string     `json:"rejected_reason,omitempty"`
	RejectedByAction string     `json:"rejected_by_action,omitempty"`
	RejectedAt       *time.Time `json:"rejected_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 被接纳的证据对象
type EvidenceRecord struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`

	// Payload：仅 public metadata 不要放私有值
	Payload map[string]any `json:"payload,omitempty"`

	// AdmittedView：plain baseline 才会真正使用。
	AdmittedView map[string]any `json:"admitted_view,omitempty"`

	EvidenceDigest string `json:"evidence_digest"`
	EvidenceRef    string `json:"evidence_ref,omitempty"`
	Admitted       bool   `json:"admitted"`

	CreatedAt time.Time `json:"created_at"`
}

// 绑定到当前执行上下文的生命周期快照
type PinnedSnapshot struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`

	// Payload：仅 public metadata 不要放私有值
	Payload map[string]any `json:"payload"`

	SnapshotDigest string `json:"snapshot_digest"`
	SnapshotRef    string `json:"snapshot_ref,omitempty"`

	PinnedAt time.Time `json:"pinned_at"`
}

// -------------------------------
// Strict MPC 任务与结果回执
// -------------------------------
type StrictMPCTaskClause struct {
	ClauseID string `json:"clause_id"`

	Owner      string `json:"owner"`
	OwnerIndex int    `json:"owner_index"`

	Source string `json:"source"`
	Field  string `json:"field"`
	Op     string `json:"op"`

	// 公开策略值；由各 party 在本地按同样规则编码
	ExpectedValue    string `json:"expected_value"`
	ExpectedEncoding string `json:"expected_encoding"` // eq_hash / int_compare
}

type ResultCallbackSpec struct {
	SubmitURL string `json:"submit_url"`
}

// StrictMPCTaskSpec 是 GovAuth 对外发布的 public evaluation task spec。
// 它可以被 3 个本地 agent 读取，但不包含任何 party 私有明文
type StrictMPCTaskSpec struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	SessionID string `json:"session_id"`
	PolicyID  string `json:"policy_id"`
	PlanID    string `json:"plan_id"`

	EvaluatorMode string `json:"evaluator_mode"`
	BackendMode   string `json:"backend_mode"`

	Clauses            []StrictMPCTaskClause   `json:"clauses"`
	OwnershipPartition map[string][]OwnedField `json:"ownership_partition"`
	BindingInfo        map[string]any          `json:"binding_info"`
	ResultCallback     ResultCallbackSpec      `json:"result_callback"`
	Metadata           map[string]any          `json:"metadata,omitempty"`

	ManifestDigest string    `json:"manifest_digest"`
	CreatedAt      time.Time `json:"created_at"`
}

// SecureExecutionRequest 是 GovAuth 发给 strict backend 的公共任务请求。
// 注意：它只携带 digest / public bindings，不携带私有输入值。
type SecureExecutionRequest struct {
	RequestID string `json:"request_id"`
	SessionID string `json:"session_id"`
	PolicyID  string `json:"policy_id"`
	PlanID    string `json:"plan_id"`

	EvaluatorMode string `json:"evaluator_mode"`
	BackendMode   string `json:"backend_mode"`

	Plan    *EnforcementPlan `json:"plan"`
	Clauses []Clause         `json:"clauses"`

	EvidenceDigest string `json:"evidence_digest"`
	SnapshotDigest string `json:"snapshot_digest"`
	ContextDigest  string `json:"context_digest"`

	BindingInfo map[string]any `json:"binding_info"`

	RequestedAt time.Time `json:"requested_at"`
}

// MPC runtime后提交给GovAuth的最小回执，无明文输入
type StrictMPCResultReceipt struct {
	TaskID    string `json:"task_id"`
	RequestID string `json:"request_id"`
	SessionID string `json:"session_id"`
	PlanID    string `json:"plan_id"`

	Decision    Decision `json:"decision"`
	ClauseCount int      `json:"clause_count"`

	TranscriptDigest string         `json:"transcript_digest"`
	ResultDigest     string         `json:"result_digest"`
	ProofReceipt     string         `json:"proof_receipt,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`

	SubmittedBy string    `json:"submitted_by,omitempty"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// 安全执行过程中的步骤记录
type SecureExecutionStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SecureBackend 返回的结构化执行结果
type SecureExecutionResult struct {
	ExecutionID string `json:"execution_id"`
	TaskID      string `json:"task_id"`
	SessionID   string `json:"session_id"`

	BackendMode string   `json:"backend_mode"`
	Decision    Decision `json:"decision"`
	Reason      string   `json:"reason"`

	TranscriptDigest string                  `json:"transcript_digest,omitempty"`
	Receipt          *StrictMPCResultReceipt `json:"receipt,omitempty"`

	Steps      []SecureExecutionStep `json:"steps,omitempty"`
	Metadata   map[string]any        `json:"metadata,omitempty"`
	ExecutedAt time.Time             `json:"executed_at"`
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
	ID        string `json:"id"`
	SessionID string `json:"session_id"`

	PolicyDigest        string `json:"policy_digest"`
	EvidenceDigest      string `json:"evidence_digest"`
	LifecycleDigest     string `json:"lifecycle_digest"`
	ContextDigest       string `json:"context_digest"`
	TaskManifestDigest  string `json:"task_manifest_digest,omitempty"`
	ResultReceiptDigest string `json:"result_receipt_digest,omitempty"`

	AuthorizationDecision Decision       `json:"authorization_decision"`
	Context               map[string]any `json:"context"`

	Signature      string    `json:"signature"`
	ArtifactDigest string    `json:"artifact_digest"`
	CreatedAt      time.Time `json:"created_at"`
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
