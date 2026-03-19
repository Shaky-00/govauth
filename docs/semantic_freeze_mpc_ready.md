# GovAuth MPC-Ready Semantic Freeze (v1)

## 1. 目标
当前阶段，GovAuth 不实现真实 MPC 协议，而是先完成“可承载安全求值”的执行架构改造。

本次冻结的目标是：
1. 统一策略的内部执行语义；
2. 明确各类输入的 source 与 owner；
3. 将执行判断从 workflow/service 中剥离为可替换的 evaluator；
4. 为未来 Secure Evaluator / MPC Evaluator 预留边界。

---

## 2. 内部规范表示（Canonical Representation）

### 2.1 Policy 的内部执行表示
GovAuth 内部统一以 `Clauses []Clause` 作为唯一执行语义。

旧字段：
- required_role
- required_department
- required_purpose
- required_resource_status

仅作为兼容输入存在，不再作为内部执行主语义。

### 2.2 EnforcementPlan 的执行语义
EnforcementPlan 中应直接保存规范化后的 clauses。
后续 evaluator 只读取 plan 中的标准 clauses，不再从动态 hints 中解析 clauses。

---

## 3. Clause 语义冻结

每个 Clause 表示一条最小判断约束：

- `source`: 输入来源
- `field`: 字段名
- `op`: 比较操作
- `value`: 期望值
- `owner`: 输入归属方

### 3.1 支持的 source
- `evidence`
- `snapshot`
- `context`

### 3.2 支持的 owner
- `requester`
- `provider`
- `authority`

### 3.3 默认 owner 映射规则
若 clause 未显式填写 owner，则按 source 赋默认值：

- evidence -> requester
- context -> requester
- snapshot -> provider

authority 不设默认值，必须显式指定。

---

## 4. 字段归属冻结

当前最小 happy path 中，各字段的推荐归属如下：

| 字段名 | source | owner | 说明 |
|---|---|---|---|
| role | evidence | requester | 主体角色属性 |
| department | evidence | requester | 主体部门属性 |
| purpose | context | requester | 请求用途，属于请求上下文 |
| resource_status | snapshot | provider | 资源状态，由资源侧/提供方快照给出 |
| approval_state | snapshot | authority | 未来治理状态，占位字段 |

注意：
- `purpose` 从本版本起语义上归入 `context`，不再作为 evidence 主语义字段。
- evidence 中即便仍带有 purpose，也不作为 evaluator 的标准读取来源。

---

## 5. 执行边界冻结

### 5.1 Service 层职责
workflow.Service 只负责：
1. 对象装配；
2. 状态机校验；
3. 调用 evaluator；
4. 保存 evaluation result；
5. 推进 session 状态。

### 5.2 Evaluator 层职责
Evaluator 只负责：
1. 解释 clauses；
2. 读取输入视图；
3. 进行 allow/deny 判断；
4. 返回决策与原因。

---

## 6. Evaluator 分层冻结

### 6.1 PlainEvaluator
PlainEvaluator 直接在本地读取：
- evidence view
- snapshot
- context

并逐条执行 clause 比较。

### 6.2 SecureStubEvaluator
SecureStubEvaluator 不实现真实 MPC。
它只做以下事情：
1. 按 owner 将输入分为 requester/provider/authority 三类；
2. 显式构造多方输入视图；
3. 在本地模拟 secure evaluation；
4. 返回决策结果。

它的作用是为未来 MPC evaluator 提供边界，而不是提供真实隐私保护。

---

## 7. 本轮不做的事情

本轮明确不做：
- Shamir secret sharing
- garbled circuits
- BGW/SPDZ 等 MPC 协议
- 多进程/多节点部署
- ZKP/commitment 的深度接入

---

## 8. 测试目标冻结

本轮改造完成后，应满足：
1. 原有 happy path 继续可运行；
2. deny path 继续可运行；
3. invalid transition 继续可运行；
4. 可通过切换 evaluator 模式运行 PlainEvaluator；
5. 可通过切换 evaluator 模式运行 SecureStubEvaluator；
6. purpose 的标准读取来源为 context。