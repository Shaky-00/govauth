#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
这个脚本用于自动执行 govauth 的 deny path，并测量每一步接口的耗时。
设计目标：
1. 不依赖第三方 Python 包，仅使用标准库。
2. 保持与 happy_path_runner.py 相同的整体调用顺序，便于横向对比。
3. 通过提交与策略不匹配的证据，使最终评估结果进入 DENY。
4. 将完整结果保存为 JSON，便于后续实验统计、截图与写作。
5. 支持校验 plain / secure_stub / secure_orchestrating 三种 evaluator 模式。
6. 在 secure 模式下，额外校验 mock MPC 返回的结构化 deny 结果。
"""

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from pathlib import Path


def request_json(method: str, url: str, payload=None, timeout=10):
    """发送 HTTP 请求，并返回 (解析后的 JSON, 状态码, 耗时毫秒)。"""
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url=url, data=data, headers=headers, method=method)

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            elapsed_ms = (time.perf_counter() - start) * 1000
            return json.loads(body), resp.status, elapsed_ms
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        elapsed_ms = (time.perf_counter() - start) * 1000
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return parsed, e.code, elapsed_ms


class StepFailure(Exception):
    pass


def must_ok(name, result):
    """检查接口是否成功；若失败则抛出异常并携带详细信息。"""
    payload, status, elapsed_ms = result
    if status != 200:
        raise StepFailure(f"步骤 {name} 失败，HTTP {status}，响应={payload}")
    return payload, elapsed_ms


def normalize_expect_mode(expect_mode: str) -> str:
    """规范化期望模式。"""
    mode = (expect_mode or "").strip().lower()
    allowed = {"plain", "secure_stub", "secure_orchestrating"}
    if mode not in allowed:
        raise StepFailure(f"--expect-mode 不合法：{expect_mode}，必须是 {sorted(allowed)} 之一")
    return mode


def validate_evaluation_for_mode(evaluation: dict, expect_mode: str):
    """
    根据期望模式校验 evaluate 返回结果。
    返回：
    - evaluator_mode
    - backend_mode
    - secure_execution
    """
    evaluator_mode = evaluation.get("evaluator_mode")
    backend_mode = evaluation.get("backend_mode")
    secure_execution = evaluation.get("secure_execution")

    if expect_mode == "plain":
        if evaluator_mode != "plain":
            raise StepFailure(f"plain 模式下预期 evaluator_mode=plain，但实际为 {evaluator_mode}")
        if backend_mode != "local_plain":
            raise StepFailure(f"plain 模式下预期 backend_mode=local_plain，但实际为 {backend_mode}")
        if secure_execution is not None:
            raise StepFailure("plain 模式下不应返回 secure_execution")
        return evaluator_mode, backend_mode, secure_execution

    # secure_stub / secure_orchestrating 统一走 secure 校验
    if evaluator_mode != expect_mode:
        raise StepFailure(
            f"{expect_mode} 模式下预期 evaluator_mode={expect_mode}，但实际为 {evaluator_mode}"
        )

    if backend_mode != "mock_mpc":
        raise StepFailure(f"{expect_mode} 模式下预期 backend_mode=mock_mpc，但实际为 {backend_mode}")

    if not isinstance(secure_execution, dict):
        raise StepFailure(f"{expect_mode} 模式下 secure_execution 不应为空")

    if secure_execution.get("backend_mode") != "mock_mpc":
        raise StepFailure(
            f"{expect_mode} 模式下 secure_execution.backend_mode 应为 mock_mpc，"
            f"但实际为 {secure_execution.get('backend_mode')}"
        )

    if secure_execution.get("decision") != evaluation.get("decision"):
        raise StepFailure(
            f"{expect_mode} 模式下 secure_execution.decision 与 evaluation.decision 不一致："
            f"{secure_execution.get('decision')} vs {evaluation.get('decision')}"
        )

    if not secure_execution.get("execution_id"):
        raise StepFailure(f"{expect_mode} 模式下 secure_execution.execution_id 不应为空")

    if not secure_execution.get("proof_stub"):
        raise StepFailure(f"{expect_mode} 模式下 secure_execution.proof_stub 不应为空")

    transcript = secure_execution.get("transcript")
    if not isinstance(transcript, list) or len(transcript) == 0:
        raise StepFailure(f"{expect_mode} 模式下 secure_execution.transcript 不应为空")

    steps = secure_execution.get("steps")
    if not isinstance(steps, list) or len(steps) == 0:
        raise StepFailure(f"{expect_mode} 模式下 secure_execution.steps 不应为空")

    return evaluator_mode, backend_mode, secure_execution


def validate_deny_path_outcome(evaluation: dict, artifact: dict, final_session: dict):
    """deny path 的最终结果校验。"""
    if evaluation.get("decision") != "DENY":
        raise StepFailure(f"deny path 预期 evaluation.decision=DENY，但实际为 {evaluation.get('decision')}")

    if artifact.get("authorization_decision") != "DENY":
        raise StepFailure(
            "deny path 预期 artifact.authorization_decision=DENY，"
            f"但实际为 {artifact.get('authorization_decision')}"
        )

    if final_session.get("state") != "ENFORCED":
        raise StepFailure(
            f"deny path 预期最终 session.state=ENFORCED，但实际为 {final_session.get('state')}"
        )


def validate_secure_deny_reason(secure_execution: dict | None):
    """在 secure 模式下，额外校验 deny 的结构化结果。"""
    if not secure_execution:
        return

    if secure_execution.get("decision") != "DENY":
        raise StepFailure(
            f"secure 模式下预期 secure_execution.decision=DENY，但实际为 {secure_execution.get('decision')}"
        )

    reason = secure_execution.get("reason")
    if not reason:
        raise StepFailure("secure 模式下 deny 结果应包含 secure_execution.reason")


def extract_secure_execution_brief(secure_execution: dict | None) -> dict:
    """提取 secure execution 的摘要信息，便于写入步骤结果。"""
    secure_execution = secure_execution or {}
    return {
        "secure_execution_id": secure_execution.get("execution_id"),
        "secure_execution_backend_mode": secure_execution.get("backend_mode"),
        "proof_stub": secure_execution.get("proof_stub"),
        "transcript_len": len(secure_execution.get("transcript", []) or []),
        "steps_len": len(secure_execution.get("steps", []) or []),
        "secure_execution_reason": secure_execution.get("reason"),
    }


def run_once(base_url: str, expect_mode: str):
    """执行一轮完整 deny path，返回原始结果和计时信息。"""
    steps = []
    expect_mode = normalize_expect_mode(expect_mode)

    # 1. 创建策略。
    policy_req = {
        "name": "cross-domain research access policy deny-path",
        "content": {
            "clauses": [
                {
                    "source": "evidence",
                    "field": "role",
                    "op": "eq",
                    "value": "researcher",
                    "owner": "requester"
                },
                {
                    "source": "evidence",
                    "field": "department",
                    "op": "eq",
                    "value": "lab-a",
                    "owner": "requester"
                },
                {
                    "source": "context",
                    "field": "purpose",
                    "op": "eq",
                    "value": "study",
                    "owner": "requester"
                },
                {
                    "source": "snapshot",
                    "field": "resource_status",
                    "op": "eq",
                    "value": "active",
                    "owner": "provider"
                }
            ],
            "description": "拒绝不满足科研角色或部门约束的访问请求",
        },
    }
    payload, elapsed = must_ok("create_policy", request_json("POST", f"{base_url}/api/v1/policies", policy_req))
    policy = payload["data"]
    policy_id = policy["id"]
    steps.append({"step": "create_policy", "latency_ms": elapsed, "id": policy_id})

    # 2. 策略准入。
    payload, elapsed = must_ok("admit_policy", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/admit"))
    steps.append({"step": "admit_policy", "latency_ms": elapsed, "status": payload["data"]["status"]})

    # 3. 策略发布。
    payload, elapsed = must_ok("publish_policy", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/publish"))
    steps.append({"step": "publish_policy", "latency_ms": elapsed, "status": payload["data"]["status"]})

    # 4. 派生执行计划。
    payload, elapsed = must_ok("derive_plan", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/derive-plan"))
    plan = payload["data"]
    plan_id = plan["id"]
    steps.append({"step": "derive_plan", "latency_ms": elapsed, "id": plan_id})

    # 5. 创建执行会话。
    session_req = {
        "policy_id": policy_id,
        "plan_id": plan_id,
        "requester": "bob",
        "resource_id": "dataset-001",
        "context": {
            "purpose": "study",
            "channel": "prototype-client",
            "request_ip": "127.0.0.1",
        },
    }
    payload, elapsed = must_ok("create_session", request_json("POST", f"{base_url}/api/v1/sessions", session_req))
    session = payload["data"]
    session_id = session["id"]
    steps.append({"step": "create_session", "latency_ms": elapsed, "id": session_id, "state": session["state"]})

    # 6. 提交证据：这里故意给出不满足策略的角色和部门，使系统走到 DENY。
    evidence_req = {
        "payload": {
            "role": "visitor",
            "department": "lab-b",
            "purpose": "study",
            "holder": "did:example:bob",
            "credential_id": "vc-deny-001",
        }
    }
    payload, elapsed = must_ok("admit_evidence", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evidence", evidence_req))
    steps.append({
        "step": "admit_evidence",
        "latency_ms": elapsed,
        "evidence_id": payload["data"]["evidence"]["id"],
        "state": payload["data"]["session"]["state"],
    })

    # 7. 固定快照：快照本身保持合法，确保 DENY 主要由证据不满足策略导致。
    snapshot_req = {
        "payload": {
            "resource_status": "active",
            "lifecycle": "approved",
            "owner_domain": "lab-a",
            "version": "v1",
        }
    }
    payload, elapsed = must_ok("pin_snapshot", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/snapshot", snapshot_req))
    steps.append({
        "step": "pin_snapshot",
        "latency_ms": elapsed,
        "snapshot_id": payload["data"]["snapshot"]["id"],
        "state": payload["data"]["session"]["state"],
    })

    # 8. 执行评估：此处预期 decision=DENY。
    payload, elapsed = must_ok("evaluate", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evaluate"))
    evaluation = payload["data"]["evaluation"]
    evaluator_mode, backend_mode, secure_execution = validate_evaluation_for_mode(evaluation, expect_mode)

    if evaluation["decision"] != "DENY":
        raise StepFailure(f"deny path 预期 decision=DENY，但实际为 {evaluation['decision']}")

    validate_secure_deny_reason(secure_execution)

    evaluate_step = {
        "step": "evaluate",
        "latency_ms": elapsed,
        "evaluation_id": evaluation["id"],
        "decision": evaluation["decision"],
        "reason": evaluation.get("reason"),
        "evaluator_mode": evaluator_mode,
        "backend_mode": backend_mode,
        "state": payload["data"]["session"]["state"],
    }
    evaluate_step.update(extract_secure_execution_brief(secure_execution))
    steps.append(evaluate_step)

    # 9. 生成工件并完成执行。
    payload, elapsed = must_ok("seal_artifact", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/artifact"))
    artifact = payload["data"]["artifact"]
    final_session = payload["data"]["session"]

    validate_deny_path_outcome(evaluation, artifact, final_session)

    steps.append({
        "step": "seal_artifact",
        "latency_ms": elapsed,
        "artifact_id": artifact["id"],
        "decision": artifact["authorization_decision"],
        "state": final_session["state"],
    })

    # 10. 拉取审计包。
    payload, elapsed = must_ok("get_audit_bundle", request_json("GET", f"{base_url}/api/v1/sessions/{session_id}/audit"))
    audit_bundle = payload["data"]
    events = audit_bundle.get("events", [])

    steps.append({
        "step": "get_audit_bundle",
        "latency_ms": elapsed,
        "event_count": len(events),
    })

    total_ms = sum(step["latency_ms"] for step in steps)
    return {
        "expect_mode": expect_mode,
        "steps": steps,
        "total_latency_ms": total_ms,
        "final_decision": artifact["authorization_decision"],
        "final_session_state": final_session["state"],
        "artifact_id": artifact["id"],
        "policy_id": policy_id,
        "plan_id": plan_id,
        "session_id": session_id,
        "event_count": len(events),
        "evaluation": {
            "id": evaluation["id"],
            "decision": evaluation["decision"],
            "reason": evaluation.get("reason"),
            "evaluator_mode": evaluator_mode,
            "backend_mode": backend_mode,
            "secure_execution": secure_execution,
        },
    }


def print_summary(runs):
    """打印简洁的统计摘要。"""
    print("\n=== Deny Path 统计摘要 ===")
    totals = [run["total_latency_ms"] for run in runs]
    print(f"执行轮数: {len(runs)}")
    print(f"总耗时均值: {statistics.mean(totals):.3f} ms")
    print(f"总耗时最小值: {min(totals):.3f} ms")
    print(f"总耗时最大值: {max(totals):.3f} ms")

    step_names = [step["step"] for step in runs[0]["steps"]]
    print("\n每一步平均耗时：")
    for step_name in step_names:
        values = []
        for run in runs:
            for step in run["steps"]:
                if step["step"] == step_name:
                    values.append(step["latency_ms"])
                    break
        print(f"- {step_name:<18} {statistics.mean(values):>10.3f} ms")

    print("\n最后一轮结果：")
    last = runs[-1]
    print(f"- expect_mode: {last['expect_mode']}")
    print(f"- final_decision: {last['final_decision']}")
    print(f"- final_session_state: {last['final_session_state']}")
    print(f"- event_count: {last['event_count']}")
    print(f"- artifact_id: {last['artifact_id']}")
    print(f"- evaluator_mode: {last['evaluation']['evaluator_mode']}")
    print(f"- backend_mode: {last['evaluation']['backend_mode']}")

    secure_execution = last["evaluation"].get("secure_execution")
    if secure_execution:
        print(f"- secure_execution_id: {secure_execution.get('execution_id')}")
        print(f"- proof_stub: {secure_execution.get('proof_stub')}")
        print(f"- transcript_len: {len(secure_execution.get('transcript', []) or [])}")
        print(f"- steps_len: {len(secure_execution.get('steps', []) or [])}")


def main():
    parser = argparse.ArgumentParser(description="Run govauth deny path and collect latency metrics.")
    parser.add_argument("--base-url", default="http://localhost:8080", help="服务基地址，默认 http://localhost:8080")
    parser.add_argument("--rounds", type=int, default=3, help="执行轮数，默认 3")
    parser.add_argument("--output", default="scripts/deny_path_result.json", help="结果输出路径")
    parser.add_argument(
        "--expect-mode",
        default="plain",
        choices=["plain", "secure_stub", "secure_orchestrating"],
        help="期望的 evaluator 模式，默认 plain",
    )
    args = parser.parse_args()

    runs = []
    for idx in range(args.rounds):
        run = run_once(args.base_url, args.expect_mode)
        runs.append(run)
        print(
            f"第 {idx + 1} 轮完成："
            f"mode={run['expect_mode']} "
            f"decision={run['final_decision']} "
            f"backend={run['evaluation']['backend_mode']} "
            f"total={run['total_latency_ms']:.3f} ms"
        )

    print_summary(runs)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"runs": runs}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n详细结果已写入: {output_path}")


if __name__ == "__main__":
    main()