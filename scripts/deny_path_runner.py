#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
这个脚本用于自动执行 govauth 的 deny path，并测量每一步接口的耗时。

本版增强点：
1. 支持 evaluator_mode 与 backend_mode 分离校验：
   - plain + local_plain
   - secure_stub + mock_mpc
   - secure_orchestrating + mock_mpc
   - secure_orchestrating + real_mpc
2. 支持详细日志输出到 scripts/logs/ 目录。
3. 日志记录每一步的：
   - 请求方法 / URL
   - 请求 payload
   - 响应 JSON
   - latency
   - session 状态变化
   - evaluator / backend / secure_execution 摘要
4. JSON 输出继续保持结构化，便于后续实验统计。
"""

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


class StepFailure(Exception):
    pass


def now_str():
    """返回适合文件名与日志标识的时间字符串。"""
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def json_dumps_safe(obj):
    """安全转 JSON 字符串。"""
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


class RunLogger:
    """简单文件日志器。"""

    def __init__(self, log_dir: Path, prefix: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / f"{prefix}_{now_str()}.log"

    def write(self, message: str):
        text = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] {message}\n"
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text)

    def section(self, title: str):
        self.write("=" * 30 + f" {title} " + "=" * 30)


def request_json(method: str, url: str, payload=None, timeout=10, logger: RunLogger | None = None):
    """发送 HTTP 请求，并返回 (解析后的 JSON, 状态码, 耗时毫秒)。"""
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url=url, data=data, headers=headers, method=method)

    if logger:
        logger.section(f"HTTP REQUEST {method} {url}")
        logger.write(f"request_payload=\n{json_dumps_safe(payload) if payload is not None else 'null'}")

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            elapsed_ms = (time.perf_counter() - start) * 1000
            parsed = json.loads(body)

            if logger:
                logger.write(f"http_status={resp.status}")
                logger.write(f"latency_ms={elapsed_ms:.3f}")
                logger.write(f"response_body=\n{json_dumps_safe(parsed)}")

            return parsed, resp.status, elapsed_ms
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        elapsed_ms = (time.perf_counter() - start) * 1000
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}

        if logger:
            logger.write(f"http_status={e.code}")
            logger.write(f"latency_ms={elapsed_ms:.3f}")
            logger.write(f"response_body=\n{json_dumps_safe(parsed)}")

        return parsed, e.code, elapsed_ms


def must_ok(name, result):
    """检查接口是否成功；若失败则抛出异常并携带详细信息。"""
    payload, status, elapsed_ms = result
    if status != 200:
        raise StepFailure(f"步骤 {name} 失败，HTTP {status}，响应={payload}")
    return payload, elapsed_ms


def normalize_expect_mode(expect_mode: str) -> str:
    """规范化 evaluator 模式。"""
    mode = (expect_mode or "").strip().lower()
    allowed = {"plain", "secure_stub", "secure_orchestrating"}
    if mode not in allowed:
        raise StepFailure(f"--expect-mode 不合法：{expect_mode}，必须是 {sorted(allowed)} 之一")
    return mode


def normalize_expect_backend(expect_backend: str, expect_mode: str) -> str:
    """规范化 backend 模式；支持 auto 自动推导。"""
    backend = (expect_backend or "").strip().lower()
    allowed = {"auto", "local_plain", "mock_mpc", "real_mpc"}
    if backend not in allowed:
        raise StepFailure(f"--expect-backend 不合法：{expect_backend}，必须是 {sorted(allowed)} 之一")

    if backend == "auto":
        if expect_mode == "plain":
            return "local_plain"
        if expect_mode == "secure_stub":
            return "mock_mpc"
        if expect_mode == "secure_orchestrating":
            return "mock_mpc"
    return backend


def validate_evaluation_for_mode(evaluation: dict, expect_mode: str, expect_backend: str):
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

    if evaluator_mode != expect_mode:
        raise StepFailure(
            f"预期 evaluator_mode={expect_mode}，但实际为 {evaluator_mode}"
        )

    if backend_mode != expect_backend:
        raise StepFailure(
            f"预期 backend_mode={expect_backend}，但实际为 {backend_mode}"
        )

    if expect_mode == "plain":
        if secure_execution is not None:
            raise StepFailure("plain 模式下不应返回 secure_execution")
        return evaluator_mode, backend_mode, secure_execution

    if not isinstance(secure_execution, dict):
        raise StepFailure(f"{expect_mode} 模式下 secure_execution 不应为空")

    if secure_execution.get("backend_mode") != expect_backend:
        raise StepFailure(
            f"{expect_mode} 模式下 secure_execution.backend_mode 应为 {expect_backend}，"
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


def log_step_result(logger: RunLogger, step_name: str, step_result: dict):
    """把步骤结果详细写入日志。"""
    logger.section(f"STEP RESULT {step_name}")
    logger.write(json_dumps_safe(step_result))


def run_once(base_url: str, expect_mode: str, expect_backend: str, logger: RunLogger):
    """执行一轮完整 deny path，返回原始结果和计时信息。"""
    steps = []
    expect_mode = normalize_expect_mode(expect_mode)
    expect_backend = normalize_expect_backend(expect_backend, expect_mode)

    logger.section("RUN START")
    logger.write(f"expect_mode={expect_mode}")
    logger.write(f"expect_backend={expect_backend}")
    logger.write(f"base_url={base_url}")

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
    payload, elapsed = must_ok("create_policy", request_json("POST", f"{base_url}/api/v1/policies", policy_req, logger=logger))
    policy = payload["data"]
    policy_id = policy["id"]
    step_result = {"step": "create_policy", "latency_ms": elapsed, "id": policy_id}
    steps.append(step_result)
    log_step_result(logger, "create_policy", step_result)

    # 2. 策略准入。
    payload, elapsed = must_ok("admit_policy", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/admit", logger=logger))
    step_result = {"step": "admit_policy", "latency_ms": elapsed, "status": payload["data"]["status"]}
    steps.append(step_result)
    log_step_result(logger, "admit_policy", step_result)

    # 3. 策略发布。
    payload, elapsed = must_ok("publish_policy", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/publish", logger=logger))
    step_result = {"step": "publish_policy", "latency_ms": elapsed, "status": payload["data"]["status"]}
    steps.append(step_result)
    log_step_result(logger, "publish_policy", step_result)

    # 4. 派生执行计划。
    payload, elapsed = must_ok("derive_plan", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/derive-plan", logger=logger))
    plan = payload["data"]
    plan_id = plan["id"]
    step_result = {"step": "derive_plan", "latency_ms": elapsed, "id": plan_id}
    steps.append(step_result)
    log_step_result(logger, "derive_plan", step_result)

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
    payload, elapsed = must_ok("create_session", request_json("POST", f"{base_url}/api/v1/sessions", session_req, logger=logger))
    session = payload["data"]
    session_id = session["id"]
    step_result = {"step": "create_session", "latency_ms": elapsed, "id": session_id, "state": session["state"]}
    steps.append(step_result)
    log_step_result(logger, "create_session", step_result)

    # 6. 提交证据：故意不满足策略，使系统走到 DENY。
    evidence_req = {
        "payload": {
            "role": "visitor",
            "department": "lab-b",
            "purpose": "study",
            "holder": "did:example:bob",
            "credential_id": "vc-deny-001",
        }
    }
    payload, elapsed = must_ok("admit_evidence", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evidence", evidence_req, logger=logger))
    step_result = {
        "step": "admit_evidence",
        "latency_ms": elapsed,
        "evidence_id": payload["data"]["evidence"]["id"],
        "state": payload["data"]["session"]["state"],
    }
    steps.append(step_result)
    log_step_result(logger, "admit_evidence", step_result)

    # 7. 固定快照：快照本身保持合法，确保 DENY 主要由证据不满足策略导致。
    snapshot_req = {
        "payload": {
            "resource_status": "active",
            "lifecycle": "approved",
            "owner_domain": "lab-a",
            "version": "v1",
        }
    }
    payload, elapsed = must_ok("pin_snapshot", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/snapshot", snapshot_req, logger=logger))
    step_result = {
        "step": "pin_snapshot",
        "latency_ms": elapsed,
        "snapshot_id": payload["data"]["snapshot"]["id"],
        "state": payload["data"]["session"]["state"],
    }
    steps.append(step_result)
    log_step_result(logger, "pin_snapshot", step_result)

    # 8. 执行评估。
    payload, elapsed = must_ok("evaluate", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evaluate", logger=logger))
    evaluation = payload["data"]["evaluation"]
    evaluator_mode, backend_mode, secure_execution = validate_evaluation_for_mode(
        evaluation, expect_mode, expect_backend
    )

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
    log_step_result(logger, "evaluate", evaluate_step)

    # 9. 生成工件并完成执行。
    payload, elapsed = must_ok("seal_artifact", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/artifact", logger=logger))
    artifact = payload["data"]["artifact"]
    final_session = payload["data"]["session"]

    validate_deny_path_outcome(evaluation, artifact, final_session)

    step_result = {
        "step": "seal_artifact",
        "latency_ms": elapsed,
        "artifact_id": artifact["id"],
        "decision": artifact["authorization_decision"],
        "state": final_session["state"],
    }
    steps.append(step_result)
    log_step_result(logger, "seal_artifact", step_result)

    # 10. 拉取审计包。
    payload, elapsed = must_ok("get_audit_bundle", request_json("GET", f"{base_url}/api/v1/sessions/{session_id}/audit", logger=logger))
    audit_bundle = payload["data"]
    events = audit_bundle.get("events", [])

    step_result = {
        "step": "get_audit_bundle",
        "latency_ms": elapsed,
        "event_count": len(events),
    }
    steps.append(step_result)
    log_step_result(logger, "get_audit_bundle", step_result)

    total_ms = sum(step["latency_ms"] for step in steps)
    run_result = {
        "expect_mode": expect_mode,
        "expect_backend": expect_backend,
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
        "log_file": str(logger.path),
    }

    logger.section("RUN END")
    logger.write(json_dumps_safe(run_result))
    return run_result


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
    print(f"- expect_backend: {last['expect_backend']}")
    print(f"- final_decision: {last['final_decision']}")
    print(f"- final_session_state: {last['final_session_state']}")
    print(f"- event_count: {last['event_count']}")
    print(f"- artifact_id: {last['artifact_id']}")
    print(f"- evaluator_mode: {last['evaluation']['evaluator_mode']}")
    print(f"- backend_mode: {last['evaluation']['backend_mode']}")
    print(f"- log_file: {last['log_file']}")

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
    parser.add_argument(
        "--expect-backend",
        default="auto",
        choices=["auto", "local_plain", "mock_mpc", "real_mpc"],
        help="期望的 backend 模式，默认 auto。若你使用 RealMPCBackend，请显式传 real_mpc。",
    )
    parser.add_argument(
        "--log-dir",
        default="scripts/logs",
        help="详细日志输出目录，默认 scripts/logs",
    )
    args = parser.parse_args()

    runs = []
    for idx in range(args.rounds):
        logger = RunLogger(Path(args.log_dir), prefix=f"deny_path_round_{idx + 1}")
        try:
            run = run_once(args.base_url, args.expect_mode, args.expect_backend, logger)
            runs.append(run)
            print(
                f"第 {idx + 1} 轮完成："
                f"mode={run['expect_mode']} "
                f"backend={run['expect_backend']} "
                f"decision={run['final_decision']} "
                f"actual_backend={run['evaluation']['backend_mode']} "
                f"total={run['total_latency_ms']:.3f} ms"
            )
        except Exception as e:
            logger.section("RUN FAILED")
            logger.write(str(e))
            raise

    print_summary(runs)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"runs": runs}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n详细结果已写入: {output_path}")


if __name__ == "__main__":
    main()