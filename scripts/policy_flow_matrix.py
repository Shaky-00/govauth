#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
统一的 GovAuth 流程测试脚本。

设计目标：
1. 用一个脚本统一覆盖 plain / mock_mpc / real_mpc 三种模式。
2. 用一个脚本统一覆盖 happy / deny 两种场景。
3. 尽量减少重复启动服务端的次数：
   - 以“模式”为单位启动服务；
   - 每启动一次服务，在该模式下连续跑 happy 和 deny。
4. 输出结构化 JSON，便于后续实验统计和论文画图。
5. 所有关键步骤带中文注释，方便后续维护。

推荐使用方式：
    python3 ./scripts/policy_flow_matrix.py

也支持自定义：
    python3 ./scripts/policy_flow_matrix.py --modes plain,mock,real --scenarios happy,deny --rounds 1
"""

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class StepFailure(Exception):
    """某一步接口或断言失败时抛出的异常。"""
    pass


class RunLogger:
    """简单日志器：每个 mode 一个日志文件。"""

    def __init__(self, log_dir: Path, prefix: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log"

    def write(self, message: str) -> None:
        text = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] {message}\n"
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text)

    def section(self, title: str) -> None:
        self.write("=" * 30 + f" {title} " + "=" * 30)


def json_dumps_safe(obj) -> str:
    """尽量安全地转 JSON 字符串，避免日志写入时报错。"""
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


def request_json(
    method: str,
    url: str,
    payload=None,
    timeout: int = 15,
    logger: Optional[RunLogger] = None,
) -> Tuple[dict, int, float]:
    """
    发送 HTTP 请求，并返回：
    - 解析后的 JSON
    - HTTP 状态码
    - 耗时毫秒
    """
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


def must_ok(name: str, result: Tuple[dict, int, float]) -> Tuple[dict, float]:
    """要求接口必须返回 200，否则抛错。"""
    payload, status, elapsed_ms = result
    if status != 200:
        raise StepFailure(f"步骤 {name} 失败，HTTP {status}，响应={payload}")
    return payload, elapsed_ms


def mode_to_expectation(mode: str) -> Tuple[str, str]:
    """
    将脚本里的简写 mode 映射到服务端 evaluate 返回中应出现的：
    - evaluator_mode
    - backend_mode
    """
    mode = mode.strip().lower()
    if mode == "plain":
        return "plain", "local_plain"
    if mode == "mock":
        return "secure_orchestrating", "mock_mpc"
    if mode == "real":
        return "secure_orchestrating", "real_mpc"
    raise StepFailure(f"未知模式：{mode}")


def build_server_env(base_env: Dict[str, str], mode: str) -> Dict[str, str]:
    """
    根据 mode 构造服务端启动环境变量。
    注意：
    - plain 模式只设置 EVALUATOR_MODE=plain
    - mock / real 模式设置 secure_orchestrating + 对应 backend
    - MPC 相关环境变量直接透传，便于 real_mpc 使用
    """
    env = dict(base_env)

    evaluator_mode, backend_mode = mode_to_expectation(mode)
    env["EVALUATOR_MODE"] = evaluator_mode

    # 先清掉，避免旧环境污染。
    env.pop("SECURE_BACKEND_MODE", None)

    if evaluator_mode == "secure_orchestrating":
        env["SECURE_BACKEND_MODE"] = backend_mode

    return env


def wait_for_health(base_url: str, timeout_sec: int, logger: Optional[RunLogger]) -> None:
    """等待服务端 /healthz 就绪。"""
    deadline = time.time() + timeout_sec
    last_error = None

    while time.time() < deadline:
        try:
            payload, status, _ = request_json("GET", f"{base_url}/healthz", logger=logger)
            if status == 200:
                if logger:
                    logger.write(f"healthz ready: {json_dumps_safe(payload)}")
                return
        except Exception as e:
            last_error = str(e)
        time.sleep(1)

    raise StepFailure(f"服务在 {timeout_sec}s 内未就绪，最后错误：{last_error}")

import socket

def ensure_port_free(host: str, port: int):
    """确保目标端口空闲，避免误打到旧服务。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            raise StepFailure(
                f"端口 {host}:{port} 已被占用。请先关闭旧的 govauth 服务，否则测试可能会命中旧进程。"
            )

def start_server(
    root_dir: Path,
    mode: str,
    base_url: str,
    logger: RunLogger,
    startup_timeout_sec: int,
) -> subprocess.Popen:
    """
    启动 govauth 服务端。
    这里使用 subprocess.Popen，便于脚本统一管理生命周期。
    """
    env = build_server_env(os.environ.copy(), mode)

    server_log = root_dir / "scripts" / f"server_{mode}.log"
    server_log.parent.mkdir(parents=True, exist_ok=True)

    logger.section(f"START SERVER [{mode}]")
    logger.write(f"server_log={server_log}")
    logger.write(f"EVALUATOR_MODE={env.get('EVALUATOR_MODE')}")
    logger.write(f"SECURE_BACKEND_MODE={env.get('SECURE_BACKEND_MODE')}")

    with server_log.open("w", encoding="utf-8") as f:
        proc = subprocess.Popen(
            ["go", "run", "./cmd/server"],
            cwd=str(root_dir),
            stdout=f,
            stderr=subprocess.STDOUT,
            env=env,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )

    logger.write(f"server_pid={proc.pid}")
    wait_for_health(base_url, startup_timeout_sec, logger)
    return proc


def stop_server(proc: Optional[subprocess.Popen], logger: Optional[RunLogger]) -> None:
    """关闭服务端。"""
    if proc is None:
        return

    try:
        if logger:
            logger.section("STOP SERVER")
            logger.write(f"server_pid={proc.pid}")

        if os.name != "nt":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()

        proc.wait(timeout=10)
    except Exception:
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


def validate_evaluation_for_mode(evaluation: dict, mode: str) -> Tuple[str, str, Optional[dict]]:
    """
    校验 evaluate 返回是否符合当前 mode 的预期。
    """
    expect_evaluator_mode, expect_backend_mode = mode_to_expectation(mode)

    evaluator_mode = evaluation.get("evaluator_mode")
    backend_mode = evaluation.get("backend_mode")
    secure_execution = evaluation.get("secure_execution")

    if evaluator_mode != expect_evaluator_mode:
        raise StepFailure(
            f"模式 {mode} 下，预期 evaluator_mode={expect_evaluator_mode}，实际为 {evaluator_mode}"
        )

    if backend_mode != expect_backend_mode:
        raise StepFailure(
            f"模式 {mode} 下，预期 backend_mode={expect_backend_mode}，实际为 {backend_mode}"
        )

    # plain 模式下，不应该带 secure_execution。
    if mode == "plain":
        if secure_execution is not None:
            raise StepFailure("plain 模式下不应返回 secure_execution")
        return evaluator_mode, backend_mode, None

    # mock / real 模式下，应该带 secure_execution
    if not isinstance(secure_execution, dict):
        raise StepFailure(f"{mode} 模式下 secure_execution 不应为空")

    if secure_execution.get("backend_mode") != expect_backend_mode:
        raise StepFailure(
            f"{mode} 模式下 secure_execution.backend_mode 应为 {expect_backend_mode}，"
            f"但实际为 {secure_execution.get('backend_mode')}"
        )

    if secure_execution.get("decision") != evaluation.get("decision"):
        raise StepFailure(
            f"{mode} 模式下 secure_execution.decision 与 evaluation.decision 不一致："
            f"{secure_execution.get('decision')} vs {evaluation.get('decision')}"
        )

    if not secure_execution.get("execution_id"):
        raise StepFailure(f"{mode} 模式下 secure_execution.execution_id 不应为空")

    return evaluator_mode, backend_mode, secure_execution


def extract_secure_execution_brief(secure_execution: Optional[dict]) -> dict:
    """提取 secure_execution 的摘要，便于结果记录。"""
    secure_execution = secure_execution or {}
    return {
        "secure_execution_id": secure_execution.get("execution_id"),
        "secure_execution_backend_mode": secure_execution.get("backend_mode"),
        "proof_stub": secure_execution.get("proof_stub"),
        "transcript_len": len(secure_execution.get("transcript", []) or []),
        "steps_len": len(secure_execution.get("steps", []) or []),
        "secure_execution_reason": secure_execution.get("reason"),
    }


def build_case_data(scenario: str) -> dict:
    """
    构造场景数据。
    - happy：应走 ALLOW
    - deny：应走 DENY
    """
    scenario = scenario.strip().lower()

    if scenario == "happy":
        return {
            "expected_decision": "ALLOW",
            "policy_req": {
                "name": "cross-domain research access policy",
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
                            "source": "context",
                            "field": "risk_score",
                            "op": "lte",
                            "value": 60,
                            "owner": "authority"
                        },
                        {
                            "source": "snapshot",
                            "field": "clearance_level",
                            "op": "gte",
                            "value": 3,
                            "owner": "provider"
                        },
                        {
                            "source": "snapshot",
                            "field": "resource_status",
                            "op": "neq",
                            "value": "revoked",
                            "owner": "provider"
                        }
                    ],
                    "description": "允许满足科研用途与部门约束的请求访问活跃数据资源",
                },
            },
            "session_req": {
                "requester": "alice",
                "resource_id": "dataset-001",
                "context": {
                    "purpose": "study",
                    "channel": "prototype-client",
                    "request_ip": "127.0.0.1",
                    "risk_score": 45
                },
            },
            "evidence_req": {
                "payload": {
                    "role": "researcher",
                    "holder": "did:example:alice",
                    "credential_id": "vc-001"
                }
            },
            "snapshot_req": {
                "payload": {
                    "resource_status": "active",
                    "lifecycle": "approved",
                    "owner_domain": "lab-a",
                    "version": "v1",
                    "clearance_level": 4
                }
            },
        }

    if scenario == "deny":
        # deny 这里故意把多个条件都设成不满足，保证稳定走 DENY。
        return {
            "expected_decision": "DENY",
            "policy_req": {
                "name": "cross-domain research access deny policy",
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
                            "source": "context",
                            "field": "risk_score",
                            "op": "lte",
                            "value": 60,
                            "owner": "authority"
                        },
                        {
                            "source": "snapshot",
                            "field": "clearance_level",
                            "op": "gte",
                            "value": 3,
                            "owner": "provider"
                        },
                        {
                            "source": "snapshot",
                            "field": "resource_status",
                            "op": "neq",
                            "value": "revoked",
                            "owner": "provider"
                        }
                    ],
                    "description": "用于验证 deny 流程的策略",
                },
            },
            "session_req": {
                "requester": "bob",
                "resource_id": "dataset-002",
                "context": {
                    "purpose": "unknown",
                    "channel": "prototype-client",
                    "request_ip": "127.0.0.1",
                    "risk_score": 95
                },
            },
            "evidence_req": {
                "payload": {
                    "role": "guest",
                    "holder": "did:example:bob",
                    "credential_id": "vc-002"
                }
            },
            "snapshot_req": {
                "payload": {
                    "resource_status": "revoked",
                    "lifecycle": "frozen",
                    "owner_domain": "lab-b",
                    "version": "v2",
                    "clearance_level": 1
                }
            },
        }

    raise StepFailure(f"未知场景：{scenario}")


def validate_final_outcome(
    scenario: str,
    evaluation: dict,
    artifact: Optional[dict],
    final_session: Optional[dict],
) -> None:
    """
    校验 happy / deny 最终结果。
    为避免和你现有实现状态机细节过度绑定，这里做“必要但不过度死板”的断言：
    - happy 必须 ALLOW
    - deny 必须 DENY
    - artifact 如果存在，则其 authorization_decision 必须与预期一致
    """
    expected_decision = build_case_data(scenario)["expected_decision"]
    actual_decision = evaluation.get("decision")

    if actual_decision != expected_decision:
        raise StepFailure(
            f"{scenario} 场景预期 evaluation.decision={expected_decision}，实际为 {actual_decision}"
        )

    if artifact is not None:
        artifact_decision = artifact.get("authorization_decision")
        if artifact_decision != expected_decision:
            raise StepFailure(
                f"{scenario} 场景预期 artifact.authorization_decision={expected_decision}，"
                f"实际为 {artifact_decision}"
            )

    if final_session is not None and not final_session.get("state"):
        raise StepFailure(f"{scenario} 场景 final_session.state 不应为空")


def run_one_scenario(
    base_url: str,
    mode: str,
    scenario: str,
    round_idx: int,
    logger: RunLogger,
) -> dict:
    """
    在某个 mode 下执行一次具体场景（happy 或 deny）。
    """
    steps: List[dict] = []
    case_data = build_case_data(scenario)

    logger.section(f"SCENARIO START mode={mode} scenario={scenario} round={round_idx}")

    # 1. 创建策略
    payload, elapsed = must_ok(
        "create_policy",
        request_json("POST", f"{base_url}/api/v1/policies", case_data["policy_req"], logger=logger)
    )
    policy = payload["data"]
    policy_id = policy["id"]
    steps.append({"step": "create_policy", "latency_ms": elapsed, "id": policy_id})

    # 2. 策略准入
    payload, elapsed = must_ok(
        "admit_policy",
        request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/admit", logger=logger)
    )
    steps.append({"step": "admit_policy", "latency_ms": elapsed, "status": payload["data"]["status"]})

    # 3. 策略发布
    payload, elapsed = must_ok(
        "publish_policy",
        request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/publish", logger=logger)
    )
    steps.append({"step": "publish_policy", "latency_ms": elapsed, "status": payload["data"]["status"]})

    # 4. 派生执行计划
    payload, elapsed = must_ok(
        "derive_plan",
        request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/derive-plan", logger=logger)
    )
    plan = payload["data"]
    plan_id = plan["id"]
    steps.append({"step": "derive_plan", "latency_ms": elapsed, "id": plan_id})

    # 5. 创建会话
    session_req = deepcopy(case_data["session_req"])
    session_req["policy_id"] = policy_id
    session_req["plan_id"] = plan_id

    payload, elapsed = must_ok(
        "create_session",
        request_json("POST", f"{base_url}/api/v1/sessions", session_req, logger=logger)
    )
    session = payload["data"]
    session_id = session["id"]
    steps.append({"step": "create_session", "latency_ms": elapsed, "id": session_id, "state": session.get("state")})

    # 6. 提交证据
    payload, elapsed = must_ok(
        "admit_evidence",
        request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evidence", case_data["evidence_req"], logger=logger)
    )
    steps.append({
        "step": "admit_evidence",
        "latency_ms": elapsed,
        "evidence_id": payload["data"]["evidence"]["id"],
        "state": payload["data"]["session"]["state"],
    })

    # 7. 固定快照
    payload, elapsed = must_ok(
        "pin_snapshot",
        request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/snapshot", case_data["snapshot_req"], logger=logger)
    )
    steps.append({
        "step": "pin_snapshot",
        "latency_ms": elapsed,
        "snapshot_id": payload["data"]["snapshot"]["id"],
        "state": payload["data"]["session"]["state"],
    })

    # 8. 执行评估
    payload, elapsed = must_ok(
        "evaluate",
        request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evaluate", logger=logger)
    )
    evaluation = payload["data"]["evaluation"]
    evaluator_mode, backend_mode, secure_execution = validate_evaluation_for_mode(evaluation, mode)

    evaluate_step = {
        "step": "evaluate",
        "latency_ms": elapsed,
        "evaluation_id": evaluation["id"],
        "decision": evaluation["decision"],
        "reason": evaluation.get("reason"),
        "evaluator_mode": evaluator_mode,
        "backend_mode": backend_mode,
        "state": payload["data"]["session"].get("state"),
    }
    evaluate_step.update(extract_secure_execution_brief(secure_execution))
    steps.append(evaluate_step)

    # 9. 生成工件
    # 这里假设 deny 也允许生成 artifact。若你的实现不是这样，可把这里调整成“有条件调用”。
    payload, elapsed = must_ok(
        "seal_artifact",
        request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/artifact", logger=logger)
    )
    artifact = payload["data"].get("artifact")
    final_session = payload["data"].get("session")

    validate_final_outcome(scenario, evaluation, artifact, final_session)

    steps.append({
        "step": "seal_artifact",
        "latency_ms": elapsed,
        "artifact_id": artifact.get("id") if artifact else None,
        "decision": artifact.get("authorization_decision") if artifact else None,
        "state": final_session.get("state") if final_session else None,
    })

    # 10. 拉取审计包
    payload, elapsed = must_ok(
        "get_audit_bundle",
        request_json("GET", f"{base_url}/api/v1/sessions/{session_id}/audit", logger=logger)
    )
    audit_bundle = payload["data"]
    events = audit_bundle.get("events", [])
    steps.append({
        "step": "get_audit_bundle",
        "latency_ms": elapsed,
        "event_count": len(events),
    })

    total_latency_ms = sum(step["latency_ms"] for step in steps)

    result = {
        "mode": mode,
        "scenario": scenario,
        "round": round_idx,
        "expected_decision": case_data["expected_decision"],
        "final_decision": evaluation["decision"],
        "total_latency_ms": total_latency_ms,
        "policy_id": policy_id,
        "plan_id": plan_id,
        "session_id": session_id,
        "artifact_id": artifact.get("id") if artifact else None,
        "final_session_state": final_session.get("state") if final_session else None,
        "event_count": len(events),
        "steps": steps,
        "evaluation": {
            "id": evaluation["id"],
            "decision": evaluation["decision"],
            "reason": evaluation.get("reason"),
            "evaluator_mode": evaluator_mode,
            "backend_mode": backend_mode,
            "secure_execution": secure_execution,
        },
    }

    logger.section(f"SCENARIO END mode={mode} scenario={scenario} round={round_idx}")
    logger.write(json_dumps_safe(result))
    return result


def summarize_results(results: List[dict]) -> None:
    """在终端打印摘要。"""
    print("\n=== GovAuth 统一流程测试摘要 ===")

    if not results:
        print("没有可展示的结果。")
        return

    by_group: Dict[str, List[dict]] = {}
    for item in results:
        key = f"{item['mode']}::{item['scenario']}"
        by_group.setdefault(key, []).append(item)

    for key, group in by_group.items():
        total_list = [x["total_latency_ms"] for x in group]
        final_decisions = [x["final_decision"] for x in group]
        backend_modes = [x["evaluation"]["backend_mode"] for x in group]

        print(f"\n[{key}]")
        print(f"- 轮数: {len(group)}")
        print(f"- decision: {final_decisions}")
        print(f"- backend_mode: {backend_modes}")
        print(f"- avg_total_latency_ms: {statistics.mean(total_list):.3f}")
        print(f"- min_total_latency_ms: {min(total_list):.3f}")
        print(f"- max_total_latency_ms: {max(total_list):.3f}")

        # 顺带重点看 evaluate 的平均耗时
        eval_latencies = []
        for item in group:
            for step in item["steps"]:
                if step["step"] == "evaluate":
                    eval_latencies.append(step["latency_ms"])
                    break
        if eval_latencies:
            print(f"- avg_evaluate_latency_ms: {statistics.mean(eval_latencies):.3f}")


def parse_csv_arg(text: str) -> List[str]:
    """把 a,b,c 这样的参数拆成列表。"""
    return [x.strip() for x in text.split(",") if x.strip()]


def main():
    parser = argparse.ArgumentParser(description="GovAuth unified policy flow matrix runner.")
    parser.add_argument("--base-url", default="http://localhost:8080", help="服务基地址")
    parser.add_argument("--modes", default="plain,mock,real", help="模式列表：plain,mock,real")
    parser.add_argument("--scenarios", default="happy,deny", help="场景列表：happy,deny")
    parser.add_argument("--rounds", type=int, default=1, help="每个 mode+scenario 跑几轮，默认 1")
    parser.add_argument("--startup-timeout-sec", type=int, default=30, help="服务启动等待时间，默认 30 秒")
    parser.add_argument("--output", default="scripts/policy_flow_matrix_result.json", help="结果输出路径")
    parser.add_argument("--log-dir", default="scripts/logs", help="日志目录")
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    log_dir = Path(args.log_dir)

    modes = parse_csv_arg(args.modes)
    scenarios = parse_csv_arg(args.scenarios)

    valid_modes = {"plain", "mock", "real"}
    valid_scenarios = {"happy", "deny"}

    for mode in modes:
        if mode not in valid_modes:
            raise StepFailure(f"不支持的 mode：{mode}，当前只支持 {sorted(valid_modes)}")

    for scenario in scenarios:
        if scenario not in valid_scenarios:
            raise StepFailure(f"不支持的 scenario：{scenario}，当前只支持 {sorted(valid_scenarios)}")

    all_results: List[dict] = []

    for mode in modes:
        logger = RunLogger(log_dir, prefix=f"matrix_{mode}")
        proc: Optional[subprocess.Popen] = None

        try:
            proc = start_server(root_dir, mode, args.base_url, logger, args.startup_timeout_sec)

            # 每个 mode 只启动一次 server，然后连续跑多个 scenario / rounds
            for scenario in scenarios:
                for round_idx in range(1, args.rounds + 1):
                    result = run_one_scenario(
                        base_url=args.base_url,
                        mode=mode,
                        scenario=scenario,
                        round_idx=round_idx,
                        logger=logger,
                    )
                    all_results.append(result)

                    print(
                        f"[OK] mode={mode:<5} scenario={scenario:<5} round={round_idx} "
                        f"decision={result['final_decision']:<5} total={result['total_latency_ms']:.3f} ms"
                    )

        finally:
            stop_server(proc, logger)

    summarize_results(all_results)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"results": all_results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n详细结果已写入: {output_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FAILED] {e}", file=sys.stderr)
        sys.exit(1)