#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
这个脚本用于自动执行 govauth 的 happy path，并测量每一步接口的耗时。
设计目标：
1. 不依赖第三方 Python 包，仅使用标准库。
2. 可执行多轮，输出单步耗时、总耗时、最终决策与事件数。
3. 将完整结果保存为 JSON，便于后续写实验或做截图。
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


def run_once(base_url: str):
    """执行一轮完整 happy path，返回原始结果和计时信息。"""
    steps = []

    # 1. 创建策略。
    policy_req = {
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
            "description": "允许满足科研用途与部门约束的请求访问活跃数据资源",
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
        "requester": "alice",
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

    # 6. 提交证据。
    evidence_req = {
        "payload": {
            "role": "researcher",
            "department": "lab-a",
            "purpose": "study",
            "holder": "did:example:alice",
            "credential_id": "vc-001",
        }
    }
    payload, elapsed = must_ok("admit_evidence", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evidence", evidence_req))
    steps.append({
        "step": "admit_evidence",
        "latency_ms": elapsed,
        "evidence_id": payload["data"]["evidence"]["id"],
        "state": payload["data"]["session"]["state"],
    })

    # 7. 固定快照。
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

    # 8. 执行评估。
    payload, elapsed = must_ok("evaluate", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evaluate"))
    evaluation = payload["data"]["evaluation"]
    steps.append({
        "step": "evaluate",
        "latency_ms": elapsed,
        "evaluation_id": evaluation["id"],
        "decision": evaluation["decision"],
        "state": payload["data"]["session"]["state"],
    })

    # 9. 生成工件并完成执行。
    payload, elapsed = must_ok("seal_artifact", request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/artifact"))
    artifact = payload["data"]["artifact"]
    final_session = payload["data"]["session"]
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
    steps.append({
        "step": "get_audit_bundle",
        "latency_ms": elapsed,
        "event_count": len(audit_bundle.get("events", [])),
    })

    total_ms = sum(step["latency_ms"] for step in steps)
    return {
        "steps": steps,
        "total_latency_ms": total_ms,
        "final_decision": artifact["authorization_decision"],
        "final_session_state": final_session["state"],
        "artifact_id": artifact["id"],
        "policy_id": policy_id,
        "plan_id": plan_id,
        "session_id": session_id,
        "event_count": len(audit_bundle.get("events", [])),
    }


def print_summary(runs):
    """打印简洁的统计摘要。"""
    print("\n=== Happy Path 统计摘要 ===")
    totals = [run["total_latency_ms"] for run in runs]
    print(f"执行轮数: {len(runs)}")
    print(f"总耗时均值: {statistics.mean(totals):.3f} ms")
    print(f"总耗时最小值: {min(totals):.3f} ms")
    print(f"总耗时最大值: {max(totals):.3f} ms")

    # 汇总每一步平均耗时。
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
    print(f"- final_decision: {last['final_decision']}")
    print(f"- final_session_state: {last['final_session_state']}")
    print(f"- event_count: {last['event_count']}")
    print(f"- artifact_id: {last['artifact_id']}")


def main():
    parser = argparse.ArgumentParser(description="Run govauth happy path and collect latency metrics.")
    parser.add_argument("--base-url", default="http://localhost:8080", help="服务基地址，默认 http://localhost:8080")
    parser.add_argument("--rounds", type=int, default=3, help="执行轮数，默认 3")
    parser.add_argument("--output", default="scripts/happy_path_result.json", help="结果输出路径")
    args = parser.parse_args()

    runs = []
    for idx in range(args.rounds):
        run = run_once(args.base_url)
        runs.append(run)
        print(f"第 {idx + 1} 轮完成：decision={run['final_decision']} total={run['total_latency_ms']:.3f} ms")

    print_summary(runs)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"runs": runs}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n详细结果已写入: {output_path}")


if __name__ == "__main__":
    main()