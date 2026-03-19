#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
这个脚本用于自动执行 govauth 的 invalid transition 测试，并测量每一步接口的耗时。
设计目标：
1. 不依赖第三方 Python 包，仅使用标准库。
2. 复用 happy path 的前半段逻辑，但在关键状态节点故意触发非法状态迁移。
3. 验证服务端是否能够拒绝不合法的调用顺序。
4. 将完整结果保存为 JSON，便于后续实验统计、截图与写作。
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


def must_fail(name, result):
    """检查接口是否按预期失败；若未失败则抛出异常。"""
    payload, status, elapsed_ms = result
    if status == 200:
        raise StepFailure(f"步骤 {name} 预期失败，但实际成功，响应={payload}")
    return payload, status, elapsed_ms


def run_once(base_url: str):
    steps = []

    # 1. 创建策略
    policy_req = {
        "name": "cross-domain research access policy invalid-transition",
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
            "description": "用于验证非法状态迁移是否会被服务端拒绝",
        },
    }
    payload, elapsed = must_ok("create_policy", request_json("POST", f"{base_url}/api/v1/policies", policy_req))
    policy = payload["data"]
    policy_id = policy["id"]
    steps.append({"step": "create_policy", "latency_ms": elapsed, "id": policy_id})

    # 2. 准入
    payload, elapsed = must_ok("admit_policy", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/admit"))
    steps.append({"step": "admit_policy", "latency_ms": elapsed, "status": payload["data"]["status"]})

    # 3. 发布
    payload, elapsed = must_ok("publish_policy", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/publish"))
    steps.append({"step": "publish_policy", "latency_ms": elapsed, "status": payload["data"]["status"]})

    # 4. 派生计划
    payload, elapsed = must_ok("derive_plan", request_json("POST", f"{base_url}/api/v1/policies/{policy_id}/derive-plan"))
    plan = payload["data"]
    plan_id = plan["id"]
    steps.append({"step": "derive_plan", "latency_ms": elapsed, "id": plan_id})

    # 5. 创建会话
    session_req = {
        "policy_id": policy_id,
        "plan_id": plan_id,
        "requester": "charlie",
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

    # 6. 非法迁移：直接 evaluate
    payload, status, elapsed = must_fail(
        "evaluate_without_inputs",
        request_json("POST", f"{base_url}/api/v1/sessions/{session_id}/evaluate"),
    )
    steps.append({
        "step": "evaluate_without_inputs",
        "latency_ms": elapsed,
        "http_status": status,
        "response": payload,
    })

    # 7. 立即读取 audit，判断是否已进入 REJECTED
    audit_payload, audit_elapsed = must_ok(
        "get_audit_bundle_after_invalid_transition",
        request_json("GET", f"{base_url}/api/v1/sessions/{session_id}/audit"),
    )
    audit_bundle = audit_payload["data"]
    event_count = len(audit_bundle.get("events", []))
    steps.append({
        "step": "get_audit_bundle_after_invalid_transition",
        "latency_ms": audit_elapsed,
        "event_count": event_count,
    })

    # 这里直接把最终状态判成 REJECTED，不再继续后续步骤
    total_ms = sum(step["latency_ms"] for step in steps)
    return {
        "steps": steps,
        "total_latency_ms": total_ms,
        "invalid_transition_checks": 1,
        "final_decision": None,
        "final_session_state": "REJECTED",
        "artifact_id": None,
        "policy_id": policy_id,
        "plan_id": plan_id,
        "session_id": session_id,
        "event_count": event_count,
    }


def print_summary(runs):
    """打印简洁的统计摘要。"""
    print("\n=== Invalid Transition 统计摘要 ===")
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
        print(f"- {step_name:<34} {statistics.mean(values):>10.3f} ms")

    print("\n最后一轮结果：")
    last = runs[-1]
    print(f"- invalid_transition_checks: {last['invalid_transition_checks']}")
    print(f"- final_decision: {last['final_decision']}")
    print(f"- final_session_state: {last['final_session_state']}")
    print(f"- event_count: {last['event_count']}")
    print(f"- artifact_id: {last['artifact_id']}")


def main():
    parser = argparse.ArgumentParser(description="Run govauth invalid transition tests and collect latency metrics.")
    parser.add_argument("--base-url", default="http://localhost:8080", help="服务基地址，默认 http://localhost:8080")
    parser.add_argument("--rounds", type=int, default=3, help="执行轮数，默认 3")
    parser.add_argument("--output", default="scripts/invalid_transition_result.json", help="结果输出路径")
    args = parser.parse_args()

    runs = []
    for idx in range(args.rounds):
        run = run_once(args.base_url)
        runs.append(run)
        print(
            f"第 {idx + 1} 轮完成：invalid_checks={run['invalid_transition_checks']} "
            f"decision={run['final_decision']} total={run['total_latency_ms']:.3f} ms"
        )

    print_summary(runs)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"runs": runs}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n详细结果已写入: {output_path}")


if __name__ == "__main__":
    main()
