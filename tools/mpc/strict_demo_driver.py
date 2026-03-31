#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
strict_demo_driver.py

增强版 strict MPC 演示驱动器：
1. 创建 policy / admit / publish / derive plan
2. 创建 session（只绑定 public context / digest / ref）
3. 绑定 requester evidence digest
4. 绑定 provider snapshot digest
5. 请求 GovAuth 发布 strict MPC task spec
6. 启动 3 个本地 party agents
7. 读取 result.json 并提交最小 receipt
8. seal artifact
9. 拉取 audit bundle

增强点：
- 终端增加 emoji 风格阶段输出，便于演示和截图；
- summary.json 增加策略复杂度 / 属性数量 / 结果统计；
- metrics.json 增加分组时延，便于后续画图；
- 控制台明确展示：
  - 当前走到哪一步；
  - 当前策略长什么样；
  - GovAuth 能看到什么 / 看不到什么；
  - 最终结果是什么。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def elapsed_ms(start_ms: float) -> float:
    return round(now_ms() - start_ms, 3)


def http_json(method: str, url: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"{method} {url} failed: {e.code} {text}") from e


def timed_http_json(
    method: str,
    url: str,
    metrics: Dict[str, float],
    metric_name: str,
    body: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    start = now_ms()
    resp = http_json(method, url, body)
    metrics[metric_name] = elapsed_ms(start)
    return resp


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def step(msg: str) -> None:
    print(msg, flush=True)


def demo_policy() -> Dict[str, Any]:
    return {
        "name": "strict-mpc-demo-policy",
        "content": {
            "description": "Strict MPC demo policy: three parties each own one private input.",
            "clauses": [
                {
                    "source": "evidence",
                    "field": "department",
                    "op": "eq",
                    "value": "research",
                    "owner": "requester",
                },
                {
                    "source": "snapshot",
                    "field": "data_tier",
                    "op": "lte",
                    "value": "2",
                    "owner": "provider",
                },
                {
                    "source": "context",
                    "field": "risk_score",
                    "op": "lt",
                    "value": "50",
                    "owner": "authority",
                },
            ],
        },
    }


def format_clause(clause: Dict[str, Any]) -> str:
    return f"{clause['source']}.{clause['field']} {clause['op']} {clause['value']} (owner={clause['owner']})"


def collect_policy_stats(policy_content: Dict[str, Any]) -> Dict[str, Any]:
    clauses = policy_content.get("clauses", [])

    owners = sorted({c["owner"] for c in clauses})
    sources = sorted({c["source"] for c in clauses})
    ops = sorted({c["op"] for c in clauses})
    fields = sorted({f"{c['source']}.{c['field']}" for c in clauses})

    by_owner: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    by_op: Dict[str, int] = {}
    comparison_profile = {"eq_hash": 0, "int_compare": 0}

    for c in clauses:
        by_owner[c["owner"]] = by_owner.get(c["owner"], 0) + 1
        by_source[c["source"]] = by_source.get(c["source"], 0) + 1
        by_op[c["op"]] = by_op.get(c["op"], 0) + 1

        if c["op"] in {"eq", "neq"}:
            comparison_profile["eq_hash"] += 1
        else:
            comparison_profile["int_compare"] += 1

    return {
        "clause_count": len(clauses),
        "owner_count": len(owners),
        "source_count": len(sources),
        "op_count": len(ops),
        "owners": owners,
        "sources": sources,
        "ops": ops,
        "distinct_fields": len(fields),
        "attribute_paths": fields,
        "clauses_by_owner": by_owner,
        "clauses_by_source": by_source,
        "clauses_by_op": by_op,
        "comparison_profile": comparison_profile,
        # 给“复杂度”先留一个最小演示型指标，后续你可继续扩展
        "complexity_score": len(clauses) + len(fields) + len(ops),
    }


def collect_attribute_stats(policy_stats: Dict[str, Any]) -> Dict[str, Any]:
    by_owner = policy_stats.get("clauses_by_owner", {})
    return {
        "total_attributes": policy_stats.get("distinct_fields", 0),
        "requester_attributes": by_owner.get("requester", 0),
        "provider_attributes": by_owner.get("provider", 0),
        "authority_attributes": by_owner.get("authority", 0),
        "attribute_paths": policy_stats.get("attribute_paths", []),
    }


def collect_result_stats(result_doc: Dict[str, Any]) -> Dict[str, Any]:
    clause_results = result_doc.get("clause_results", [])
    passed = sum(1 for x in clause_results if x.get("passed"))
    failed = len(clause_results) - passed
    pass_rate = round(passed / len(clause_results), 3) if clause_results else 0.0

    failed_clauses = [
        f"{x['source']}.{x['field']} ({x['op']})"
        for x in clause_results
        if not x.get("passed")
    ]

    return {
        "decision": result_doc.get("decision"),
        "passed_clause_count": passed,
        "failed_clause_count": failed,
        "pass_rate": pass_rate,
        "failed_clauses": failed_clauses,
    }


def build_latency_groups(metrics: Dict[str, float]) -> Dict[str, float]:
    govauth_control_plane_ms = round(
        metrics.get("create_policy_ms", 0)
        + metrics.get("admit_policy_ms", 0)
        + metrics.get("publish_policy_ms", 0)
        + metrics.get("derive_plan_ms", 0)
        + metrics.get("create_session_ms", 0)
        + metrics.get("bind_evidence_ms", 0)
        + metrics.get("bind_snapshot_ms", 0)
        + metrics.get("prepare_task_ms", 0),
        3,
    )

    artifact_and_audit_ms = round(
        metrics.get("submit_receipt_ms", 0)
        + metrics.get("seal_artifact_ms", 0)
        + metrics.get("fetch_audit_ms", 0),
        3,
    )

    return {
        "govauth_control_plane_ms": govauth_control_plane_ms,
        "mpc_runtime_ms": round(metrics.get("mpc_runtime_ms", 0), 3),
        "artifact_and_audit_ms": artifact_and_audit_ms,
        "end_to_end_ms": round(sum(metrics.values()), 3),
    }


def run_agents(
    project_root: Path,
    work_dir: Path,
    task_path: Path,
    scenario_dir: Path,
    base_port: int,
    metrics: Dict[str, float],
) -> None:
    agent_script = project_root / "tools" / "mpc" / "strict_party_agent.py"
    result_file = work_dir / "result.json"
    error_log = work_dir / "agent_error.log"

    procs = []
    start = now_ms()

    for role in ["requester", "provider", "authority"]:
        private_input = scenario_dir / f"{role}_private.json"

        cmd = [
            sys.executable,
            str(agent_script),
            "--role",
            role,
            "--task",
            str(task_path),
            "--private-input",
            str(private_input),
            "--result-file",
            str(result_file),
            "--base-port",
            str(base_port),
            "--quiet",
        ]
        procs.append(
            subprocess.Popen(
                cmd,
                cwd=str(project_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        )

    stderr_list = []
    exit_codes = []
    for p in procs:
        _, stderr_text = p.communicate()
        exit_codes.append(p.returncode)
        if stderr_text and stderr_text.strip():
            stderr_list.append(stderr_text.strip())

    metrics["mpc_runtime_ms"] = elapsed_ms(start)

    if stderr_list:
        error_log.write_text("\n\n".join(stderr_list), encoding="utf-8")

    if any(code != 0 for code in exit_codes):
        raise RuntimeError(f"one or more party agents failed: {exit_codes}")


def build_summary(
    scenario: str,
    session_id: str,
    policy_id: str,
    plan_id: str,
    decision: str,
    work_dir: Path,
    metrics: Dict[str, float],
    result_doc: Dict[str, Any],
    policy_content: Dict[str, Any],
) -> Dict[str, Any]:
    policy_stats = collect_policy_stats(policy_content)
    attribute_stats = collect_attribute_stats(policy_stats)
    result_stats = collect_result_stats(result_doc)
    latency_groups = build_latency_groups(metrics)
    mpc_inner_timings = result_doc.get("metadata", {}).get("timings_ms", {})

    return {
        "scenario": scenario,
        "session_id": session_id,
        "policy_id": policy_id,
        "plan_id": plan_id,
        "decision": decision,
        "clause_count": result_doc.get("clause_count"),
        "transcript_digest": result_doc.get("transcript_digest"),
        "result_digest": result_doc.get("result_digest"),
        "proof_receipt": result_doc.get("proof_receipt"),
        "work_dir": str(work_dir),
        "policy_stats": policy_stats,
        "attribute_stats": attribute_stats,
        "result_stats": result_stats,
        "metrics_ms": metrics,
        "latency_groups_ms": latency_groups,
        "mpc_inner_timings_ms": mpc_inner_timings,
        "notes": {
            "govauth_sees_plaintext": False,
            "private_inputs_sent_to_govauth": False,
            "console_output_mode": "emoji_compact",
            "govauth_visible_only": [
                "policy",
                "plan",
                "session public context",
                "evidence digest/ref",
                "snapshot digest/ref",
                "authority digest/ref",
                "final decision",
                "transcript digest",
                "result digest",
                "proof receipt",
            ],
            "govauth_not_visible": [
                "evidence.department actual value",
                "snapshot.data_tier actual value",
                "context.risk_score actual value",
            ],
        },
    }


def print_policy_overview(policy_content: Dict[str, Any], policy_stats: Dict[str, Any]) -> None:
    step(
        "🧩 Policy profile: "
        f"clauses={policy_stats['clause_count']} | "
        f"attributes={policy_stats['distinct_fields']} | "
        f"owners={policy_stats['owners']} | "
        f"ops={policy_stats['ops']} | "
        f"complexity={policy_stats['complexity_score']}"
    )
    print("📐 Policy checks:", flush=True)
    for clause in policy_content.get("clauses", []):
        print(f"   - {format_clause(clause)}", flush=True)


def print_visibility_overview() -> None:
    print("👀 GovAuth can see:", flush=True)
    print("   - policy / plan / session public context", flush=True)
    print("   - requester evidence digest + reference", flush=True)
    print("   - provider snapshot digest + reference", flush=True)
    print("   - authority context digest + reference", flush=True)
    print("   - final decision + transcript digest + result digest", flush=True)
    print("🙈 GovAuth cannot see:", flush=True)
    print("   - evidence.department actual value", flush=True)
    print("   - snapshot.data_tier actual value", flush=True)
    print("   - context.risk_score actual value", flush=True)


def print_final_summary(summary: Dict[str, Any]) -> None:
    latency = summary["latency_groups_ms"]
    result_stats = summary["result_stats"]

    emoji = "✅" if summary["decision"] == "ALLOW" else "⛔"

    print(
        f"{emoji} FINAL DECISION: {summary['decision']} | "
        f"session={summary['session_id']} | plan={summary['plan_id']}",
        flush=True,
    )
    print(
        "📊 Result stats: "
        f"passed={result_stats['passed_clause_count']} | "
        f"failed={result_stats['failed_clause_count']} | "
        f"pass_rate={result_stats['pass_rate']}",
        flush=True,
    )
    if result_stats["failed_clauses"]:
        print("⚠️ Failed clauses:", flush=True)
        for item in result_stats["failed_clauses"]:
            print(f"   - {item}", flush=True)

    print(
        "⏱️ Latency: "
        f"control={latency['govauth_control_plane_ms']} ms | "
        f"mpc={latency['mpc_runtime_ms']} ms | "
        f"artifact+audit={latency['artifact_and_audit_ms']} ms | "
        f"end-to-end={latency['end_to_end_ms']} ms",
        flush=True,
    )
    print(f"📂 Output dir: {summary['work_dir']}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=["happy", "deny"])
    parser.add_argument("--base-url", default=os.environ.get("GOVAUTH_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--base-port", type=int, default=int(os.environ.get("MPC_BASE_PORT", "11500")))
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    scenario_dir = project_root / "demo" / "strict" / args.scenario
    work_dir = project_root / "tmp" / f"strict_{args.scenario}"

    ensure_clean_dir(work_dir)

    requester_file = scenario_dir / "requester_private.json"
    provider_file = scenario_dir / "provider_private.json"
    authority_file = scenario_dir / "authority_private.json"

    metrics: Dict[str, float] = {}
    policy_doc = demo_policy()
    policy_content = policy_doc["content"]
    policy_stats = collect_policy_stats(policy_content)

    step(f"🚀 Starting strict MPC demo: scenario={args.scenario}")
    print_policy_overview(policy_content, policy_stats)

    step("📘 [1/8] Creating policy...")
    create_policy_resp = timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/policies",
        metrics,
        "create_policy_ms",
        policy_doc,
    )
    policy = create_policy_resp["data"]
    policy_id = policy["id"]

    step("🛡️ [2/8] Admitting policy...")
    timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/policies/{policy_id}/admit",
        metrics,
        "admit_policy_ms",
    )

    step("📢 [3/8] Publishing policy...")
    timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/policies/{policy_id}/publish",
        metrics,
        "publish_policy_ms",
    )

    step("🪢 [4/8] Deriving enforcement plan...")
    derive_resp = timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/policies/{policy_id}/derive-plan",
        metrics,
        "derive_plan_ms",
    )
    plan = derive_resp["data"]
    plan_id = plan["id"]
    print(f"🧾 Plan ready: plan_id={plan_id} | clause_count={policy_stats['clause_count']}", flush=True)

    step("🔐 [5/8] Creating session and binding digests...")
    session_payload = {
        "policy_id": policy_id,
        "plan_id": plan_id,
        "requester": "alice",
        "resource_id": "dataset-001",
        "context": {
            "purpose": "analytics-demo",
            "authority_private_digest": file_sha256(authority_file),
            "authority_private_ref": f"local://{authority_file.as_posix()}",
        },
    }
    create_session_resp = timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/sessions",
        metrics,
        "create_session_ms",
        session_payload,
    )
    session = create_session_resp["data"]
    session_id = session["id"]

    evidence_payload = {
        "payload": {
            "private_digest": file_sha256(requester_file),
            "reference": f"local://{requester_file.as_posix()}",
            "public_meta": {
                "owner": "requester",
                "fields": ["evidence.department"],
            },
        }
    }
    timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/sessions/{session_id}/evidence",
        metrics,
        "bind_evidence_ms",
        evidence_payload,
    )

    snapshot_payload = {
        "payload": {
            "private_digest": file_sha256(provider_file),
            "reference": f"local://{provider_file.as_posix()}",
            "public_meta": {
                "owner": "provider",
                "fields": ["snapshot.data_tier"],
            },
        }
    }
    timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/sessions/{session_id}/snapshot",
        metrics,
        "bind_snapshot_ms",
        snapshot_payload,
    )
    print_visibility_overview()

    step("🤝 [6/8] Preparing strict MPC task...")
    task_resp = timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/sessions/{session_id}/evaluate",
        metrics,
        "prepare_task_ms",
    )
    task = task_resp["data"]["task_spec"]
    task_path = work_dir / "task.json"
    write_json(task_path, task)
    print(f"📦 Task ready: task_id={task['id']} | request_id={task['request_id']}", flush=True)

    step("⚙️ [7/8] Running 3-party MPyC...")
    print("👥 Parties: requester + provider + authority", flush=True)
    run_agents(project_root, work_dir, task_path, scenario_dir, args.base_port, metrics)

    result_path = work_dir / "result.json"
    if not result_path.exists():
        raise RuntimeError("strict MPC finished but result.json was not produced")
    result_doc = json.loads(result_path.read_text(encoding="utf-8"))

    step("📨 [8/8] Submitting MPC receipt, sealing artifact, fetching audit...")
    receipt = {
        "task_id": result_doc["task_id"],
        "request_id": result_doc["request_id"],
        "session_id": result_doc["session_id"],
        "plan_id": result_doc["plan_id"],
        "decision": result_doc["decision"],
        "clause_count": result_doc["clause_count"],
        "transcript_digest": result_doc["transcript_digest"],
        "result_digest": result_doc["result_digest"],
        "proof_receipt": result_doc["proof_receipt"],
        "metadata": result_doc.get("metadata", {}),
        "submitted_by": "strict_demo_driver",
    }
    submit_resp = timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/sessions/{session_id}/mpc-result",
        metrics,
        "submit_receipt_ms",
        receipt,
    )

    timed_http_json(
        "POST",
        f"{args.base_url}/api/v1/sessions/{session_id}/artifact",
        metrics,
        "seal_artifact_ms",
    )
    audit_resp = timed_http_json(
        "GET",
        f"{args.base_url}/api/v1/sessions/{session_id}/audit",
        metrics,
        "fetch_audit_ms",
    )

    decision = submit_resp["data"]["evaluation"]["decision"]

    summary = build_summary(
        scenario=args.scenario,
        session_id=session_id,
        policy_id=policy_id,
        plan_id=plan_id,
        decision=decision,
        work_dir=work_dir,
        metrics=metrics,
        result_doc=result_doc,
        policy_content=policy_content,
    )

    write_json(work_dir / "summary.json", summary)
    write_json(
        work_dir / "metrics.json",
        {
            "scenario": args.scenario,
            "metrics_ms": metrics,
            "latency_groups_ms": build_latency_groups(metrics),
            "policy_stats": summary["policy_stats"],
            "attribute_stats": summary["attribute_stats"],
            "result_stats": summary["result_stats"],
            "mpc_inner_timings_ms": summary["mpc_inner_timings_ms"],
        },
    )
    write_json(work_dir / "audit_bundle.json", audit_resp)

    print_final_summary(summary)


if __name__ == "__main__":
    main()