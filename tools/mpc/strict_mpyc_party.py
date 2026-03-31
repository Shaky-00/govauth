#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
strict_mpyc_party.py

真正执行 MPyC 的三方协议程序。
它读取：
1. GovAuth 发布的 public task spec（不含私有明文）
2. 当前 party 自己的本地 private input 文件

然后直接在 MPyC 中完成 secure evaluation，并由 party 0 输出最小结果文件。

改造目标：
- 不打印大量重复 trace；
- 保留结构化 timing 数据；
- result.json 足够用于实验和画图；
- 不把原始私有值写入任何输出文件。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from mpyc.runtime import mpc


ROLE_TO_INDEX = {
    "requester": 0,
    "provider": 1,
    "authority": 2,
}


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def elapsed_ms(start_ms: float) -> float:
    return round(now_ms() - start_ms, 3)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: Dict[str, Any]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def stable_sha256(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def encode_eq_hash(raw: Any) -> int:
    text = str(raw)
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    x = int.from_bytes(digest[:8], "big")
    x &= (1 << 61) - 1
    return x or 1


def encode_value(expected_encoding: str, raw: Any) -> int:
    if expected_encoding == "eq_hash":
        return encode_eq_hash(raw)
    if expected_encoding == "int_compare":
        return int(raw)
    raise ValueError(f"unsupported encoding: {expected_encoding}")


def private_value_for_clause(private_inputs: Dict[str, Any], clause: Dict[str, Any]) -> Any:
    source = clause["source"]
    field = clause["field"]
    source_map = private_inputs.get(source, {})
    if field not in source_map:
        raise KeyError(f"missing private value for {source}.{field}")
    return source_map[field]


def compute_pass_expr(secint, secret_value, clause: Dict[str, Any]):
    expected_public = encode_value(clause["expected_encoding"], clause["expected_value"])
    op = clause["op"]

    if op == "eq":
        return secret_value == expected_public
    if op == "neq":
        return secint(1) - (secret_value == expected_public)
    if op == "gt":
        return secret_value > expected_public
    if op == "gte":
        return secret_value >= expected_public
    if op == "lt":
        return secret_value < expected_public
    if op == "lte":
        return secret_value <= expected_public

    raise ValueError(f"unsupported op: {op}")


async def main() -> None:
    total_start = now_ms()

    role = os.environ["GOVAUTH_MPC_ROLE"].strip().lower()
    task_path = os.environ["GOVAUTH_MPC_TASK"]
    private_input_path = os.environ["GOVAUTH_MPC_PRIVATE_INPUT"]
    result_path = os.environ["GOVAUTH_MPC_RESULT"]

    task = load_json(task_path)
    private_inputs = load_json(private_input_path)

    secint = mpc.SecInt(61)
    clause_results: List[Dict[str, Any]] = []
    secret_pass_exprs = []

    timings: Dict[str, float] = {}

    start = now_ms()
    await mpc.start()
    timings["mpc_start_ms"] = elapsed_ms(start)

    start = now_ms()
    for clause in task["clauses"]:
        owner_index = int(clause["owner_index"])

        local_value = 0
        if mpc.pid == owner_index:
            local_raw = private_value_for_clause(private_inputs, clause)
            local_value = encode_value(clause["expected_encoding"], local_raw)

        shared_secret = mpc.input(secint(local_value), senders=owner_index)
        pass_expr = compute_pass_expr(secint, shared_secret, clause)
        secret_pass_exprs.append(pass_expr)

        passed_public = bool(await mpc.output(pass_expr))
        clause_results.append(
            {
                "clause_id": clause["clause_id"],
                "owner": clause["owner"],
                "source": clause["source"],
                "field": clause["field"],
                "op": clause["op"],
                "passed": passed_public,
            }
        )
    timings["clause_eval_ms"] = elapsed_ms(start)

    start = now_ms()
    overall = secint(1)
    for expr in secret_pass_exprs:
        overall = overall * expr
    decision_public = int(await mpc.output(overall))
    decision = "ALLOW" if decision_public == 1 else "DENY"
    timings["decision_reduce_ms"] = elapsed_ms(start)

    minimal_transcript = [
        f"task_id={task['id']}",
        f"request_id={task['request_id']}",
        f"session_id={task['session_id']}",
        f"plan_id={task['plan_id']}",
        f"party_count={len(task['ownership_partition'])}",
        f"clause_count={len(task['clauses'])}",
        f"decision={decision}",
    ]

    transcript_digest = stable_sha256(
        {
            "task_id": task["id"],
            "request_id": task["request_id"],
            "session_id": task["session_id"],
            "plan_id": task["plan_id"],
            "decision": decision,
            "clause_results": clause_results,
            "transcript": minimal_transcript,
        }
    )
    result_digest = stable_sha256(
        {
            "task_id": task["id"],
            "request_id": task["request_id"],
            "session_id": task["session_id"],
            "plan_id": task["plan_id"],
            "decision": decision,
            "clause_results": clause_results,
            "transcript_digest": transcript_digest,
        }
    )
    proof_receipt = stable_sha256(
        {
            "task_manifest_digest": task["manifest_digest"],
            "result_digest": result_digest,
        }
    )

    timings["total_party_ms"] = elapsed_ms(total_start)

    if mpc.pid == 0:
        result_doc = {
            "task_id": task["id"],
            "request_id": task["request_id"],
            "session_id": task["session_id"],
            "plan_id": task["plan_id"],
            "decision": decision,
            "clause_count": len(task["clauses"]),
            "clause_results": clause_results,
            "transcript_digest": transcript_digest,
            "result_digest": result_digest,
            "proof_receipt": proof_receipt,
            "metadata": {
                "runtime": "mpyc",
                "party_count": 3,
                "owner_partition": task["ownership_partition"],
                "timings_ms": timings,
            },
        }
        write_json(result_path, result_doc)

    start = now_ms()
    await mpc.shutdown()
    timings["mpc_shutdown_ms"] = elapsed_ms(start)


if __name__ == "__main__":
    mpc.run(main())