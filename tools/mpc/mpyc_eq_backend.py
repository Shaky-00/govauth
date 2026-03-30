#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GovAuth 最小真实 MPC 后端（MPyC 版本）

说明：
1. 该脚本由 Go 侧 RealMPCBackend 拉起；
2. Go 会通过环境变量传入：
   - GOVAUTH_MPC_TASK
   - GOVAUTH_MPC_INPUT
   - GOVAUTH_MPC_RESULT
   - GOVAUTH_MPC_TRACE
   - GOVAUTH_MPC_ROLE
3. 当前支持的操作：
   - eq
   - neq
   - gt
   - gte
   - lt
   - lte
4. 当前是 demo-grade 后端，目标是接通“真实多进程 MPC 执行链”，
   不追求工业级完备性。
"""

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List

from mpyc.runtime import mpc


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def append_trace(trace_path: str, message: str) -> None:
    if not trace_path:
        return
    Path(trace_path).parent.mkdir(parents=True, exist_ok=True)
    with open(trace_path, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def normalize_bool(v: Any) -> bool:
    # MPyC 输出后可能是 int / bool 等，这里统一规整为 Python bool。
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    return bool(v)


def secret_compare(op: str, actual, expected):
    """
    对安全值 actual 和公开常量 expected 执行比较。
    这里 expected 直接作为公开常量注入电路即可。
    """
    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "gt":
        return actual > expected
    if op == "gte":
        return actual >= expected
    if op == "lt":
        return actual < expected
    if op == "lte":
        return actual <= expected

    raise ValueError(f"unsupported op: {op}")


async def main() -> None:
    task_path = os.getenv("GOVAUTH_MPC_TASK", "").strip()
    input_path = os.getenv("GOVAUTH_MPC_INPUT", "").strip()
    result_path = os.getenv("GOVAUTH_MPC_RESULT", "").strip()
    trace_path = os.getenv("GOVAUTH_MPC_TRACE", "").strip()
    role = os.getenv("GOVAUTH_MPC_ROLE", "").strip()

    if not task_path:
        raise RuntimeError("missing GOVAUTH_MPC_TASK")
    if not input_path:
        raise RuntimeError("missing GOVAUTH_MPC_INPUT")
    if not result_path:
        raise RuntimeError("missing GOVAUTH_MPC_RESULT")

    task_doc = load_json(task_path)
    input_doc = load_json(input_path)

    bit_length = int(task_doc.get("bit_length", 61))
    secint = mpc.SecInt(bit_length)

    local_party_index = int(input_doc["party_index"])
    local_inputs = [int(x) for x in input_doc.get("inputs", [])]
    clauses = task_doc.get("clauses", [])

    append_trace(trace_path, f"role={role} local_party_index={local_party_index}")
    append_trace(trace_path, f"loaded {len(clauses)} clauses and {len(local_inputs)} local inputs")

    await mpc.start()

    try:
        if mpc.pid != local_party_index:
            append_trace(
                trace_path,
                f"warning: MPyC runtime pid={mpc.pid} differs from input party_index={local_party_index}",
            )

        secure_results = []

        for idx, clause in enumerate(clauses):
            owner_index = int(clause["owner_index"])
            op = str(clause["op"]).strip().lower()
            expected_value = int(clause["expected_value"])

            # 关键点：
            # 所有 party 都要对同一个 sender 发起 mpc.input() 调用，
            # 只有 sender 对应 party 的本地值会被真正作为输入使用。
            local_value = 0
            if idx < len(local_inputs):
                local_value = int(local_inputs[idx])

            secret_actual = mpc.input(secint(local_value), senders=owner_index)

            # 某些 MPyC 版本对单 sender 也可能返回列表，这里做兼容处理。
            if isinstance(secret_actual, list):
                if len(secret_actual) != 1:
                    raise RuntimeError(f"unexpected secret_actual length: {len(secret_actual)}")
                secret_actual = secret_actual[0]

            secret_expected = secint(expected_value)
            secure_pass = secret_compare(op, secret_actual, secret_expected)
            secure_results.append(secure_pass)

            append_trace(
                trace_path,
                f"clause[{idx}] owner_index={owner_index} op={op} local_value={local_value} expected={expected_value}",
            )

        opened_results = await mpc.output(secure_results)
        opened_results = [normalize_bool(v) for v in opened_results]
        decision = "ALLOW" if all(opened_results) else "DENY"

        transcript = [
            f"mpyc runtime pid={mpc.pid}",
            f"mpyc evaluated {len(clauses)} clauses",
            f"mpyc final decision={decision}",
        ]

        clause_results = []
        for idx, clause in enumerate(clauses):
            clause_results.append(
                {
                    "clause_id": clause["clause_id"],
                    "owner": clause["owner"],
                    "source": clause["source"],
                    "field": clause["field"],
                    "op": clause["op"],
                    "passed": opened_results[idx],
                }
            )

        # 约定由 0 号 party 写最终结果文件，避免多方同时写入。
        if mpc.pid == 0:
            Path(result_path).parent.mkdir(parents=True, exist_ok=True)
            result_doc = {
                "request_id": task_doc["request_id"],
                "session_id": task_doc["session_id"],
                "decision": decision,
                "clause_results": clause_results,
                "transcript": transcript,
            }
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(result_doc, f, ensure_ascii=False, indent=2)

            append_trace(trace_path, f"party pid={mpc.pid} wrote result file: {result_path}")
        else:
            append_trace(trace_path, f"party pid={mpc.pid} finished without writing result file")

    finally:
        await mpc.shutdown()


if __name__ == "__main__":
    try:
        mpc.run(main())
    except Exception as exc:
        trace_path = os.getenv("GOVAUTH_MPC_TRACE", "").strip()
        append_trace(trace_path, f"fatal error: {exc}")
        append_trace(trace_path, traceback.format_exc())
        raise