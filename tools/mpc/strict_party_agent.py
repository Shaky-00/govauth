#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
strict_party_agent.py

本地 party agent 包装器。
职责：
1. 读取 role / task / private_input / result 等参数；
2. 将参数通过环境变量传给真正的 MPyC 程序 strict_mpyc_party.py；
3. 以独立进程身份参与 MPC。

改造目标：
- 默认静默运行，不往控制台刷屏；
- 只有失败时才把 stderr 冒出来；
- 不再要求单独 trace-file。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROLE_TO_INDEX = {
    "requester": 0,
    "provider": 1,
    "authority": 2,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=["requester", "provider", "authority"])
    parser.add_argument("--task", required=True)
    parser.add_argument("--private-input", required=True)
    parser.add_argument("--result-file", required=True)
    parser.add_argument("--party-count", type=int, default=3)
    parser.add_argument("--base-port", type=int, default=11500)
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    mpyc_script = script_dir / "strict_mpyc_party.py"

    env = os.environ.copy()
    env["GOVAUTH_MPC_ROLE"] = args.role
    env["GOVAUTH_MPC_TASK"] = args.task
    env["GOVAUTH_MPC_PRIVATE_INPUT"] = args.private_input
    env["GOVAUTH_MPC_RESULT"] = args.result_file

    cmd = [
        args.python_bin,
        str(mpyc_script),
        "-M",
        str(args.party_count),
        "-I",
        str(ROLE_TO_INDEX[args.role]),
        "-B",
        str(args.base_port),
        "--no-log",
    ]

    if args.quiet:
        completed = subprocess.run(
            cmd,
            check=False,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            sys.stderr.write(
                f"[strict-party-agent] role={args.role} failed\n{completed.stderr}\n"
            )
            raise SystemExit(completed.returncode)
        return

    subprocess.run(cmd, check=True, env=env)


if __name__ == "__main__":
    main()