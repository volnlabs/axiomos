#!/usr/bin/env python3
"""Run explicit v0.4 behavior lifecycle commands with named marker context."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import time

STAGES = ("load", "verify", "admit", "attach", "active")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--behavior", required=True)
    parser.add_argument("--sample-id", required=True, type=int)
    for stage in STAGES:
        parser.add_argument(f"--{stage}", required=True, help=f"command that completes {stage}")
    args = parser.parse_args()
    if args.sample_id < 1:
        parser.error("--sample-id must be positive")
    for stage in STAGES:
        command = shlex.split(getattr(args, stage))
        if not command:
            parser.error(f"--{stage} must name a command")
        result = subprocess.run(command, check=False)
        if result.returncode:
            print(f"V04_BENCH_FAIL behavior={args.behavior} stage={stage} code={result.returncode}", file=sys.stderr)
            return result.returncode
        print(f"V04_BEHAVIOR sample_id={args.sample_id} behavior={args.behavior} stage={stage} ts_ns={time.monotonic_ns()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
