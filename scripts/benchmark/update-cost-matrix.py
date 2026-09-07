#!/usr/bin/env python3
"""Run the hosted update-cost test matrix from one prebuilt release test binary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess

PROTOCOLS = ("atomic", "guarded")
HOLDS_US = (0, 10, 100, 500, 900, 1100)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1000)
    parser.add_argument("--dispatch-cpu", type=int, default=12)
    parser.add_argument("--update-cpu", type=int, default=14)
    args = parser.parse_args()
    executable = args.executable.resolve()
    if not executable.is_file():
        parser.error(f"measurement executable does not exist: {executable}")
    if args.attempts < 1 or args.runs < 1 or args.warmup < 0:
        parser.error("attempts/runs must be positive and warmup must be nonnegative")
    allowed = os.sched_getaffinity(0)
    cpus = {args.dispatch_cpu, args.update_cpu}
    if len(cpus) != 2 or not cpus <= allowed:
        parser.error(f"distinct dispatch/update CPUs must be in allowed set {sorted(allowed)}")
    def topology(cpu: int) -> tuple[str, str]:
        root = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        try:
            return ((root / "physical_package_id").read_text().strip(),
                    (root / "core_id").read_text().strip())
        except OSError as error:
            parser.error(f"cannot read topology for CPU {cpu}: {error}")
    if topology(args.dispatch_cpu) == topology(args.update_cpu):
        parser.error("dispatch and update CPUs must be different physical cores")

    child_args = [str(executable), "measures_update_cost", "--exact", "--ignored",
                  "--nocapture", "--test-threads=1"]
    for run in range(args.runs):
        holds = HOLDS_US[run % len(HOLDS_US):] + HOLDS_US[:run % len(HOLDS_US)]
        for hold_us in holds:
            protocols = PROTOCOLS if (run + hold_us) % 2 == 0 else tuple(reversed(PROTOCOLS))
            for protocol in protocols:
                env = os.environ.copy()
                env.update({
                    "AXIOM_UPDATE_COST_PROTOCOL": protocol,
                    "AXIOM_UPDATE_COST_HOLD_US": str(hold_us),
                    "AXIOM_UPDATE_COST_RUN": str(run),
                    "AXIOM_UPDATE_COST_ATTEMPTS": str(args.attempts),
                    "AXIOM_UPDATE_COST_WARMUP": str(args.warmup),
                    "AXIOM_UPDATE_COST_DISPATCH_CPU": str(args.dispatch_cpu),
                    "AXIOM_UPDATE_COST_UPDATE_CPU": str(args.update_cpu),
                })
                print(f"UPDATE_COST_RUN protocol={protocol} hold_us={hold_us} run={run}", flush=True)
                code = subprocess.run(child_args, env=env).returncode
                if code:
                    return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
