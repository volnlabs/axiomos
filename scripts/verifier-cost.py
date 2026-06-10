#!/usr/bin/env python3
"""Parse `AXIOM VERIFIER COST` markers from a serial/UART log into the
verifier-cost-vs-size dataset (Track B).

The kernel, built with `--features verifier-cost`, emits one line per BPF load:

    AXIOM VERIFIER COST prog_id=<u32> insns=<n> states=<states_explored> cycles=<cntvct_delta>

This script extracts those lines, writes a CSV, prints a summary table, and —
if matplotlib is available — saves a cost-vs-size plot overlaying the declared
budget T(n) = (h+1)*n from docs/verifier-fragment.md.

Usage:
    scripts/verifier-cost.py uart.clean.log [-o cost.csv] [--plot cost.png]
    cat uart.log | scripts/verifier-cost.py -

The cntvct frequency on the Pi5 is ~54 MHz; pass --cntfrq to convert cycles to
microseconds in the summary.
"""

import argparse
import csv
import re
import sys

MARKER = re.compile(
    r"AXIOM VERIFIER COST\s+"
    r"prog_id=(?P<prog_id>\d+)\s+"
    r"insns=(?P<insns>\d+)\s+"
    r"states=(?P<states>\d+)\s+"
    r"cycles=(?P<cycles>\d+)"
    r"(?:\s+wcet=(?P<wcet>\d+))?"
)

# Execution-cost marker emitted by the feature-gated BPF_BENCH_EXEC command.
EXEC_MARKER = re.compile(
    r"AXIOM EXEC COST\s+"
    r"prog_id=(?P<prog_id>\d+)\s+"
    r"insns=(?P<insns>\d+)\s+"
    r"runs=(?P<runs>\d+)\s+"
    r"cycles=(?P<cycles>\d+)"
)

# Shape labels printed by the verifier_bench driver: "<shape> n=<n> prog_id=<id>".
LABEL = re.compile(r"^(?P<shape>straight|memory|div|ktime|map|copy|ringbuf)\s+n=(?P<n>\d+)\s+prog_id=(?P<prog_id>\d+)")

# Measured-op count per shape (mirrors kernel_bpf::cost_corpus `ops`).
SHAPE_OPS = {
    "straight": lambda n: n - 2,
    "memory": lambda n: n - 3,
    "div": lambda n: n - 2,
    "ktime": lambda n: n - 1,
    "map": lambda n: (n - 4) // 4,
    "copy": lambda n: (n - 2) // 2,
    "ringbuf": lambda n: (n - 4) // 6,
}

# The cost-model constant each shape calibrates (verifier/cost.rs).
SHAPE_CONSTANT = {
    "straight": "COST_DEFAULT",
    "memory": "COST_MEMORY",
    "div": "COST_ALU_EXPENSIVE",
    "ktime": "COST_HELPER_READ",
    "map": "COST_HELPER_MAP",
    "copy": "COST_HELPER_COPY",
    "ringbuf": "COST_HELPER_RINGBUF",
}


def parse(lines):
    rows, exec_rows, labels = [], [], {}
    for line in lines:
        m = MARKER.search(line)
        if m:
            rows.append({k: (int(v) if v is not None else 0) for k, v in m.groupdict().items()})
            continue
        m = EXEC_MARKER.search(line)
        if m:
            exec_rows.append({k: int(v) for k, v in m.groupdict().items()})
            continue
        m = LABEL.search(line.strip())
        if m:
            labels[int(m.group("prog_id"))] = (m.group("shape"), int(m.group("n")))
    return rows, exec_rows, labels


def summarize_exec(exec_rows, labels, cntfrq):
    if not exec_rows:
        return
    print("\n=== Execution cost (BPF_BENCH_EXEC) ===")
    width = "{:>10} {:>8} {:>8} {:>6} {:>14} {:>14} {:>12}"
    print(width.format("shape", "prog_id", "insns", "runs", "cycles", "cyc/run", "cyc/op"))
    # (shape) -> {n: cycles_per_run}
    by_shape = {}
    for r in exec_rows:
        shape, n = labels.get(r["prog_id"], ("?", r["insns"]))
        per_run = r["cycles"] / r["runs"] if r["runs"] else 0.0
        ops = SHAPE_OPS.get(shape, lambda n: n)(n)
        per_op = per_run / ops if ops else 0.0
        by_shape.setdefault(shape, {})[n] = per_run
        print(width.format(
            shape, r["prog_id"], r["insns"], r["runs"], r["cycles"],
            "{:.1f}".format(per_run), "{:.2f}".format(per_op),
        ))
    # Calibration: slope between the two largest sizes per shape cancels the
    # fixed per-run overhead (interpreter entry/exit, timer reads).
    print("\n=== Calibration estimates (slope between sizes) ===")
    for shape, sizes in sorted(by_shape.items()):
        if shape not in SHAPE_OPS or len(sizes) < 2:
            continue
        ns = sorted(sizes)
        n1, n2 = ns[-2], ns[-1]
        ops1, ops2 = SHAPE_OPS[shape](n1), SHAPE_OPS[shape](n2)
        if ops2 == ops1:
            continue
        per_op = (sizes[n2] - sizes[n1]) / (ops2 - ops1)
        line = "{:>10}: {:.2f} cycles/op -> {}".format(shape, per_op, SHAPE_CONSTANT[shape])
        if cntfrq:
            line += "  ({:.1f} ns/op)".format(per_op * 1e9 / cntfrq)
        print(line)


def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["prog_id", "insns", "states", "cycles", "wcet"])
        w.writeheader()
        w.writerows(rows)


def summarize(rows, cntfrq):
    if not rows:
        print("no AXIOM VERIFIER COST markers found", file=sys.stderr)
        return
    width = "{:>8} {:>8} {:>10} {:>12} {:>10} {:>14} {:>16}"
    print(width.format("prog_id", "insns", "states", "cycles", "wcet", "cyc/insn", "us" if cntfrq else ""))
    for r in rows:
        cyc_per_insn = r["cycles"] / r["insns"] if r["insns"] else 0.0
        us = "{:.3f}".format(r["cycles"] * 1e6 / cntfrq) if cntfrq else ""
        print(width.format(
            r["prog_id"], r["insns"], r["states"], r["cycles"], r.get("wcet", 0),
            "{:.2f}".format(cyc_per_insn), us,
        ))
    # Bound check: for the loop-free fragment states_explored <= n.
    violations = [r for r in rows if r["states"] > r["insns"]]
    if violations:
        print(
            "\nWARNING: {} program(s) exceeded states<=n (loop-free bound):".format(len(violations)),
            file=sys.stderr,
        )
        for r in violations:
            print("  prog_id={} insns={} states={}".format(r["prog_id"], r["insns"], r["states"]), file=sys.stderr)
    else:
        print("\nOK: all loads respected states_explored <= insns (loop-free linear bound)")


def plot(rows, path, h):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available; skipping plot", file=sys.stderr)
        return
    rows = sorted(rows, key=lambda r: r["insns"])
    n = [r["insns"] for r in rows]
    cycles = [r["cycles"] for r in rows]
    states = [r["states"] for r in rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    ax1.plot(n, states, "o-", label="states_explored")
    ax1.plot(n, [(h + 1) * x for x in n], "--", label="budget T(n)=(h+1)·n")
    ax1.set_xlabel("program size (instructions)")
    ax1.set_ylabel("verifier states explored")
    ax1.set_title("Verifier state count vs size")
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    ax2.plot(n, cycles, "o-", color="C2", label="verify cycles (CNTVCT)")
    ax2.set_xlabel("program size (instructions)")
    ax2.set_ylabel("verification cost (cycles)")
    ax2.set_title("Verifier wall-clock cost vs size")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print("wrote plot to {}".format(path))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="UART/serial log file, or - for stdin")
    ap.add_argument("-o", "--csv", help="write parsed rows to this CSV")
    ap.add_argument("--plot", help="write a cost-vs-size PNG to this path")
    ap.add_argument("--cntfrq", type=float, default=0.0, help="cntvct frequency in Hz (Pi5 ~54e6) for us conversion")
    ap.add_argument("--height", type=int, default=0, help="abstract-domain height h for the T(n)=(h+1)·n budget overlay (0 ⇒ straight-line, T(n)=n)")
    args = ap.parse_args()

    src = sys.stdin if args.log == "-" else open(args.log)
    rows, exec_rows, labels = parse(src)
    if args.log != "-":
        src.close()

    summarize(rows, args.cntfrq)
    summarize_exec(exec_rows, labels, args.cntfrq)
    if args.csv:
        write_csv(rows, args.csv)
        print("\nwrote {} rows to {}".format(len(rows), args.csv))
        if exec_rows:
            exec_csv = args.csv.replace(".csv", "-exec.csv")
            with open(exec_csv, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["shape", "n", "prog_id", "insns", "runs", "cycles"])
                w.writeheader()
                for r in exec_rows:
                    shape, n = labels.get(r["prog_id"], ("?", r["insns"]))
                    w.writerow({"shape": shape, "n": n, **r})
            print("wrote {} exec rows to {}".format(len(exec_rows), exec_csv))
    if args.plot:
        plot(rows, args.plot, args.height)


if __name__ == "__main__":
    main()
