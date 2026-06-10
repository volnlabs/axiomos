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
)


def parse(lines):
    rows = []
    for line in lines:
        m = MARKER.search(line)
        if m:
            rows.append({k: int(v) for k, v in m.groupdict().items()})
    return rows


def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["prog_id", "insns", "states", "cycles"])
        w.writeheader()
        w.writerows(rows)


def summarize(rows, cntfrq):
    if not rows:
        print("no AXIOM VERIFIER COST markers found", file=sys.stderr)
        return
    width = "{:>8} {:>8} {:>10} {:>12} {:>14} {:>16}"
    print(width.format("prog_id", "insns", "states", "cycles", "cyc/insn", "us" if cntfrq else ""))
    for r in rows:
        cyc_per_insn = r["cycles"] / r["insns"] if r["insns"] else 0.0
        us = "{:.3f}".format(r["cycles"] * 1e6 / cntfrq) if cntfrq else ""
        print(width.format(
            r["prog_id"], r["insns"], r["states"], r["cycles"],
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
    rows = parse(src)
    if args.log != "-":
        src.close()

    summarize(rows, args.cntfrq)
    if args.csv:
        write_csv(rows, args.csv)
        print("\nwrote {} rows to {}".format(len(rows), args.csv))
    if args.plot:
        plot(rows, args.plot, args.height)


if __name__ == "__main__":
    main()
