#!/usr/bin/env python3
"""Reduce V03-B latency markers from a Pi UART log into a distribution.

Parses legacy and keyed `PI5_MC`/`PI5_MA` lines and reports count +
min/median/p95/p99/p99.9/max. Use `scripts/benchmark/analyze-v03.py --pairs`
for the merge-gating paired M-A result.

Usage: v03b-reduce.py [--warmup N] <uart-log> [uart-log ...]

--warmup N   drop the first N M-C/M-A samples from each input log
             (cold cache/TLB after each boot). Default 0.
"""
import math
import re
import sys

MC = re.compile(rb"PI5_MC(?: sample_id=\d+)? ns=(\d+)")
MA = re.compile(rb"PI5_MA(?: sample_id=\d+ monitor_)?ns=(\d+)")


def pct(xs, p):
    # nearest-rank percentile on a sorted list
    if not xs:
        return 0
    k = max(0, min(len(xs) - 1, math.ceil(p / 100.0 * len(xs)) - 1))
    return xs[k]


def summarize(name, vals, target_ns=None):
    vals = sorted(vals)
    n = len(vals)
    print(f"\n== {name}  (n={n}) ==")
    if n == 0:
        print("  no samples")
        return
    med = pct(vals, 50)
    for label, p in (("min", 0), ("median", 50), ("p95", 95),
                     ("p99", 99), ("p99.9", 99.9), ("max", 100)):
        v = vals[0] if p == 0 else (vals[-1] if p == 100 else pct(vals, p))
        print(f"  {label:>7}: {v:>10} ns  ({v/1000:.3f} us)")
    if target_ns is not None:
        verdict = "PASS" if med < target_ns else "OVER"
        print(f"  median vs {target_ns} ns target: {verdict}")


def main(paths, warmup=0):
    mc, ma = [], []
    for p in paths:
        data = open(p, "rb").read()
        path_mc = [int(m.group(1)) for m in MC.finditer(data)]
        path_ma = [int(m.group(1)) for m in MA.finditer(data)]
        if warmup:
            path_mc = path_mc[warmup:]
            path_ma = path_ma[warmup:]
        mc += path_mc
        ma += path_ma
    if warmup:
        print(f"(dropping first {warmup} samples per input log as warmup)")
    # V03-B target: median < 500 ns (fallback < 1000 ns). V03-A: M-A < 5000 ns.
    summarize("M-C edge->actuate (V03-B software path)", mc, target_ns=1000)
    summarize("M-A monitor overhead (V03-A)", ma, target_ns=5000)
    print()
    if len(mc) < 10000:
        print(f"NOTE: {len(mc)} M-C samples < 10000 — send more pulses for the "
              f"N>=10,000 requirement.")


if __name__ == "__main__":
    args = sys.argv[1:]
    warmup = 0
    if len(args) >= 2 and args[0] == "--warmup":
        warmup = int(args[1])
        args = args[2:]
    if not args:
        print(__doc__)
        sys.exit(2)
    main(args, warmup)
