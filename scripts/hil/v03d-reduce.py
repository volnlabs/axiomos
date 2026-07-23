#!/usr/bin/env python3
"""Reduce a V03-D sigrok capture into GPIO24-to-GPIO12 e-stop latencies.

Usage: v03d-reduce.py [--count N] capture.sr [capture.sr ...]

The capture must be acquired at 24 MHz with D0=GPIO24 and D1=GPIO12.  Each D0
falling edge is paired with the next D1 falling edge.  The reducer rejects
missing/extra edges, missing re-arms, out-of-order responses, unsafe final
levels, fewer than N=100 samples, and a maximum latency of 1 ms or more.
"""
import argparse
import csv
import math
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable

SAMPLE_RATE_HZ = 24_000_000
LIMIT_NS = 1_000_000
SAMPLE_RATE = re.compile(r"^;\s*Samplerate:\s*24\s*MHz\s*$", re.MULTILINE)


@dataclass
class Edges:
    d0_falls: list[int]
    d0_rises: list[int]
    d1_falls: list[int]
    d1_rises: list[int]
    initial: tuple[int, int] | None
    final: tuple[int, int] | None


def level(value: str) -> int | None:
    value = value.strip().lower()
    if value in {"0", "low", "l", "false"}:
        return 0
    if value in {"1", "high", "h", "true"}:
        return 1
    return None


def parse_csv(rows: Iterable[list[str]]) -> Edges:
    """Parse sigrok CSV rows and synthesize its trigger edge at sample zero.

    With a D0=f trigger, sigrok begins the stored post-trigger stream with D0
    low and D1 high.  The edge itself happened just before sample 0, so include
    that first physical press explicitly instead of silently losing it.
    """
    d0_falls: list[int] = []
    d0_rises: list[int] = []
    d1_falls: list[int] = []
    d1_rises: list[int] = []
    previous: tuple[int, int] | None = None
    initial: tuple[int, int] | None = None
    samples = 0

    for row in rows:
        if len(row) < 2:
            continue
        d0 = level(row[-2])
        d1 = level(row[-1])
        if d0 is None or d1 is None:
            continue  # CSV heading/comment
        current = (d0, d1)
        if previous is None:
            initial = current
            if current == (0, 1):
                d0_falls.append(0)
        else:
            if previous[0] == 1 and d0 == 0:
                d0_falls.append(samples)
            elif previous[0] == 0 and d0 == 1:
                d0_rises.append(samples)
            if previous[1] == 1 and d1 == 0:
                d1_falls.append(samples)
            elif previous[1] == 0 and d1 == 1:
                d1_rises.append(samples)
        previous = current
        samples += 1

    return Edges(d0_falls, d0_rises, d1_falls, d1_rises, initial, previous)


def pct(values: list[int], percentile: float) -> int:
    # Nearest-rank percentile (also used by the V03-B reducer).
    k = max(0, min(len(values) - 1, math.ceil(percentile / 100 * len(values)) - 1))
    return values[k]


def ns(sample: int) -> int:
    return round(sample * 1_000_000_000 / SAMPLE_RATE_HZ)


def validate(edges: Edges, expected_count: int) -> tuple[list[int], list[str]]:
    errors: list[str] = []
    if edges.initial != (0, 1):
        errors.append(
            "capture must begin D0=0/D1=1 after the D0 falling trigger; "
            f"got {edges.initial!r}"
        )
    if edges.final != (0, 0):
        errors.append(f"capture must end safe with D0=0/D1=0; got {edges.final!r}")

    actual = (len(edges.d0_falls), len(edges.d0_rises), len(edges.d1_falls), len(edges.d1_rises))
    wanted = (expected_count, expected_count - 1, expected_count, expected_count - 1)
    labels = ("D0 falls (presses)", "D0 rises (releases)", "D1 falls (safe responses)", "D1 rises (re-arms)")
    for label, got, need in zip(labels, actual, wanted):
        if got != need:
            errors.append(f"{label}: got {got}, expected exactly {need}")

    latencies: list[int] = []
    for index, d0_fall in enumerate(edges.d0_falls):
        if index >= len(edges.d1_falls):
            errors.append(f"press {index + 1}: no D1 falling safe response")
            break
        d1_fall = edges.d1_falls[index]
        next_d0 = edges.d0_falls[index + 1] if index + 1 < len(edges.d0_falls) else None
        if d1_fall < d0_fall:
            errors.append(f"press {index + 1}: D1 fell before its D0 press")
        elif next_d0 is not None and d1_fall >= next_d0:
            errors.append(f"press {index + 1}: D1 did not fall before the next press")
        else:
            latencies.append(ns(d1_fall - d0_fall))

        if index + 1 < len(edges.d0_falls):
            # The output must remain safe until the physical e-stop releases:
            # press -> safe output -> release -> re-arm -> next press.
            if index >= len(edges.d0_rises) or index >= len(edges.d1_rises):
                errors.append(f"press {index + 1}: release/re-arm edge missing")
            elif not (
                d0_fall
                < d1_fall
                < edges.d0_rises[index]
                < edges.d1_rises[index]
                < next_d0
            ):
                errors.append(f"press {index + 1}: release/re-arm sequence is misaligned")

    # Any response edge not used in the positional pairing is an invalid extra.
    if len(edges.d1_falls) > len(edges.d0_falls):
        first_extra = edges.d1_falls[len(edges.d0_falls)]
        errors.append(f"extra D1 falling response at sample {first_extra}")
    return latencies, errors


def read_capture(path: str) -> Edges:
    try:
        result = subprocess.run(
            ["sigrok-cli", "-i", path, "-O", "csv"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError("sigrok-cli not found") from None
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or f"exit {exc.returncode}"
        raise RuntimeError(f"sigrok-cli could not export {path}: {detail}") from None
    if SAMPLE_RATE.search(result.stdout) is None:
        raise RuntimeError("capture does not declare the required 24 MHz samplerate")
    return parse_csv(csv.reader(result.stdout.splitlines()))


def summarize(latencies: list[int]) -> None:
    values = sorted(latencies)
    print(f"latency samples: n={len(values)}")
    if not values:
        return
    for label, percentile in (("min", 0), ("median", 50), ("p95", 95),
                              ("p99", 99), ("p99.9", 99.9), ("max", 100)):
        value = values[0] if percentile == 0 else values[-1] if percentile == 100 else pct(values, percentile)
        print(f"  {label:>6}: {value:>9} ns ({value / 1000:.3f} us)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=100, help="expected press count (default: 100)")
    parser.add_argument("captures", nargs="+", help="sigrok .sr captures")
    args = parser.parse_args()
    if args.count < 100:
        parser.error("--count must be >= 100")

    all_latencies: list[int] = []
    errors: list[str] = []
    for path in args.captures:
        if not path.endswith(".sr"):
            errors.append(f"{path}: expected a .sr capture")
            continue
        try:
            edges = read_capture(path)
        except RuntimeError as exc:
            errors.append(f"{path}: {exc}")
            continue
        latencies, capture_errors = validate(edges, args.count)
        all_latencies.extend(latencies)
        print(f"{path}: D0 falls={len(edges.d0_falls)} rises={len(edges.d0_rises)}; "
              f"D1 falls={len(edges.d1_falls)} rises={len(edges.d1_rises)}")
        errors.extend(f"{path}: {error}" for error in capture_errors)

    summarize(all_latencies)
    if len(all_latencies) < args.count:
        errors.append(f"only {len(all_latencies)} valid latency samples; need >= {args.count}")
    if all_latencies and max(all_latencies) >= LIMIT_NS:
        errors.append(f"max latency {max(all_latencies)} ns is not below {LIMIT_NS} ns (1 ms)")

    if errors:
        print("VERDICT: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"VERDICT: PASS (N={len(all_latencies)}, max < 1 ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
