#!/usr/bin/env python3
"""Analyze v0.3 Pi5 bench serial and logic-analyzer captures."""

import argparse
import csv
import math
import re
import statistics
import tempfile
import unittest
from pathlib import Path

SERIAL_PATTERNS = {
    "M-A": re.compile(r"\[bench\]\s+M-A\s+monitor_overhead_ns=(\d+)"),
    "M-B": re.compile(r"\[bench\]\s+M-B\s+estop irq-entry->safe latency_ns=(\d+)"),
    "M-C": re.compile(r"\[bench\]\s+M-C\s+edge->pwm-apply ch=\d+ val=\d+ latency_ns=(\d+)"),
}

LOGIC_ALIASES = {
    "time_s": ("time_s", "time", "time [s]", "time(s)", "seconds"),
    "input_gpio23": ("input_gpio23", "gpio23", "ch0", "channel 0", "input"),
    "pwm_ena_gpio12": ("pwm_ena_gpio12", "gpio12", "ch1", "channel 1", "pwm", "ena"),
    "estop_gpio24": ("estop_gpio24", "gpio24", "ch2", "channel 2", "estop"),
}


class AnalyzerSelfTest(unittest.TestCase):
    def test_serial_stats_and_thresholds_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "bench.log"
            serial.write_text(
                "\n".join(
                    [
                        "[bench] M-A monitor_overhead_ns=120",
                        "[bench] M-A monitor_overhead_ns=130",
                        "[bench] M-B estop irq-entry->safe latency_ns=900",
                        "[bench] M-C edge->pwm-apply ch=1 val=0 latency_ns=210",
                        "[bench] M-C edge->pwm-apply ch=1 val=0 latency_ns=220",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            samples = parse_serial(serial)
            self.assertEqual(samples["M-A"], [120, 130])
            self.assertEqual(samples["M-B"], [900])
            self.assertEqual(samples["M-C"], [210, 220])
            self.assertEqual(stats(samples["M-C"])["max"], 220)
            self.assertEqual(validate_thresholds(samples, min_mc_count=2), [])

    def test_logic_edges_are_measured_in_nanoseconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            logic = Path(tmp) / "logic.csv"
            logic.write_text(
                "\n".join(
                    [
                        "time_s,input_gpio23,pwm_ena_gpio12,estop_gpio24",
                        "0.000000000,0,1,1",
                        "0.000001000,1,1,1",
                        "0.000001320,1,0,1",
                        "0.000002000,0,1,1",
                        "0.000003000,1,1,1",
                        "0.000003410,1,0,1",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            latencies = parse_logic(logic)
            self.assertEqual(latencies, [320, 410])
            self.assertEqual(stats(latencies)["median"], 365)


def parse_serial(path: Path) -> dict[str, list[int]]:
    samples: dict[str, list[int]] = {"M-A": [], "M-B": [], "M-C": []}
    for line in path.read_text(encoding="utf-8").splitlines():
        for name, pattern in SERIAL_PATTERNS.items():
            match = pattern.search(line)
            if match:
                samples[name].append(int(match.group(1)))
                break
    return samples


def _nearest_rank(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return ordered[idx]


def _normalize_number(value: float) -> int | float:
    if value == int(value):
        return int(value)
    return value


def stats(values: list[int]) -> dict[str, int | float]:
    if not values:
        return {"count": 0, "min": 0, "median": 0, "p99": 0, "p99.9": 0, "max": 0}

    return {
        "count": len(values),
        "min": min(values),
        "median": _normalize_number(statistics.median(values)),
        "p99": _nearest_rank(values, 0.99),
        "p99.9": _nearest_rank(values, 0.999),
        "max": max(values),
    }


def _canonical_columns(fieldnames: list[str]) -> dict[str, str]:
    lowered = {name.strip().lower(): name for name in fieldnames}
    canonical: dict[str, str] = {}
    for target, aliases in LOGIC_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                canonical[target] = lowered[alias]
                break
    missing = sorted(set(LOGIC_ALIASES) - set(canonical))
    if missing:
        raise ValueError(f"logic CSV missing columns: {', '.join(missing)}")
    return canonical


def _digital(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "high", "h"}:
        return 1
    if normalized in {"0", "false", "low", "l"}:
        return 0
    return 1 if float(normalized) >= 0.5 else 0


def parse_logic(path: Path) -> list[int]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("logic CSV has no header")
        columns = _canonical_columns(reader.fieldnames)
        rows = [
            (
                float(row[columns["time_s"]]),
                _digital(row[columns["input_gpio23"]]),
                _digital(row[columns["pwm_ena_gpio12"]]),
            )
            for row in reader
        ]

    latencies: list[int] = []
    search_from = 1
    for i in range(1, len(rows)):
        prev_t, prev_input, _prev_pwm = rows[i - 1]
        t, input_level, _pwm = rows[i]
        if prev_input != 0 or input_level != 1:
            continue

        search_from = max(search_from, i + 1)
        for j in range(search_from, len(rows)):
            prev_pwm = rows[j - 1][2]
            pwm = rows[j][2]
            if prev_pwm == 1 and pwm == 0:
                latency_ns = int(round((rows[j][0] - t) * 1_000_000_000))
                if latency_ns >= 0:
                    latencies.append(latency_ns)
                search_from = j + 1
                break
    return latencies


def validate_thresholds(samples: dict[str, list[int]], min_mc_count: int = 10_000) -> list[str]:
    errors: list[str] = []

    if not samples.get("M-A"):
        errors.append("M-A has no monitor overhead samples")
    elif stats(samples["M-A"])["max"] >= 5_000:
        errors.append(f"M-A max {stats(samples['M-A'])['max']} ns >= 5000 ns")

    if not samples.get("M-B"):
        errors.append("M-B has no e-stop latency samples")
    elif stats(samples["M-B"])["max"] >= 1_000_000:
        errors.append(f"M-B max {stats(samples['M-B'])['max']} ns >= 1000000 ns")

    if len(samples.get("M-C", [])) < min_mc_count:
        errors.append(f"M-C count {len(samples.get('M-C', []))} < {min_mc_count}")
    elif stats(samples["M-C"])["median"] >= 1_000:
        errors.append(f"M-C median {stats(samples['M-C'])['median']} ns >= 1000 ns fallback")

    return errors


def _format_stats(name: str, values: list[int]) -> str:
    s = stats(values)
    return (
        f"{name}: count={s['count']} min={s['min']} median={s['median']} "
        f"p99={s['p99']} p99.9={s['p99.9']} max={s['max']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", type=Path, help="serial log with [bench] lines")
    parser.add_argument("--logic", type=Path, help="logic-analyzer CSV")
    parser.add_argument("--self-test", action="store_true", help="run parser self-tests")
    args = parser.parse_args()

    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        return 0 if result.result.wasSuccessful() else 1

    if not args.serial and not args.logic:
        parser.error("provide --serial, --logic, or --self-test")

    failures: list[str] = []

    if args.serial:
        samples = parse_serial(args.serial)
        for name in ("M-A", "M-B", "M-C"):
            print(_format_stats(name, samples[name]))
        failures.extend(validate_thresholds(samples))
        mc_median = stats(samples["M-C"])["median"]
        if samples["M-C"] and mc_median >= 500 and mc_median < 1_000:
            print(f"M-C median {mc_median} ns misses 500 ns target; fallback claim applies")

    if args.logic:
        logic_latencies = parse_logic(args.logic)
        print(_format_stats("logic input->pwm", logic_latencies))
        if len(logic_latencies) < 10_000:
            failures.append(f"logic count {len(logic_latencies)} < 10000")
        elif stats(logic_latencies)["median"] >= 1_000:
            failures.append(
                f"logic median {stats(logic_latencies)['median']} ns >= 1000 ns fallback"
            )
        elif stats(logic_latencies)["median"] >= 500:
            print(
                f"logic median {stats(logic_latencies)['median']} ns misses 500 ns target; fallback claim applies"
            )

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: v0.3 bench thresholds satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
