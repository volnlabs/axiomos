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

KEYED_SERIAL_PATTERNS = {
    "M-A": re.compile(r"PI5_MA\s+sample_id=(\d+)\s+monitor_ns=(\d+)"),
    "M-B": re.compile(r"PI5_MB\s+sample_id=(\d+)\s+ns=(\d+)"),
    "M-C": re.compile(r"PI5_MC\s+sample_id=(\d+)\s+ns=(\d+)"),
}

PAIR_PATTERN = re.compile(
    r"PI5_PAIR\s+sample_id=(\d+)\s+baseline_ns=(\d+)\s+"
    r"monitor_ns=(\d+)\s+added_ns=(-?\d+)"
)
ESTOP_REARM_PATTERN = re.compile(
    r"PI5_ESTOP_REARM\s+sample_id=(\d+)\s+mode=gpio\s+code=(-?\d+)"
)
REFLEX_REARM_PATTERN = re.compile(
    r"PI5_REFLEX_REARM\s+sample_id=(\d+)\s+mode=gpio\s+code=(-?\d+)"
)

LOGIC_ALIASES = {
    "time_s": ("time_s", "time", "time [s]", "time(s)", "seconds"),
    "input_gpio23": ("input_gpio23", "gpio23", "ch0", "channel 0", "input"),
    "pwm_ena_gpio12": ("pwm_ena_gpio12", "gpio12", "ch1", "channel 1", "pwm", "ena"),
    "estop_gpio24": ("estop_gpio24", "gpio24", "ch2", "channel 2", "estop"),
}


class AnalyzerSelfTest(unittest.TestCase):
    def test_keyed_samples_and_overhead_pairs_are_correlated(self):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "bench.log"
            serial.write_text(
                "\n".join(
                    [
                        "PI5_MA sample_id=7 monitor_ns=120",
                        "PI5_MC sample_id=7 ns=210 kind=gpio ch=12 val=0",
                        "PI5_PAIR sample_id=1 baseline_ns=80 monitor_ns=130 added_ns=50",
                        "PI5_PAIR sample_id=2 baseline_ns=90 monitor_ns=125 added_ns=35",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            samples = parse_serial(serial)
            self.assertEqual(samples["M-A"], [120])
            self.assertEqual(samples["M-C"], [210])
            self.assertEqual(samples["M-A-ids"], [7])
            self.assertEqual(samples["M-C-ids"], [7])
            self.assertEqual(validate_correlations(samples), [])
            pairs = parse_pairs(serial)
            self.assertEqual(pairs, [(1, 80, 130, 50), (2, 90, 125, 35)])
            self.assertEqual(validate_pairs(pairs, min_count=2), [])

    def test_overhead_pair_gate_uses_added_time_and_exact_count(self):
        too_few = [(1, 80, 130, 50)]
        self.assertEqual(validate_pairs(too_few, min_count=2), ["paired M-A count 1 < 2"])

        too_slow = [(1, 80, 5080, 5000), (2, 90, 130, 40)]
        self.assertEqual(
            validate_pairs(too_slow, min_count=2),
            ["paired M-A max added_ns 5000 >= 5000 ns"],
        )

    def test_overhead_pairs_reject_duplicate_or_inconsistent_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            duplicate = Path(tmp) / "duplicate.log"
            duplicate.write_text(
                "PI5_PAIR sample_id=1 baseline_ns=80 monitor_ns=130 added_ns=50\n"
                "PI5_PAIR sample_id=1 baseline_ns=81 monitor_ns=131 added_ns=50\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate sample_id 1"):
                parse_pairs(duplicate)

            inconsistent = Path(tmp) / "inconsistent.log"
            inconsistent.write_text(
                "PI5_PAIR sample_id=1 baseline_ns=80 monitor_ns=130 added_ns=49\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "inconsistent added_ns"):
                parse_pairs(inconsistent)

    def test_estop_rearms_match_every_nonfinal_press(self):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "estop.log"
            serial.write_text(
                "PI5_MB sample_id=2 ns=900\n"
                "PI5_ESTOP_REARM sample_id=2 mode=gpio code=0\n"
                "PI5_MB sample_id=4 ns=850\n",
                encoding="utf-8",
            )
            self.assertEqual(validate_estop_cycles(serial, expected_count=2), [])

            serial.write_text(
                "PI5_MB sample_id=2 ns=900\n"
                "PI5_ESTOP_REARM sample_id=3 mode=gpio code=0\n"
                "PI5_MB sample_id=4 ns=850\n",
                encoding="utf-8",
            )
            self.assertEqual(
                validate_estop_cycles(serial, expected_count=2),
                ["e-stop re-arm IDs [3] do not match nonfinal press IDs [2]"],
            )

    def test_sensor_samples_reject_missing_or_duplicate_ids(self):
        samples = {
            "M-A-ids": [2, 4, 4],
            "M-C-ids": [2, 5, 6],
        }
        self.assertEqual(
            validate_correlations(samples),
            [
                "M-A sample IDs contain duplicates",
                "M-A sample IDs are not increasing",
                "M-A IDs [2, 4, 4] do not match M-C IDs [2, 5, 6]",
            ],
        )

    def test_sensor_rearms_match_every_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "sensor.log"
            serial.write_text(
                "PI5_MA sample_id=2 monitor_ns=120\n"
                "PI5_MC sample_id=2 ns=210 kind=gpio ch=12 val=0\n"
                "PI5_REFLEX_REARM sample_id=2 mode=gpio code=0\n"
                "PI5_MA sample_id=3 monitor_ns=125\n"
                "PI5_MC sample_id=3 ns=220 kind=gpio ch=12 val=0\n"
                "PI5_REFLEX_REARM sample_id=3 mode=gpio code=0\n",
                encoding="utf-8",
            )
            self.assertEqual(validate_sensor_cycles(serial, expected_count=2), [])

            serial.write_text(
                "PI5_MA sample_id=2 monitor_ns=120\n"
                "PI5_MC sample_id=2 ns=210 kind=gpio ch=12 val=0\n"
                "PI5_REFLEX_REARM sample_id=3 mode=gpio code=0\n",
                encoding="utf-8",
            )
            self.assertEqual(
                validate_sensor_cycles(serial, expected_count=1),
                ["reflex re-arm IDs [3] do not match M-C IDs [2]"],
            )

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
    samples: dict[str, list[int]] = {
        "M-A": [],
        "M-B": [],
        "M-C": [],
        "M-A-ids": [],
        "M-B-ids": [],
        "M-C-ids": [],
    }
    for line in path.read_text(encoding="utf-8").splitlines():
        keyed = False
        for name, pattern in KEYED_SERIAL_PATTERNS.items():
            match = pattern.search(line)
            if match:
                samples[f"{name}-ids"].append(int(match.group(1)))
                samples[name].append(int(match.group(2)))
                keyed = True
                break
        if keyed:
            continue
        for name, pattern in SERIAL_PATTERNS.items():
            match = pattern.search(line)
            if match:
                samples[name].append(int(match.group(1)))
                break
    return samples


def parse_pairs(path: Path) -> list[tuple[int, int, int, int]]:
    pairs: list[tuple[int, int, int, int]] = []
    seen: set[int] = set()
    for match in PAIR_PATTERN.finditer(path.read_text(encoding="utf-8")):
        sample_id, baseline_ns, monitor_ns, added_ns = map(int, match.groups())
        if sample_id in seen:
            raise ValueError(f"duplicate sample_id {sample_id}")
        expected_id = len(pairs) + 1
        if sample_id != expected_id:
            raise ValueError(f"sample_id {sample_id} out of order; expected {expected_id}")
        if monitor_ns - baseline_ns != added_ns:
            raise ValueError(f"sample_id {sample_id} has inconsistent added_ns")
        seen.add(sample_id)
        pairs.append((sample_id, baseline_ns, monitor_ns, added_ns))
    return pairs


def validate_pairs(
    pairs: list[tuple[int, int, int, int]], min_count: int = 10_000
) -> list[str]:
    if len(pairs) < min_count:
        return [f"paired M-A count {len(pairs)} < {min_count}"]
    maximum = max(pair[3] for pair in pairs)
    if maximum >= 5_000:
        return [f"paired M-A max added_ns {maximum} >= 5000 ns"]
    return []


def validate_estop_cycles(path: Path, expected_count: int = 100) -> list[str]:
    samples = parse_serial(path)
    press_ids = samples["M-B-ids"]
    errors: list[str] = []
    if len(press_ids) != expected_count:
        errors.append(f"e-stop press count {len(press_ids)} != {expected_count}")
    if len(set(press_ids)) != len(press_ids):
        errors.append("e-stop press IDs contain duplicates")
    if press_ids != sorted(press_ids):
        errors.append("e-stop press IDs are not increasing")

    text = path.read_text(encoding="utf-8")
    rearm_records = [(int(match.group(1)), int(match.group(2))) for match in ESTOP_REARM_PATTERN.finditer(text)]
    failed_rearms = [sample_id for sample_id, code in rearm_records if code != 0]
    if failed_rearms:
        errors.append(f"e-stop re-arm failed for IDs {failed_rearms}")
    rearm_ids = [sample_id for sample_id, _code in rearm_records]
    expected_rearms = press_ids[:-1]
    if rearm_ids != expected_rearms:
        errors.append(
            f"e-stop re-arm IDs {rearm_ids} do not match nonfinal press IDs {expected_rearms}"
        )
    return errors


def validate_correlations(samples: dict[str, list[int]]) -> list[str]:
    ma_ids = samples.get("M-A-ids", [])
    mc_ids = samples.get("M-C-ids", [])
    if not ma_ids and not mc_ids:
        return []  # Historical logs predate keyed markers.

    errors: list[str] = []
    for name, sample_ids in (("M-A", ma_ids), ("M-C", mc_ids)):
        if len(set(sample_ids)) != len(sample_ids):
            errors.append(f"{name} sample IDs contain duplicates")
        if sample_ids != sorted(set(sample_ids)):
            errors.append(f"{name} sample IDs are not increasing")
    if ma_ids != mc_ids:
        errors.append(f"M-A IDs {ma_ids} do not match M-C IDs {mc_ids}")
    return errors


def validate_sensor_cycles(path: Path, expected_count: int = 10_000) -> list[str]:
    samples = parse_serial(path)
    mc_ids = samples["M-C-ids"]
    errors = validate_correlations(samples)
    if len(mc_ids) != expected_count:
        errors.append(f"sensor response count {len(mc_ids)} != {expected_count}")

    rearm_records = [
        (int(match.group(1)), int(match.group(2)))
        for match in REFLEX_REARM_PATTERN.finditer(path.read_text(encoding="utf-8"))
    ]
    failed_rearms = [sample_id for sample_id, code in rearm_records if code != 0]
    if failed_rearms:
        errors.append(f"reflex re-arm failed for IDs {failed_rearms}")
    rearm_ids = [sample_id for sample_id, _code in rearm_records]
    if rearm_ids != mc_ids:
        errors.append(f"reflex re-arm IDs {rearm_ids} do not match M-C IDs {mc_ids}")
    return errors


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
    parser.add_argument("--pairs", type=Path, help="serial log with PI5_PAIR records")
    parser.add_argument("--estop", type=Path, help="serial log with keyed V03-D records")
    parser.add_argument("--estop-count", type=int, default=100, help="expected V03-D press count")
    parser.add_argument("--sensor", type=Path, help="serial log with keyed V03-B records")
    parser.add_argument("--sensor-count", type=int, default=10_000, help="expected V03-B edge count")
    parser.add_argument("--logic", type=Path, help="logic-analyzer CSV")
    parser.add_argument("--self-test", action="store_true", help="run parser self-tests")
    args = parser.parse_args()

    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        return 0 if result.result.wasSuccessful() else 1

    if not args.serial and not args.logic and not args.pairs and not args.estop and not args.sensor:
        parser.error("provide --serial, --pairs, --sensor, --estop, --logic, or --self-test")

    failures: list[str] = []

    if args.serial:
        samples = parse_serial(args.serial)
        for name in ("M-A", "M-B", "M-C"):
            print(_format_stats(name, samples[name]))
        failures.extend(validate_thresholds(samples))
        failures.extend(validate_correlations(samples))
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

    if args.pairs:
        try:
            pairs = parse_pairs(args.pairs)
        except ValueError as error:
            failures.append(str(error))
        else:
            print(_format_stats("M-A baseline", [pair[1] for pair in pairs]))
            print(_format_stats("M-A monitor", [pair[2] for pair in pairs]))
            print(_format_stats("M-A added", [pair[3] for pair in pairs]))
            failures.extend(validate_pairs(pairs))

    if args.estop:
        failures.extend(validate_estop_cycles(args.estop, args.estop_count))

    if args.sensor:
        failures.extend(validate_sensor_cycles(args.sensor, args.sensor_count))

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: v0.3 bench thresholds satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
