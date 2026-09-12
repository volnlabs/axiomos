#!/usr/bin/env python3
"""Analyze v0.3 Pi5 bench serial and logic-analyzer captures."""

import argparse
import csv
import math
import re
import statistics
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch
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
CONTAINMENT_RECORD_PATTERN = re.compile(
    r"PI5_V03C\s+sample_id=(\d+)\s+kind=(pwm|gpio)\s+channel=(\d+)\s+"
    r"requested=(\d+)\s+decision=(allow|clamp|safe|reject)\s+"
    r"applied=(\d+)\s+intended_output=(\d+)"
)
CONTAINMENT_SUMMARY_PATTERN = re.compile(
    r"PI5_V03C_SUMMARY\s+n=(\d+)\s+escapes=(\d+)\s+safed=(\d+)\s+"
    r"clamps=(\d+)\s+seed=(0x[0-9a-fA-F]+)"
)
BENCH_LOG_LOSS_PATTERN = re.compile(r"PI5_BENCH_LOG_LOSS\s+dropped_records=(\d+)")

LOGIC_ALIASES = {
    "time_s": ("time_s", "time", "time [s]", "time(s)", "seconds"),
    "input_gpio23": ("input_gpio23", "gpio23", "ch0", "channel 0", "input"),
    "pwm_ena_gpio12": ("pwm_ena_gpio12", "gpio12", "ch1", "channel 1", "pwm", "ena"),
    "estop_gpio24": ("estop_gpio24", "gpio24", "ch2", "channel 2", "estop"),
}

# Locked embedded-profile envelopes used by the on-device corpus.
PWM_DUTY_MAX = 90
GPIO_LEVEL_MAX = 1
GPIO_PIN_MAX = 27


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

    def test_logic_edges_reject_missing_duplicate_or_out_of_order_responses(self):
        header = "time_s,input_gpio23,pwm_ena_gpio12,estop_gpio24"
        cases = {
            "missing": [
                "0,0,1,1", "1e-6,1,1,1", "2e-6,0,1,1",
                "3e-6,1,1,1", "3.4e-6,1,0,1",
            ],
            "duplicate": [
                "0,0,1,1", "1e-6,1,1,1", "1.2e-6,1,0,1",
                "1.5e-6,1,1,1", "1.7e-6,1,0,1",
            ],
            "out-of-order": [
                "0,0,1,1", "1e-6,1,1,1", "2e-6,0,1,1",
                "2.5e-6,1,1,1", "2.6e-6,0,1,1", "2.7e-6,1,0,1",
            ],
        }
        for name, rows in cases.items():
            with tempfile.TemporaryDirectory() as tmp:
                logic = Path(tmp) / f"{name}.csv"
                logic.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "edge"):
                    parse_logic(logic)

    def test_logic_edges_reject_nonmonotonic_timestamps_and_same_row_response(self):
        header = "time_s,input_gpio23,pwm_ena_gpio12,estop_gpio24"
        for rows in (
            ["0,0,1,1", "2e-6,1,1,1", "1e-6,1,0,1", "3e-6,0,1,1"],
            ["0,0,1,1", "1e-6,1,0,1", "2e-6,0,1,1"],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                logic = Path(tmp) / "ordering.csv"
                logic.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "(timestamp|row|edge)"):
                    parse_logic(logic)

    def test_containment_records_are_correlated_and_exact(self):
        text = (
            "PI5_V03C sample_id=1 kind=pwm channel=2 requested=200 "
            "decision=clamp applied=90 intended_output=90\n"
            "PI5_V03C sample_id=2 kind=gpio channel=99 requested=1 "
            "decision=reject applied=0 intended_output=0\n"
            "PI5_V03C_SUMMARY n=2 escapes=0 safed=1 clamps=1 seed=0x1\n"
        )
        records = parse_containment(text, expected_count=2)
        self.assertEqual([record["sample_id"] for record in records], [1, 2])
        summary = parse_containment_summary(text)
        self.assertEqual(validate_containment(records, summary), [])

    def test_containment_records_reject_missing_duplicate_or_mismatch(self):
        base = (
            "PI5_V03C sample_id=1 kind=pwm channel=2 requested=200 "
            "decision=clamp applied=90 intended_output=90\n"
            "PI5_V03C sample_id=2 kind=gpio channel=99 requested=1 "
            "decision=reject applied=0 intended_output=0\n"
        )
        for malformed in (
            base.replace("sample_id=2", "sample_id=1"),
            base.replace("sample_id=2", "sample_id=3"),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_containment(malformed, expected_count=2)
        records = parse_containment(base, expected_count=2)
        self.assertTrue(validate_containment([records[1].copy() | {"intended_output": 1}]))
        self.assertTrue(validate_containment([records[0].copy() | {"applied": 999, "intended_output": 999}]))

    def test_sensor_cli_pass_names_cycle_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "sensor.log"
            serial.write_text(
                "PI5_MA sample_id=1 monitor_ns=120\n"
                "PI5_MC sample_id=1 ns=210 kind=gpio ch=12 val=0\n"
                "PI5_REFLEX_REARM sample_id=1 mode=gpio code=0\n",
                encoding="utf-8",
            )
            output = StringIO()
            with patch("sys.argv", [__file__, "--sensor", str(serial), "--sensor-count", "1"]), redirect_stdout(output):
                self.assertEqual(main(), 0)
            self.assertIn("PASS: selected checks satisfied: sensor cycle correlation", output.getvalue())
            self.assertNotIn("timing thresholds", output.getvalue())

    def test_log_loss_uses_cumulative_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "bench.log"
            serial.write_text(
                "PI5_BENCH_LOG_LOSS dropped_records=1\n"
                "PI5_BENCH_LOG_LOSS dropped_records=2\n",
                encoding="utf-8",
            )
            self.assertEqual(validate_log_loss(serial), ["serial log loss: dropped_records=2"])


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


def validate_log_loss(path: Path) -> list[str]:
    losses = [int(match.group(1)) for match in BENCH_LOG_LOSS_PATTERN.finditer(path.read_text(encoding="utf-8"))]
    dropped = max(losses, default=0)
    return [f"serial log loss: dropped_records={dropped}"] if dropped else []


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

    for row_index in range(1, len(rows)):
        if rows[row_index][0] <= rows[row_index - 1][0]:
            raise ValueError(f"logic timestamp at row {row_index + 1} is not strictly increasing")

    input_edges: list[tuple[float, int]] = []
    response_edges: list[tuple[float, int]] = []
    for i in range(1, len(rows)):
        prev_t, prev_input, _prev_pwm = rows[i - 1]
        t, input_level, _pwm = rows[i]
        if prev_input == 0 and input_level == 1:
            input_edges.append((t, i))
        if rows[i - 1][2] == 1 and rows[i][2] == 0:
            response_edges.append((t, i))

    if len(input_edges) != len(response_edges):
        raise ValueError(
            f"edge population mismatch: {len(input_edges)} input edges, "
            f"{len(response_edges)} response edges"
        )
    latencies: list[int] = []
    for index, ((input_t, input_row), (response_t, response_row)) in enumerate(
        zip(input_edges, response_edges)
    ):
        next_input_t = input_edges[index + 1][0] if index + 1 < len(input_edges) else None
        if response_t < input_t:
            raise ValueError(f"edge response {index + 1} precedes its input")
        if response_row <= input_row:
            raise ValueError(f"edge response {index + 1} is not after its input row")
        if next_input_t is not None and response_t >= next_input_t:
            raise ValueError(f"edge response {index + 1} occurs after the next input")
        latencies.append(int(round((response_t - input_t) * 1_000_000_000)))
    return latencies


def parse_containment(source: Path | str, expected_count: int = 1_000) -> list[dict[str, int | str]]:
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    records: list[dict[str, int | str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("PI5_V03C "):
            continue
        match = CONTAINMENT_RECORD_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"line {line_no}: malformed containment record")
        sample_id, kind, channel, requested, decision, applied, output = match.groups()
        if int(sample_id) != len(records) + 1:
            raise ValueError(f"containment sample_id {sample_id} out of order; expected {len(records) + 1}")
        records.append({
            "sample_id": int(sample_id),
            "kind": kind,
            "channel": int(channel),
            "requested": int(requested),
            "decision": decision,
            "applied": int(applied),
            "intended_output": int(output),
        })
    if len(records) != expected_count:
        raise ValueError(f"containment record count {len(records)} != {expected_count}")
    return records


def validate_containment(
    records: list[dict[str, int | str]], summary: dict[str, int] | None = None
) -> list[str]:
    errors: list[str] = []
    for record in records:
        if record["applied"] != record["intended_output"]:
            errors.append(f"containment sample_id {record['sample_id']} applied/intended mismatch")
        kind, channel = record["kind"], record["channel"]
        if kind == "pwm":
            envelope = (0, PWM_DUTY_MAX) if channel in {1, 2} else None
        else:
            envelope = (0, GPIO_LEVEL_MAX) if 0 <= channel <= GPIO_PIN_MAX else None
        decision = record["decision"]
        requested, applied = record["requested"], record["applied"]
        if requested > 0xFFFF_FFFF:
            errors.append(f"containment sample_id {record['sample_id']} requested value out of range")
        if envelope is None:
            if decision != "reject" or applied != 0:
                errors.append(f"containment sample_id {record['sample_id']} invalid channel escaped reject")
        elif not envelope[0] <= applied <= envelope[1]:
            errors.append(f"containment sample_id {record['sample_id']} applied value outside envelope")
        elif decision == "allow" and (requested > envelope[1] or applied != requested):
            errors.append(f"containment sample_id {record['sample_id']} invalid allow decision")
        elif decision == "reject":
            errors.append(f"containment sample_id {record['sample_id']} rejected known channel")
    if summary is not None:
        if summary["n"] != len(records):
            errors.append(f"containment summary n {summary['n']} != {len(records)}")
        safed = sum(record["decision"] in {"safe", "reject"} for record in records)
        clamps = sum(record["decision"] == "clamp" for record in records)
        if summary["safed"] != safed:
            errors.append(f"containment summary safed {summary['safed']} != {safed}")
        if summary["clamps"] != clamps:
            errors.append(f"containment summary clamps {summary['clamps']} != {clamps}")
        if summary["escapes"] != 0:
            errors.append(f"containment escapes={summary['escapes']}")
    return errors


def parse_containment_summary(source: Path | str) -> dict[str, int]:
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    matches = CONTAINMENT_SUMMARY_PATTERN.findall(text)
    if len(matches) != 1:
        raise ValueError(f"containment summary count {len(matches)} != 1")
    n, escapes, safed, clamps, seed = matches[0]
    return {
        "n": int(n),
        "escapes": int(escapes),
        "safed": int(safed),
        "clamps": int(clamps),
        "seed": int(seed, 16),
    }


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
    parser.add_argument("--containment", type=Path, help="serial log with correlated V03-C records")
    parser.add_argument("--containment-count", type=int, default=1_000, help="expected V03-C request count")
    parser.add_argument("--logic", type=Path, help="logic-analyzer CSV")
    parser.add_argument("--self-test", action="store_true", help="run parser self-tests")
    args = parser.parse_args()

    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        return 0 if result.result.wasSuccessful() else 1

    if not args.serial and not args.logic and not args.pairs and not args.estop and not args.sensor and not args.containment:
        parser.error("provide --serial, --pairs, --sensor, --estop, --containment, --logic, or --self-test")

    failures: list[str] = []
    checks: list[str] = []

    if args.serial or args.pairs or args.estop or args.sensor or args.containment:
        serial_paths = [path for path in (args.serial, args.pairs, args.estop, args.sensor, args.containment) if path]
        for path in serial_paths:
            failures.extend(validate_log_loss(path))

    if args.serial:
        checks.append("serial timing thresholds")
        samples = parse_serial(args.serial)
        for name in ("M-A", "M-B", "M-C"):
            print(_format_stats(name, samples[name]))
        failures.extend(validate_thresholds(samples))
        failures.extend(validate_correlations(samples))
        mc_median = stats(samples["M-C"])["median"]
        if samples["M-C"] and mc_median >= 500 and mc_median < 1_000:
            print(f"M-C median {mc_median} ns misses 500 ns target; fallback claim applies")

    if args.logic:
        checks.append("logic measured criteria")
        try:
            logic_latencies = parse_logic(args.logic)
        except ValueError as error:
            failures.append(str(error))
        else:
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
        checks.append("paired timing threshold")
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
        checks.append("e-stop cycle/re-arm checks")
        failures.extend(validate_estop_cycles(args.estop, args.estop_count))

    if args.sensor:
        checks.append("sensor cycle correlation")
        failures.extend(validate_sensor_cycles(args.sensor, args.sensor_count))

    if args.containment:
        checks.append("containment decision model")
        try:
            records = parse_containment(args.containment, args.containment_count)
        except ValueError as error:
            failures.append(str(error))
        else:
            try:
                summary = parse_containment_summary(args.containment)
            except ValueError as error:
                failures.append(str(error))
            else:
                failures.extend(validate_containment(records, summary))
            print(f"V03-C decision model: count={len(records)}; live helper routing and physical output are not tested")

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"PASS: selected checks satisfied: {', '.join(checks)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
