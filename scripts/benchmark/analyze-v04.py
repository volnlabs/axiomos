#!/usr/bin/env python3
"""Reduce retained v0.4 serial markers without assigning hardware pass claims."""

from __future__ import annotations

import argparse
import math
import unittest
from collections import defaultdict
from pathlib import Path

STAGES = ("load", "verify", "admit", "attach", "active")
STAT_KEYS = ("count", "min", "median", "p95", "p99", "p99.9", "max")


def _int(record: dict[str, str], key: str) -> int:
    try:
        return int(record[key])
    except KeyError as error:
        raise ValueError(f"{record['_event']} missing {key}") from error
    except ValueError as error:
        raise ValueError(f"{record['_event']} has non-decimal {key}={record[key]!r}") from error


def parse(text: str) -> list[dict[str, str]]:
    records = []
    for line_no, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or not fields[0].startswith("V04_"):
            continue
        record = {"_event": fields[0], "_line": str(line_no)}
        for field in fields[1:]:
            if "=" not in field:
                raise ValueError(f"line {line_no}: malformed marker field {field!r}")
            key, value = field.split("=", 1)
            if not key or not value or key in record:
                raise ValueError(f"line {line_no}: malformed marker field {field!r}")
            record[key] = value
        records.append(record)
    return records


def _nearest_rank(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def stats(values: list[int]) -> dict[str, int]:
    if not values:
        return dict.fromkeys(STAT_KEYS, 0)
    return {
        "count": len(values), "min": min(values), "median": _nearest_rank(values, 0.5),
        "p95": _nearest_rank(values, 0.95), "p99": _nearest_rank(values, 0.99),
        "p99.9": _nearest_rank(values, 0.999), "max": max(values),
    }


def _contiguous(ids: list[int], label: str) -> None:
    for expected, actual in enumerate(ids, 1):
        if actual != expected:
            raise ValueError(f"{label} sample_id {actual} out of order; expected {expected}")


def analyze(text: str, *, min_behavior_samples: int = 100, min_latency_samples: int = 1000,
            min_estop_samples: int = 100, max_heartbeat_gap_ns: int | None = None,
            max_chunk_gap_ns: int | None = None) -> dict[str, dict[str, int]]:
    by_event: dict[str, list[dict[str, str]]] = defaultdict(list)
    for record in parse(text):
        by_event[record["_event"]].append(record)
    panics = by_event["V04_PANIC"]
    if panics:
        raise ValueError("panic/fatal markers present: " + ", ".join(r.get("kind", "unknown") for r in panics))

    lifecycles: dict[str, dict[int, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for record in by_event["V04_BEHAVIOR"]:
        behavior, stage = record.get("behavior"), record.get("stage")
        if not behavior:
            raise ValueError("V04_BEHAVIOR missing behavior")
        if stage not in STAGES:
            raise ValueError(f"V04_BEHAVIOR has invalid stage {stage!r}")
        lifecycles[behavior][_int(record, "sample_id")].append(record)
        _int(record, "ts_ns")
    if not lifecycles:
        raise ValueError("no V04_BEHAVIOR lifecycle markers")

    report: dict[str, dict[str, int]] = {}
    for behavior, samples in lifecycles.items():
        ids = sorted(samples)
        _contiguous(ids, f"behavior {behavior}")
        latencies = []
        for sample_id in ids:
            records = samples[sample_id]
            observed = [r["stage"] for r in records]
            if observed != list(STAGES):
                raise ValueError(f"behavior {behavior} sample_id {sample_id} lifecycle {observed} != {list(STAGES)}")
            timestamps = [_int(r, "ts_ns") for r in records]
            if timestamps != sorted(timestamps):
                raise ValueError(f"behavior {behavior} sample_id {sample_id} timestamps decrease")
            latencies.append(timestamps[-1] - timestamps[0])
        if len(latencies) < min_behavior_samples:
            raise ValueError(f"behavior {behavior} count {len(latencies)} < {min_behavior_samples}")
        report[f"behavior:{behavior}"] = stats(latencies)

    sensors: dict[str, dict[int, dict[str, str]]] = defaultdict(dict)
    for event in ("V04_ECHO_DONE", "V04_HOOK_ENTRY", "V04_MOTOR_CMD"):
        for record in by_event[event]:
            sample_id = _int(record, "sample_id")
            _int(record, "ts_ns")
            if sample_id in sensors[event]:
                raise ValueError(f"{event} contains duplicate sample_id {sample_id}")
            sensors[event][sample_id] = record
    present = [event for event, records in sensors.items() if records]
    if present:
        if len(present) != 3:
            raise ValueError("incomplete echo/hook/motor correlation")
        ids = sorted(sensors["V04_ECHO_DONE"])
        _contiguous(ids, "echo")
        for event in ("V04_HOOK_ENTRY", "V04_MOTOR_CMD"):
            if sorted(sensors[event]) != ids:
                raise ValueError(f"{event} IDs do not match V04_ECHO_DONE")
        echo_to_hook, hook_to_motor, echo_to_motor = [], [], []
        for sample_id in ids:
            echo = _int(sensors["V04_ECHO_DONE"][sample_id], "ts_ns")
            hook = _int(sensors["V04_HOOK_ENTRY"][sample_id], "ts_ns")
            motor = _int(sensors["V04_MOTOR_CMD"][sample_id], "ts_ns")
            if not echo <= hook <= motor:
                raise ValueError(f"sample_id {sample_id} echo/hook/motor timestamps are out of order")
            echo_to_hook.append(hook - echo); hook_to_motor.append(motor - hook); echo_to_motor.append(motor - echo)
        if len(ids) < min_latency_samples:
            raise ValueError(f"sensor latency count {len(ids)} < {min_latency_samples}")
        report["echo_to_hook_ns"] = stats(echo_to_hook)
        report["hook_to_motor_ns"] = stats(hook_to_motor)
        report["echo_to_motor_ns"] = stats(echo_to_motor)

    chunks: dict[int, list[dict[str, str]]] = defaultdict(list)
    for record in by_event["V04_CHUNK"]:
        if record.get("stage") not in ("start", "end"):
            raise ValueError(f"V04_CHUNK has invalid stage {record.get('stage')!r}")
        _int(record, "ts_ns")
        chunks[_int(record, "chunk_id")].append(record)
    ends = []
    for chunk_id in sorted(chunks):
        _contiguous(sorted(chunks), "chunk")
        pair = chunks[chunk_id]
        if [r["stage"] for r in pair] != ["start", "end"]:
            raise ValueError(f"chunk_id {chunk_id} must have one ordered start/end pair")
        start, end = (_int(r, "ts_ns") for r in pair)
        if end < start:
            raise ValueError(f"chunk_id {chunk_id} end precedes start")
        if ends and max_chunk_gap_ns is not None and start - ends[-1] > max_chunk_gap_ns:
            raise ValueError(f"chunk gap {start - ends[-1]} > {max_chunk_gap_ns} ns")
        ends.append(end)

    heartbeats = by_event["V04_HEARTBEAT"]
    if heartbeats:
        timestamps = [_int(record, "ts_ns") for record in heartbeats]
        for record in heartbeats:
            _int(record, "seq")  # Wire sequence wraps; timestamp ordering is authoritative.
        if timestamps != sorted(timestamps) or len(timestamps) != len(set(timestamps)):
            raise ValueError("heartbeat timestamps are not strictly increasing")
        if max_heartbeat_gap_ns is None:
            raise ValueError("heartbeat markers require --max-heartbeat-gap-ns")
        gaps = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]
        if any(gap > max_heartbeat_gap_ns for gap in gaps):
            raise ValueError(f"heartbeat gap {max(gaps)} > {max_heartbeat_gap_ns} ns")
        report["heartbeat_gap_ns"] = stats(gaps)

    for event in ("V04_LINK_LOSS", "V04_ESTOP"):
        markers = by_event[event]
        ids = [_int(record, "event_id") for record in markers]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{event} contains duplicate event_ids")
        _contiguous(ids, event)
        for marker in markers:
            _int(marker, "ts_ns")
    estops = by_event["V04_ESTOP"]
    if estops and len(estops) < min_estop_samples:
        raise ValueError(f"e-stop count {len(estops)} < {min_estop_samples}")
    report["e_stop_events"] = stats([_int(record, "ts_ns") for record in estops])
    return report


class AnalyzerSelfTest(unittest.TestCase):
    def valid(self) -> str:
        behaviors = [f"V04_BEHAVIOR sample_id=1 behavior={name} stage={stage} ts_ns={100 + i * 10}" for name in ("stop", "drive") for i, stage in enumerate(STAGES)]
        return "\n".join(behaviors + ["V04_ECHO_DONE sample_id=1 echo_us=10 ts_ns=200", "V04_HOOK_ENTRY sample_id=1 ts_ns=210", "V04_MOTOR_CMD sample_id=1 seq=1 left=0 right=0 ts_ns=220", "V04_CHUNK chunk_id=1 stage=start ts_ns=1", "V04_CHUNK chunk_id=1 stage=end ts_ns=300"])

    def run_valid(self, text: str | None = None, **kwargs: int) -> dict[str, dict[str, int]]:
        return analyze(text or self.valid(), min_behavior_samples=1, min_latency_samples=1, min_estop_samples=0, **kwargs)

    def test_valid_lifecycle_and_sensor_correlation_has_all_stats(self):
        report = self.run_valid()
        self.assertEqual(set(report["behavior:stop"]), set(STAT_KEYS))
        self.assertEqual(report["echo_to_motor_ns"]["max"], 20)

    def test_missing_duplicate_and_out_of_order_lifecycle_fail(self):
        for old, new in (("stage=admit", "stage=nope"), ("stage=admit", "stage=verify"), ("stage=verify ts_ns=110", "stage=verify ts_ns=150")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.run_valid(self.valid().replace(old, new, 1))

    def test_sensor_id_gaps_and_duplicates_fail(self):
        with self.assertRaisesRegex(ValueError, "out of order"):
            self.run_valid(self.valid().replace("sample_id=1 echo_us", "sample_id=2 echo_us"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_valid(self.valid() + "\nV04_ECHO_DONE sample_id=1 echo_us=10 ts_ns=230")

    def test_chunk_missing_end_non_monotonic_and_gap_fail(self):
        with self.assertRaises(ValueError): self.run_valid(self.valid().replace("V04_CHUNK chunk_id=1 stage=end ts_ns=300", ""))
        with self.assertRaises(ValueError): self.run_valid(self.valid().replace("stage=end ts_ns=300", "stage=end ts_ns=0"))
        with self.assertRaisesRegex(ValueError, "chunk gap"):
            self.run_valid(self.valid() + "\nV04_CHUNK chunk_id=2 stage=start ts_ns=400\nV04_CHUNK chunk_id=2 stage=end ts_ns=410", max_chunk_gap_ns=50)

    def test_heartbeat_wrap_passes_and_gap_fails(self):
        beats = "\nV04_HEARTBEAT seq=65535 ts_ns=100\nV04_HEARTBEAT seq=0 ts_ns=120"
        self.run_valid(self.valid() + beats, max_heartbeat_gap_ns=20)
        with self.assertRaisesRegex(ValueError, "heartbeat gap"):
            self.run_valid(self.valid() + beats, max_heartbeat_gap_ns=10)

    def test_panic_always_fails(self):
        with self.assertRaisesRegex(ValueError, "panic/fatal"):
            self.run_valid(self.valid() + "\nV04_PANIC kind=panic")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, help="campaign directory containing retained serial logs")
    parser.add_argument("--serial", type=Path, action="append", default=[], help="serial/log file (repeatable)")
    parser.add_argument("--min-behavior-samples", type=int, default=100)
    parser.add_argument("--min-latency-samples", type=int, default=1000)
    parser.add_argument("--min-estop-samples", type=int, default=100)
    parser.add_argument("--max-heartbeat-gap-ns", type=int)
    parser.add_argument("--max-chunk-gap-ns", type=int)
    parser.add_argument("--self-test", action="store_true", help="run reducer self-tests")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        return 0 if result.result.wasSuccessful() else 1
    paths = list(args.serial)
    if args.campaign:
        paths.extend(path for path in args.campaign.rglob("*") if path.is_file())
    if not paths:
        parser.error("provide --campaign, --serial, or --self-test")
    try:
        report = analyze("\n".join(path.read_text(encoding="utf-8", errors="replace") for path in paths), min_behavior_samples=args.min_behavior_samples, min_latency_samples=args.min_latency_samples, min_estop_samples=args.min_estop_samples, max_heartbeat_gap_ns=args.max_heartbeat_gap_ns, max_chunk_gap_ns=args.max_chunk_gap_ns)
    except ValueError as error:
        print(f"V04 FAIL: {error}")
        return 1
    print(f"V04 minimums: behavior={args.min_behavior_samples} latency={args.min_latency_samples} estop={args.min_estop_samples}")
    for name, values in report.items():
        print(name + ": " + " ".join(f"{key}={values[key]}" for key in STAT_KEYS))
    print("V04 PASS: serial boundaries only; debug-GPIO/FPGA physical latency remains pending")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
