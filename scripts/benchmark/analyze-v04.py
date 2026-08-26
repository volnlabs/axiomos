#!/usr/bin/env python3
"""Reduce retained v0.4 serial/log markers; hardware timing remains external."""

from __future__ import annotations

import argparse
import math
import unittest
from unittest import mock
from collections import defaultdict
from pathlib import Path

# `load_request` is emitted before invoking the loader; it is the honest start
# boundary for V04-A rather than pretending the load duration starts on return.
STAGES = ("load_request", "load", "verify", "admit", "attach", "active")
STAT_KEYS = ("count", "min", "median", "p95", "p99", "p99.9", "max")
SCHEMAS = {
    "V04_BEHAVIOR": {"sample_id", "behavior", "stage", "ts_ns"},
    "V04_ECHO_DONE": {"sample_id", "echo_us", "ts_ns"},
    "V04_HOOK_ENTRY": {"sample_id", "ts_ns"},
    "V04_MOTOR_CMD": {"sample_id", "seq", "left", "right", "ts_ns"},
    "V04_LINK_LOSS": {"event_id", "reason", "ts_ns"},
    "V04_ESTOP": {"event_id", "source", "stage", "ts_ns"},
    "V04_HEARTBEAT": {"seq", "ts_ns"},
    "V04_PANIC": {"kind"},
    "V04_FAILURE": {"reason", "count", "ts_ns"},
    "V04_CHUNK": {"chunk_id", "stage", "ts_ns"},
}
LOG_SUFFIXES = {".log", ".serial", ".txt", ".out"}


def _number(record: dict[str, str], key: str, *, positive: bool = False, signed_i16: bool = False) -> int:
    value = record[key]
    if signed_i16:
        try:
            number = int(value, 10)
        except ValueError:
            raise ValueError(f"{record['_event']} has invalid {key}={value!r}") from None
        if not -32768 <= number <= 32767:
            raise ValueError(f"{record['_event']} has out-of-range {key}={value!r}")
    elif not value.isdecimal():
        raise ValueError(f"{record['_event']} has invalid {key}={value!r}")
    else:
        number = int(value)
    if positive and number == 0:
        raise ValueError(f"{record['_event']} has zero {key}")
    return number


def parse(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    last_timestamp: int | None = None
    for line_no, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or not fields[0].startswith("V04_"):
            continue
        event = fields[0]
        if event not in SCHEMAS:
            raise ValueError(f"line {line_no}: unknown marker {event}")
        record = {"_event": event, "_line": str(line_no)}
        for field in fields[1:]:
            if field.count("=") != 1:
                raise ValueError(f"line {line_no}: malformed marker field {field!r}")
            key, value = field.split("=")
            if not key or not value or key in record:
                raise ValueError(f"line {line_no}: malformed marker field {field!r}")
            record[key] = value
        if set(record) - {"_event", "_line"} != SCHEMAS[event]:
            raise ValueError(f"line {line_no}: {event} schema mismatch")
        if event == "V04_BEHAVIOR" and record["stage"] not in STAGES:
            raise ValueError(f"line {line_no}: invalid behavior stage")
        if event == "V04_CHUNK" and record["stage"] not in {"start", "end"}:
            raise ValueError(f"line {line_no}: invalid chunk stage")
        if event == "V04_ESTOP" and (record["source"] not in {"operator", "watchdog", "link"} or record["stage"] not in {"assert", "release"}):
            raise ValueError(f"line {line_no}: invalid e-stop transition")
        if event == "V04_LINK_LOSS" and record["reason"] != "timeout":
            raise ValueError(f"line {line_no}: invalid link-loss reason")
        if event == "V04_PANIC" and record["kind"] not in {"panic", "fatal"}:
            raise ValueError(f"line {line_no}: invalid panic kind")
        if event == "V04_FAILURE" and record["reason"] not in {"input_overflow", "link_uninitialized", "context_reentry"}:
            raise ValueError(f"line {line_no}: invalid failure reason")
        numeric = {"ts_ns", "sample_id", "echo_us", "seq", "left", "right", "event_id", "chunk_id", "count"}
        for key in numeric & set(record):
            _number(
                record,
                key,
                positive=key in {"sample_id", "event_id", "chunk_id", "count"},
                signed_i16=key in {"left", "right"},
            )
        if "ts_ns" in record:
            timestamp = _number(record, "ts_ns")
            if last_timestamp is not None and timestamp < last_timestamp:
                raise ValueError(f"line {line_no}: marker timestamp decreases")
            last_timestamp = timestamp
        records.append(record)
    return records


def _nearest_rank(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(quantile * len(ordered)) - 1]


def stats(values: list[int]) -> dict[str, int]:
    if not values:
        raise ValueError("empty population")
    return {"count": len(values), "min": min(values), "median": _nearest_rank(values, .5),
            "p95": _nearest_rank(values, .95), "p99": _nearest_rank(values, .99),
            "p99.9": _nearest_rank(values, .999), "max": max(values)}


def _ids(records: list[dict[str, str]], key: str, label: str) -> list[int]:
    values = [_number(record, key, positive=True) for record in records]
    if len(values) != len(set(values)):
        raise ValueError(f"{label} contains duplicate {key}s")
    for expected, value in enumerate(values, 1):
        if value != expected:
            raise ValueError(f"{label} {key} {value} out of order; expected {expected}")
    return values


def analyze(text: str, *, min_behavior_samples: int = 100, min_latency_samples: int = 1000,
            min_chunks: int = 1, require_heartbeat: bool = True, require_estop: bool = True,
            min_estop_samples: int = 100, max_heartbeat_gap_ns: int | None = None,
            max_chunk_gap_ns: int | None = None) -> dict[str, dict[str, int]]:
    if min_behavior_samples < 1 or min_latency_samples < 1 or min_chunks < 1:
        raise ValueError("required minimums must be positive")
    if require_estop and min_estop_samples < 1:
        raise ValueError("required e-stop minimum must be positive")
    if max_chunk_gap_ns is None:
        raise ValueError("chunks require --max-chunk-gap-ns")
    if max_chunk_gap_ns < 0:
        raise ValueError("chunk gap limit must be nonnegative")
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    streams = [text] if isinstance(text, str) else text
    for stream in streams:
        for record in parse(stream):
            grouped[record["_event"]].append(record)
    if grouped["V04_PANIC"] or grouped["V04_FAILURE"]:
        raise ValueError("panic/fatal/failure marker present")

    report: dict[str, dict[str, int]] = {}
    lifecycle: dict[str, dict[int, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    behavior_ids: dict[str, list[int]] = defaultdict(list)
    for record in grouped["V04_BEHAVIOR"]:
        behavior, sample_id = record["behavior"], _number(record, "sample_id", positive=True)
        if sample_id not in lifecycle[behavior]:
            behavior_ids[behavior].append(sample_id)
        lifecycle[behavior][sample_id].append(record)
    if not lifecycle:
        raise ValueError("missing behavior population")
    for behavior, samples in lifecycle.items():
        for expected, sample_id in enumerate(behavior_ids[behavior], 1):
            if sample_id != expected:
                raise ValueError(f"behavior {behavior} sample_id {sample_id} out of order; expected {expected}")
        latencies = []
        for sample_id in behavior_ids[behavior]:
            records = samples[sample_id]
            if [record["stage"] for record in records] != list(STAGES):
                raise ValueError(f"behavior {behavior} sample_id {sample_id} lifecycle is incomplete or out of order")
            latencies.append(_number(records[-1], "ts_ns") - _number(records[0], "ts_ns"))
        if len(latencies) < min_behavior_samples:
            raise ValueError(f"behavior {behavior} count {len(latencies)} < {min_behavior_samples}")
        report[f"behavior:{behavior}"] = stats(latencies)

    sensor_events = ("V04_ECHO_DONE", "V04_HOOK_ENTRY", "V04_MOTOR_CMD")
    if any(not grouped[event] for event in sensor_events):
        raise ValueError("missing echo/hook/motor population")
    sensor = {event: grouped[event] for event in sensor_events}
    ids = _ids(sensor["V04_ECHO_DONE"], "sample_id", "echo")
    for event in sensor_events[1:]:
        if _ids(sensor[event], "sample_id", event) != ids:
            raise ValueError(f"{event} IDs do not match V04_ECHO_DONE")
    if len(ids) < min_latency_samples:
        raise ValueError(f"sensor latency count {len(ids)} < {min_latency_samples}")
    echo = { _number(record, "sample_id", positive=True): record for record in sensor["V04_ECHO_DONE"] }
    hook = { _number(record, "sample_id", positive=True): record for record in sensor["V04_HOOK_ENTRY"] }
    motor = { _number(record, "sample_id", positive=True): record for record in sensor["V04_MOTOR_CMD"] }
    triples = [(_number(echo[i], "ts_ns"), _number(hook[i], "ts_ns"), _number(motor[i], "ts_ns")) for i in ids]
    if any(not first <= second <= third for first, second, third in triples):
        raise ValueError("echo/hook/motor timestamps are out of order")
    report["echo_to_hook_ns"] = stats([second - first for first, second, _ in triples])
    report["hook_to_motor_ns"] = stats([third - second for _, second, third in triples])
    report["echo_to_motor_ns"] = stats([third - first for first, _, third in triples])

    chunks = grouped["V04_CHUNK"]
    if not chunks:
        raise ValueError("missing chunk population")
    chunk_pairs: dict[int, list[dict[str, str]]] = defaultdict(list)
    chunk_order: list[int] = []
    for record in chunks:
        chunk_id = _number(record, "chunk_id", positive=True)
        if chunk_id not in chunk_pairs:
            chunk_order.append(chunk_id)
        chunk_pairs[chunk_id].append(record)
    for expected, chunk_id in enumerate(chunk_order, 1):
        if chunk_id != expected:
            raise ValueError(f"chunk chunk_id {chunk_id} out of order; expected {expected}")
    if len(chunk_order) < min_chunks:
        raise ValueError(f"chunk count {len(chunk_order)} < {min_chunks}")
    previous_end = None
    durations = []
    for chunk_id in chunk_order:
        pair = chunk_pairs[chunk_id]
        if [record["stage"] for record in pair] != ["start", "end"]:
            raise ValueError(f"chunk_id {chunk_id} must have one ordered start/end pair")
        start, end = (_number(record, "ts_ns") for record in pair)
        if end < start or previous_end is not None and start < previous_end:
            raise ValueError(f"chunk_id {chunk_id} is non-monotonic")
        if previous_end is not None and start - previous_end > max_chunk_gap_ns:
            raise ValueError(f"chunk gap {start - previous_end} > {max_chunk_gap_ns} ns")
        previous_end = end
        durations.append(end - start)
    report["chunk_duration_ns"] = stats(durations)

    heartbeats = grouped["V04_HEARTBEAT"]
    if require_heartbeat and not heartbeats:
        raise ValueError("missing heartbeat population")
    if heartbeats:
        if max_heartbeat_gap_ns is None or max_heartbeat_gap_ns < 0:
            raise ValueError("heartbeats require --max-heartbeat-gap-ns")
        times = [_number(record, "ts_ns") for record in heartbeats]
        if any(later <= earlier for earlier, later in zip(times, times[1:])):
            raise ValueError("heartbeat timestamps are not strictly increasing")
        gaps = [later - earlier for earlier, later in zip(times, times[1:])]
        if any(gap > max_heartbeat_gap_ns for gap in gaps):
            raise ValueError(f"heartbeat gap {max(gaps)} > {max_heartbeat_gap_ns} ns")
        report["heartbeat_gap_ns"] = stats(gaps or [0])

    for event in ("V04_LINK_LOSS", "V04_ESTOP"):
        if grouped[event]:
            _ids(grouped[event], "event_id", event)
    estops = grouped["V04_ESTOP"]
    if require_estop and not estops:
        raise ValueError("missing e-stop population")
    if estops:
        if len(estops) < min_estop_samples:
            raise ValueError(f"e-stop count {len(estops)} < {min_estop_samples}")
        report["e_stop_events"] = stats([_number(record, "ts_ns") for record in estops])
    return report


def campaign_logs(directory: Path) -> list[Path]:
    paths = sorted(path for path in directory.rglob("*") if path.is_file() and path.suffix.lower() in LOG_SUFFIXES)
    if not paths:
        raise ValueError(f"{directory}: no retained serial/log inputs")
    return paths


class AnalyzerSelfTest(unittest.TestCase):
    def valid(self) -> str:
        lines = ["V04_CHUNK chunk_id=1 stage=start ts_ns=1"]
        for base, name in ((100, "stop"), (150, "drive")):
            lines += [f"V04_BEHAVIOR sample_id=1 behavior={name} stage={stage} ts_ns={base + i * 10}" for i, stage in enumerate(STAGES)]
        lines += ["V04_ECHO_DONE sample_id=1 echo_us=10 ts_ns=210", "V04_HOOK_ENTRY sample_id=1 ts_ns=220", "V04_MOTOR_CMD sample_id=1 seq=1 left=-32768 right=32767 ts_ns=230", "V04_CHUNK chunk_id=1 stage=end ts_ns=300"]
        return "\n".join(lines)

    def run_valid(self, text: str | None = None, **kwargs: int) -> dict[str, dict[str, int]]:
        defaults = {"min_behavior_samples": 1, "min_latency_samples": 1, "min_estop_samples": 0, "max_chunk_gap_ns": 1_000, "require_heartbeat": False, "require_estop": False}
        defaults.update(kwargs)
        return analyze(text or self.valid(), **defaults)

    def test_valid_lifecycle_correlation_and_nearest_rank(self):
        report = self.run_valid()
        self.assertEqual(set(report["behavior:stop"]), set(STAT_KEYS))
        self.assertEqual(report["echo_to_motor_ns"]["max"], 20)
        self.assertEqual(stats([1, 2, 3, 4, 5]), {"count": 5, "min": 1, "median": 3, "p95": 5, "p99": 5, "p99.9": 5, "max": 5})

    def test_missing_duplicate_and_out_of_order_lifecycle_fail(self):
        for old, new in (("stage=admit", "stage=nope"), ("stage=admit", "stage=verify"), ("stage=verify ts_ns=120", "stage=verify ts_ns=140")):
            with self.subTest(new=new), self.assertRaises(ValueError): self.run_valid(self.valid().replace(old, new, 1))

    def test_required_populations_and_limits_fail(self):
        with self.assertRaisesRegex(ValueError, "missing echo"): self.run_valid("\n".join(line for line in self.valid().splitlines() if "V04_ECHO" not in line))
        with self.assertRaisesRegex(ValueError, "missing chunk"): self.run_valid("\n".join(line for line in self.valid().splitlines() if "V04_CHUNK" not in line))
        with self.assertRaisesRegex(ValueError, "chunks require"): analyze(self.valid(), min_behavior_samples=1, min_latency_samples=1)
        with self.assertRaisesRegex(ValueError, "missing heartbeat"): self.run_valid(require_heartbeat=True)
        with self.assertRaisesRegex(ValueError, "missing e-stop"): self.run_valid(require_estop=True, min_estop_samples=1)

    def test_source_order_schemas_chunks_and_heartbeat_fail(self):
        with self.assertRaisesRegex(ValueError, "timestamp decreases"): self.run_valid(self.valid().replace("ts_ns=230", "ts_ns=205"))
        with self.assertRaisesRegex(ValueError, "unknown"): self.run_valid(self.valid() + "\nV04_UNKNOWN ts_ns=400")
        with self.assertRaisesRegex(ValueError, "schema"): self.run_valid(self.valid().replace("seq=1 left=-32768 right=32767 ", ""))
        with self.assertRaisesRegex(ValueError, "chunk_id"): self.run_valid(self.valid().replace("chunk_id=1 stage=end", "chunk_id=2 stage=end"))
        beats = "\nV04_HEARTBEAT seq=65535 ts_ns=310\nV04_HEARTBEAT seq=0 ts_ns=320"
        self.run_valid(self.valid() + beats, require_heartbeat=True, max_heartbeat_gap_ns=10)
        with self.assertRaisesRegex(ValueError, "heartbeat gap"): self.run_valid(self.valid() + beats, max_heartbeat_gap_ns=9)

    def test_sensor_ids_panic_and_campaign_discovery_fail(self):
        with self.assertRaisesRegex(ValueError, "out of order"):
            self.run_valid(self.valid().replace("V04_ECHO_DONE sample_id=1", "V04_ECHO_DONE sample_id=2"))
        with self.assertRaisesRegex(ValueError, "panic/fatal"):
            self.run_valid(self.valid() + "\nV04_PANIC kind=panic")
        with self.assertRaisesRegex(ValueError, "no retained"):
            with mock.patch.object(Path, "rglob", return_value=[]): campaign_logs(Path("empty"))

    def test_duplicate_safety_transition_fails(self):
        text = self.valid() + "\nV04_ESTOP event_id=1 source=operator stage=assert ts_ns=310\nV04_ESTOP event_id=1 source=operator stage=assert ts_ns=320"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_valid(text, require_estop=True, min_estop_samples=1)

    def test_motor_values_are_signed_i16_and_range_checked(self):
        records = parse(self.valid())
        motor = next(record for record in records if record["_event"] == "V04_MOTOR_CMD")
        self.assertEqual(motor["left"], "-32768")
        for value in ("-32769", "32768"):
            with self.assertRaisesRegex(ValueError, "left"):
                parse(self.valid().replace("left=-32768", f"left={value}"))

    def test_failure_and_per_stream_timestamps_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "failure"):
            self.run_valid(self.valid() + "\nV04_FAILURE reason=input_overflow count=1 ts_ns=310")
        empty_service = parse(
            "V04_CHUNK chunk_id=1 stage=start ts_ns=1\n"
            "V04_FAILURE reason=link_uninitialized count=1 ts_ns=1\n"
            "V04_CHUNK chunk_id=1 stage=end ts_ns=2"
        )
        self.assertEqual([record["stage"] for record in empty_service if record["_event"] == "V04_CHUNK"], ["start", "end"])
        with self.assertRaisesRegex(ValueError, "zero count"):
            parse("V04_FAILURE reason=input_overflow count=0 ts_ns=1")
        with self.assertRaisesRegex(ValueError, "timestamp decreases"):
            parse("V04_ECHO_DONE sample_id=1 echo_us=1 ts_ns=2\nV04_ECHO_DONE sample_id=2 echo_us=1 ts_ns=1")
        # Campaign files have independent timestamp origins; validate each file
        # before combining their populations.
        self.assertEqual(len(parse(self.valid())), len(parse(self.valid())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--serial", type=Path, action="append", default=[])
    parser.add_argument("--min-behavior-samples", type=int, default=100)
    parser.add_argument("--min-latency-samples", type=int, default=1000)
    parser.add_argument("--min-chunks", type=int, default=1)
    parser.add_argument("--fixture", action="store_true", help="non-acceptance focused fixture mode")
    parser.add_argument("--min-estop-samples", type=int, default=100)
    parser.add_argument("--max-heartbeat-gap-ns", type=int)
    parser.add_argument("--max-chunk-gap-ns", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        return int(not result.result.wasSuccessful())
    require_heartbeat = not args.fixture
    require_estop = not args.fixture
    contract = f"V04 CONTRACT mode={'fixture-non-acceptance' if args.fixture else 'acceptance'} behavior_min={args.min_behavior_samples} latency_min={args.min_latency_samples} chunk_min={args.min_chunks} heartbeat_required={require_heartbeat} heartbeat_gap_ns={args.max_heartbeat_gap_ns} estop_required={require_estop} estop_min={args.min_estop_samples} chunk_gap_ns={args.max_chunk_gap_ns}"
    print(contract)
    try:
        paths = sorted(args.serial) + (campaign_logs(args.campaign) if args.campaign else [])
        if not paths: raise ValueError("provide --campaign or --serial")
        report = analyze([path.read_text(encoding="utf-8") for path in paths], min_behavior_samples=args.min_behavior_samples, min_latency_samples=args.min_latency_samples, min_chunks=args.min_chunks, require_heartbeat=require_heartbeat, require_estop=require_estop, min_estop_samples=args.min_estop_samples, max_heartbeat_gap_ns=args.max_heartbeat_gap_ns, max_chunk_gap_ns=args.max_chunk_gap_ns)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"V04 FAIL: {error}")
        return 1
    for name, values in report.items(): print(name + ": " + " ".join(f"{key}={values[key]}" for key in STAT_KEYS))
    print("V04 PASS: serial boundaries only; debug-GPIO/FPGA physical latency remains pending")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
