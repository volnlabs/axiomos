#!/usr/bin/env python3
"""Strict initial v0.5 JSONL reducer for trace integrity and cycle timing.

Input is UTF-8 JSONL: one ``header``, typed events with contiguous ``seq`` and
nondecreasing integer ``ticks``, then one ``terminal``. Exact event fields are
listed by ``--describe``. ``--expectations FILE`` supplies independent exact
event/outcome counts and a contiguous release range per boot.

Examples::

  python3 scripts/benchmark/analyze-v05.py --describe
  python3 scripts/benchmark/analyze-v05.py --self-test
  python3 scripts/benchmark/analyze-v05.py --expectations expected.json trace.jsonl
  python3 scripts/benchmark/analyze-v05.py --show-acceptance

This initial reducer does not implement physical, fault-matrix, recorder-cost,
or reclamation gates, so it cannot emit a v0.5 release PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ACCEPTANCE = ROOT / "docs/performance/v0.5-acceptance.json"
TRACE_SCHEMA = "axiomos.v05.trace.v1"
EXPECTATIONS_SCHEMA = "axiomos.v05.expectations.v1"
OUTCOMES = ("successful", "failed", "rejected", "canceled")

FIELDS = {
    "operation_request": {"seq", "ticks", "operation_id", "operation", "generation", "artifact_id"},
    "operation_accepted": {"seq", "ticks", "operation_id", "generation", "artifact_id"},
    "handoff_enter": {"seq", "ticks", "operation_id", "generation", "artifact_id"},
    "sink_safe_ready": {"seq", "ticks", "operation_id", "generation", "artifact_id"},
    "operation_committed": {"seq", "ticks", "operation_id", "cycle", "generation", "artifact_id"},
    "operation_response": {"seq", "ticks", "operation_id", "outcome"},
    "cycle_release": {"seq", "ticks", "cycle", "scheduled_ticks", "mode", "generation"},
    "behavior_enter": {"seq", "ticks", "cycle", "generation", "artifact_id"},
    "behavior_exit": {"seq", "ticks", "cycle", "generation", "artifact_id"},
    "cycle_complete": {"seq", "ticks", "cycle", "mode", "generation"},
}
HEADER_FIELDS = {"type", "schema", "evidence_kind", "boot_id", "clock_hz", "source_id", "artifact_id", "acceptance_config_sha256"}
TERMINAL_FIELDS = {"type", "seq", "ticks", "event_count", "last_event_seq"}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def parse_json(text: str):
    try:
        return json.loads(text, object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON number {value}")))
    except json.JSONDecodeError as error:
        raise ValueError(f"malformed JSON: {error.msg}") from None


def load_json(path: Path):
    return parse_json(path.read_text(encoding="utf-8"))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_jsonl(text: str) -> list[dict]:
    if not text or not text.endswith("\n"):
        raise ValueError("truncated JSONL: final newline missing")
    rows = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ValueError(f"line {line_no}: empty record")
        value = parse_json(line)
        if not isinstance(value, dict):
            raise ValueError(f"line {line_no}: record must be an object")
        rows.append(value)
    return rows


def _integer(record: dict, key: str, *, positive: bool = False) -> int:
    value = record.get(key)
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError(f"{record.get('type')}: invalid {key}")
    return value


def _identity(value, key):
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid {key}")


def _one_of(value, allowed) -> bool:
    return isinstance(value, str) and value in allowed


def _at_or_over_ns(delta_ticks: int, limit_ns: int, clock_hz: int) -> bool:
    return delta_ticks * 1_000_000_000 >= limit_ns * clock_hz


def _over_ns(delta_ticks: int, limit_ns: int, clock_hz: int) -> bool:
    return delta_ticks * 1_000_000_000 > limit_ns * clock_hz


def _validate_acceptance(value: dict) -> None:
    if not isinstance(value, dict) or value.get("schema") != "axiomos.v05.acceptance.v1":
        raise ValueError("acceptance schema mismatch")
    for section, keys in (("cpu", ("period_ns",)), ("timing", ("handoff_timeout_ns",))):
        fields = value.get(section)
        if not isinstance(fields, dict) or any(type(fields.get(key)) is not int or fields[key] <= 0 for key in keys):
            raise ValueError(f"malformed acceptance {section}")
    if not isinstance(value.get("required_gates"), dict):
        raise ValueError("malformed acceptance required_gates")
    for gate in value["required_gates"].values():
        if not isinstance(gate, dict) or type(gate.get("required")) is not bool or type(gate.get("implemented_by_reducer")) is not bool or (not gate["implemented_by_reducer"] and not _one_of(gate.get("missing_policy"), {"blocked", "not_evaluated"})):
            raise ValueError("malformed acceptance required_gates")


def reduce_records(rows: list[dict], expectations: dict, acceptance: dict, config_digest: str) -> dict:
    _validate_acceptance(acceptance)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("trace records must be objects")
    if len(rows) < 3 or rows[0].get("type") != "header" or rows[-1].get("type") != "terminal":
        raise ValueError("trace requires header, events, and terminal")
    header, terminal, events = rows[0], rows[-1], rows[1:-1]
    if set(header) != HEADER_FIELDS or header["schema"] != TRACE_SCHEMA or not _one_of(header.get("evidence_kind"), {"synthetic", "physical"}):
        raise ValueError("header schema mismatch")
    _identity(header.get("boot_id"), "boot_id")
    if not isinstance(header.get("source_id"), str) or len(header["source_id"]) != 40 or any(c not in "0123456789abcdef" for c in header["source_id"]):
        raise ValueError("source_id must be a lowercase SHA-1")
    if not isinstance(header.get("artifact_id"), str) or len(header["artifact_id"]) != 64 or any(c not in "0123456789abcdef" for c in header["artifact_id"]):
        raise ValueError("artifact_id must be a lowercase SHA-256")
    _identity(header.get("acceptance_config_sha256"), "acceptance_config_sha256")
    clock_hz = _integer(header, "clock_hz", positive=True)
    if header["acceptance_config_sha256"] != config_digest:
        raise ValueError("wrong acceptance config hash")
    if set(terminal) != TERMINAL_FIELDS:
        raise ValueError("terminal schema mismatch")

    previous_ticks = -1
    for expected_seq, event in enumerate(events, 1):
        kind = event.get("type")
        if not isinstance(kind, str) or kind not in FIELDS or set(event) != FIELDS[kind] | {"type"}:
            raise ValueError(f"unknown event shape {kind!r}")
        if _integer(event, "seq", positive=True) != expected_seq:
            raise ValueError(f"event seq is duplicate, missing, or reordered at {expected_seq}")
        ticks = _integer(event, "ticks")
        if ticks < previous_ticks:
            raise ValueError("event ticks decrease")
        previous_ticks = ticks
        for key in FIELDS[kind] & {"operation_id", "cycle", "generation"}:
            _integer(event, key, positive=True)
        if "scheduled_ticks" in event:
            _integer(event, "scheduled_ticks")
        if "artifact_id" in event:
            if not isinstance(event["artifact_id"], str) or len(event["artifact_id"]) != 64 or any(c not in "0123456789abcdef" for c in event["artifact_id"]):
                raise ValueError("artifact_id must be a lowercase SHA-256")
        if "mode" in event and not _one_of(event["mode"], {"controller", "safe"}):
            raise ValueError("invalid cycle mode")
        if kind == "operation_request" and not _one_of(event["operation"], {"activate", "rollback"}):
            raise ValueError("invalid operation")
        if kind == "operation_response" and not _one_of(event["outcome"], OUTCOMES):
            raise ValueError("invalid operation outcome")
    if _integer(terminal, "seq", positive=True) != len(events) + 1 or _integer(terminal, "event_count") != len(events) or _integer(terminal, "last_event_seq") != len(events):
        raise ValueError("terminal does not prove the complete expected event count")
    if _integer(terminal, "ticks") < previous_ticks:
        raise ValueError("terminal ticks decrease")

    if not isinstance(expectations, dict) or expectations.get("schema") != EXPECTATIONS_SCHEMA or expectations.get("acceptance_config_sha256") != config_digest:
        raise ValueError("expectations schema or config hash mismatch")
    boots = expectations.get("boots")
    if not isinstance(boots, dict):
        raise ValueError("malformed expectations boots")
    boot_expected = boots.get(header["boot_id"])
    if not isinstance(boot_expected, dict):
        raise ValueError("missing workload expectations for boot")
    if boot_expected.get("source_id") != header["source_id"] or boot_expected.get("artifact_id") != header["artifact_id"]:
        raise ValueError("expected boot identity does not match trace")
    expected_counts = boot_expected.get("event_counts")
    if not isinstance(expected_counts, dict) or any(type(value) is not int or value < 0 or value > len(events) for value in expected_counts.values()):
        raise ValueError("malformed expectations event counts")
    actual_counts = dict(sorted(Counter(event["type"] for event in events).items()))
    if actual_counts != expected_counts:
        raise ValueError("event counts do not match expectations")
    actual_outcomes = {name: 0 for name in OUTCOMES}
    requests = {}
    responses = set()
    for event in events:
        if event["type"] == "operation_request":
            if event["operation_id"] in requests:
                raise ValueError("duplicate operation request")
            requests[event["operation_id"]] = event
        elif event["type"] == "operation_response":
            if event["operation_id"] in responses or event["operation_id"] not in requests:
                raise ValueError("missing request or duplicate workload response")
            responses.add(event["operation_id"])
            actual_outcomes[event["outcome"]] += 1
    expected_outcomes = boot_expected.get("operation_outcomes")
    if not isinstance(expected_outcomes, dict) or set(expected_outcomes) != set(OUTCOMES) or any(type(value) is not int or value < 0 or value > len(events) for value in expected_outcomes.values()):
        raise ValueError("malformed expectations operation outcomes")
    if actual_outcomes != expected_outcomes:
        raise ValueError("operation outcomes do not match expectations")
    unfinished = len(set(requests) - responses)
    if unfinished:
        raise ValueError(f"missing workload response for {unfinished} operation(s)")

    releases = [event for event in events if event["type"] == "cycle_release"]
    coverage = boot_expected.get("release_cycles")
    if not isinstance(coverage, dict):
        raise ValueError("malformed expectations release coverage")
    first, count = coverage.get("first"), coverage.get("count")
    if type(first) is not int or first < 1 or type(count) is not int or count < 0 or count > len(events):
        raise ValueError("malformed expectations release coverage")
    if len(releases) != count or any(event["cycle"] != first + index for index, event in enumerate(releases)):
        raise ValueError("cycle release coverage does not match expectations")
    period_ns = acceptance["cpu"]["period_ns"]
    for earlier, later in zip(releases, releases[1:]):
        if (later["scheduled_ticks"] - earlier["scheduled_ticks"]) * 1_000_000_000 != period_ns * clock_hz:
            raise ValueError("scheduled releases are not exactly one period apart")

    cycles = {}
    for event in events:
        if event["type"] == "cycle_release":
            if event["cycle"] in cycles:
                raise ValueError(f"cycle {event['cycle']} has duplicate release")
            cycles[event["cycle"]] = [event]
        elif event["type"] in {"behavior_enter", "behavior_exit", "cycle_complete"}:
            if event["cycle"] not in cycles:
                raise ValueError(f"cycle {event['cycle']} has no release")
            cycles[event["cycle"]].append(event)
    for cycle, lifecycle in cycles.items():
        release, complete = lifecycle[0], lifecycle[-1]
        expected_lifecycle = ["cycle_release", "cycle_complete"] if release["mode"] == "safe" else ["cycle_release", "behavior_enter", "behavior_exit", "cycle_complete"]
        if [event["type"] for event in lifecycle] != expected_lifecycle:
            raise ValueError(f"cycle {cycle} lifecycle incomplete or reordered")
        if len({event["generation"] for event in lifecycle}) != 1:
            raise ValueError(f"cycle {cycle} has mixed generations")
        if complete["mode"] != release["mode"]:
            raise ValueError(f"cycle {cycle} mode mismatch")
        if release["ticks"] < release["scheduled_ticks"] or _at_or_over_ns(complete["ticks"] - release["scheduled_ticks"], period_ns, clock_hz):
            raise ValueError(f"cycle {cycle} deadline violation")
        if release["mode"] == "controller" and lifecycle[1]["artifact_id"] != lifecycle[2]["artifact_id"]:
            raise ValueError(f"cycle {cycle} artifact identity mismatch")

    by_operation = {}
    for event in events:
        if "operation_id" in event:
            if event["type"] in by_operation.setdefault(event["operation_id"], {}):
                raise ValueError(f"duplicate {event['type']} for operation {event['operation_id']}")
            by_operation.setdefault(event["operation_id"], {})[event["type"]] = event
    handoff = 0
    commits_by_cycle = {}
    # ponytail: per-operation scans suit bounded host fixtures; index by identity
    # and readiness tick before admitting soak-scale traces.
    for operation_id, grouped in by_operation.items():
        request, response = grouped.get("operation_request"), grouped.get("operation_response")
        if request is None:
            raise ValueError(f"operation {operation_id} stage has no request")
        if response is None:
            raise ValueError(f"operation {operation_id} missing workload response")
        stages = ("operation_accepted", "handoff_enter", "sink_safe_ready", "operation_committed")
        if response["outcome"] in {"failed", "rejected", "canceled"}:
            if "operation_committed" in grouped:
                raise ValueError(f"unsuccessful operation {operation_id} committed")
            intermediate = [name for name in ("operation_accepted", "handoff_enter", "sink_safe_ready") if name in grouped]
            if intermediate != list(("operation_accepted", "handoff_enter", "sink_safe_ready")[:len(intermediate)]):
                raise ValueError(f"unsuccessful operation {operation_id} has invalid stage prefix")
            prior = request
            for name in intermediate:
                stage = grouped[name]
                if prior["seq"] >= stage["seq"] or stage["seq"] >= response["seq"] or (stage["generation"], stage["artifact_id"]) != (request["generation"], request["artifact_id"]):
                    raise ValueError(f"unsuccessful operation {operation_id} has invalid stage prefix")
                prior = stage
            if any(event["type"] == "behavior_enter" and event["seq"] > request["seq"] and
                   (event["generation"], event["artifact_id"]) == (request["generation"], request["artifact_id"])
                   for event in events):
                raise ValueError(f"unsuccessful operation {operation_id} candidate entered")
            continue
        if request["operation"] in {"activate", "rollback"}:
            if any(stage not in grouped for stage in stages):
                raise ValueError(f"operation {operation_id} missing handoff stage")
            ordered = [request, *(grouped[stage] for stage in stages), response]
            if any(a["seq"] >= b["seq"] for a, b in zip(ordered, ordered[1:])):
                raise ValueError(f"operation {operation_id} handoff stages reordered")
            identity = (request["generation"], request["artifact_id"])
            if any((grouped[stage]["generation"], grouped[stage]["artifact_id"]) != identity for stage in stages):
                raise ValueError(f"operation {operation_id} handoff identity mismatch")
            commit = grouped["operation_committed"]
            if _over_ns(commit["ticks"] - grouped["handoff_enter"]["ticks"], acceptance["timing"]["handoff_timeout_ns"], clock_hz):
                raise ValueError(f"operation {operation_id} handoff timeout")
            ready = grouped["sink_safe_ready"]
            eligible = next((release for release in releases if release["scheduled_ticks"] > ready["ticks"] or
                             release["scheduled_ticks"] == ready["ticks"] and release["seq"] > ready["seq"]), None)
            if eligible is None or commit["cycle"] != eligible["cycle"] or not (eligible["seq"] < commit["seq"]):
                raise ValueError(f"operation {operation_id} did not commit at next eligible release")
            first_use = next((event for event in cycles.get(commit["cycle"], ()) if event["type"] == "behavior_enter"), None)
            if first_use is None or (first_use["generation"], first_use["artifact_id"]) != identity or not (commit["seq"] < first_use["seq"] < response["seq"]):
                raise ValueError(f"operation {operation_id} committed generation identity mismatch")
            if commit["cycle"] in commits_by_cycle:
                raise ValueError(f"cycle {commit['cycle']} has multiple commits")
            commits_by_cycle[commit["cycle"]] = identity
            handoff += 1

    active = None
    seen_generations = set()
    for release in releases:
        cycle = release["cycle"]
        if cycle in commits_by_cycle:
            proposed = commits_by_cycle[cycle]
            if proposed[0] in seen_generations:
                raise ValueError("successful commit reused an installation generation")
            active = proposed
            seen_generations.add(proposed[0])
        lifecycle = cycles[cycle]
        if active is None:
            artifact = header["artifact_id"] if release["mode"] == "safe" else lifecycle[1]["artifact_id"]
            if artifact != header["artifact_id"]:
                raise ValueError("initial installation does not match header artifact")
            active = (release["generation"], artifact)
            seen_generations.add(release["generation"])
        observed = (release["generation"], active[1] if release["mode"] == "safe" else lifecycle[1]["artifact_id"])
        if observed != active:
            raise ValueError("installation changed without a successful commit")

    failures = sum(actual_outcomes[name] for name in OUTCOMES if name != "successful")
    gate_results = {name: ("pass" if gate.get("implemented_by_reducer") else gate["missing_policy"])
                    for name, gate in acceptance["required_gates"].items()}
    return {
        "schema": "axiomos.v05.results.v1",
        "trace_verdict": "pass",
        "release_verdict": "blocked",
        "gate_results": gate_results,
        "release_blockers": [name for name, gate in acceptance["required_gates"].items() if gate.get("required") and not gate.get("implemented_by_reducer")],
        "boots": [{"boot_id": header["boot_id"], "evidence_kind": header["evidence_kind"], "source_id": header["source_id"],
                   "artifact_id": header["artifact_id"], "acceptance_config_sha256": header["acceptance_config_sha256"], "event_counts": actual_counts,
                   "operation_outcomes": actual_outcomes, "failures": failures, "unfinished_operations": unfinished,
                   "release_count": len(releases), "handoff_samples": handoff}],
    }


def describe():
    return {"trace_schema": TRACE_SCHEMA, "expectations_schema": EXPECTATIONS_SCHEMA,
            "header_fields": sorted(HEADER_FIELDS), "event_fields": {key: sorted(value | {"type"}) for key, value in sorted(FIELDS.items())},
            "terminal_fields": sorted(TERMINAL_FIELDS), "implemented_checks": ["JSON and exact record shapes", "expected SHA identity/config binding", "sequence and tick order", "independent bounded exact counts/outcomes/release coverage", "controller/safe cycle lifecycle, generation, schedule, and deadline", "handoff-enter to next eligible release/commit timeout and first-use identity"],
            "unsupported_events": ["policy request", "enqueue", "sink acknowledgment"],
            "unsupported_operations": ["retire", "deactivate", "administrative lifecycle operations"],
            "expectations_shape": {"schema": EXPECTATIONS_SCHEMA, "acceptance_config_sha256": "lowercase SHA-256", "boots": {"<boot_id>": {"source_id": "lowercase SHA-1", "artifact_id": "lowercase SHA-256 of initial installation", "event_counts": "exact nonnegative integer counts by event type", "operation_outcomes": "exact successful/failed/rejected/canceled integer counts", "release_cycles": {"first": "positive integer", "count": "bounded nonnegative integer"}}}},
            "operation_generation_semantics": "requested candidate installation generation; installed only after successful commit and matching first behavior entry",
            "gate_scope": "host trace subset; not an end-to-end acceptance gate",
            "release_pass_supported": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, default=DEFAULT_ACCEPTANCE)
    parser.add_argument("--expectations", type=Path)
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--show-acceptance", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("trace", nargs="?", type=Path)
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(), sort_keys=True, indent=2)); return 0
    if args.show_acceptance:
        print(json.dumps(load_json(args.acceptance), sort_keys=True, indent=2)); return 0
    if args.self_test:
        import unittest
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/scripts"), pattern="test_v05_reducer.py")
        result = unittest.TextTestRunner(stream=sys.stderr).run(suite)
        print(json.dumps({"schema": "axiomos.v05.self-test.v1", "successful": result.wasSuccessful(), "tests_run": result.testsRun}, sort_keys=True))
        return int(not result.wasSuccessful())
    if not args.trace or not args.expectations:
        parser.error("trace and --expectations are required")
    try:
        acceptance = load_json(args.acceptance)
        result = reduce_records(parse_jsonl(args.trace.read_text(encoding="utf-8")), load_json(args.expectations), acceptance, file_sha256(args.acceptance))
        result["input_sha256"] = {"trace": file_sha256(args.trace), "expectations": file_sha256(args.expectations)}
    except (OSError, UnicodeError, ValueError) as error:
        print(json.dumps({"schema": "axiomos.v05.results.v1", "trace_verdict": "fail", "release_verdict": "blocked", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
