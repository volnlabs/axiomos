#!/usr/bin/env python3
"""Reduce raw hosted update-cost records without hiding scheduler noise."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

PROTOCOLS = ("atomic", "guarded")
HOLDS_US = (0, 10, 100, 500)
RESOURCE_PHASES = ("one_program", "two_loaded", "after_replace", "after_cleanup")
RECORD_KINDS = {"meta", "clock", "resource", "update", "dispatch",
                "controlled_transition", "end"}


def stats(values: list[int]) -> dict[str, int] | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = lambda q: ordered[math.ceil(q * len(ordered)) - 1]
    return {"count": len(values), "median": rank(0.5), "p99": rank(0.99), "max": ordered[-1]}


def _nonnegative(record: dict, key: str) -> int:
    value = record.get(key)
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{record.get('kind')} has invalid {key}")
    return value


def _summarize_run(key: tuple[str, int, int], records: list[dict], expected_attempts: int) -> dict:
    protocol, hold_us, run_number = key
    grouped: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        grouped[record.get("kind")].append(record)
    if len(grouped["meta"]) != 1 or len(grouped["end"]) != 1:
        raise ValueError(f"{key}: expected one meta and end record")
    meta, end = grouped["meta"][0], grouped["end"][0]
    if len(grouped["clock"]) != 1000:
        raise ValueError(f"{key}: expected 1000 clock samples")
    expected_controlled = 100 if protocol == "guarded" else 0
    if len(grouped["controlled_transition"]) != expected_controlled:
        raise ValueError(f"{key}: expected {expected_controlled} controlled transition samples")
    if meta.get("attempts") != expected_attempts or meta.get("period_ns") != 1_000_000:
        raise ValueError(f"{key}: measurement contract mismatch")
    if not isinstance(meta.get("warmup"), int) or meta["warmup"] < 0:
        raise ValueError(f"{key}: invalid warmup")
    _nonnegative(meta, "clock_resolution_ns")
    for field in ("dispatch_cpu", "update_cpu", "dispatch_core", "update_core",
                  "dispatch_package", "update_package"):
        _nonnegative(meta, field)
    if meta["dispatch_cpu"] == meta["update_cpu"] or (
        meta["dispatch_core"], meta["dispatch_package"]
    ) == (meta["update_core"], meta["update_package"]):
        raise ValueError(f"{key}: measurement threads do not use distinct physical cores")
    if meta.get("resource_label") != "manager-accounted resident bytecode bytes":
        raise ValueError(f"{key}: ambiguous resource label")

    updates = grouped["update"]
    if len(updates) != expected_attempts:
        raise ValueError(f"{key}: {len(updates)} update attempts, expected {expected_attempts}")
    logical, retry = 0, 1
    successes = busy = first_successes = 0
    replace_ok: list[int] = []
    replace_busy: list[int] = []
    update_lateness: list[int] = []
    for attempt, record in enumerate(updates):
        if record.get("attempt") != attempt or record.get("logical_update") != logical or record.get("retry_ordinal") != retry:
            raise ValueError(f"{key}: invalid retry sequence at attempt {attempt}")
        latency = _nonnegative(record, "latency_ns")
        scheduled_offset = _nonnegative(record, "scheduled_offset_ns")
        started_offset = _nonnegative(record, "started_offset_ns")
        expected_offset = attempt * 1_000_000 + ((137 * attempt + 97 * run_number) % 1_000) * 1_000
        if scheduled_offset != expected_offset or started_offset < scheduled_offset:
            raise ValueError(f"{key}: invalid absolute phase schedule at attempt {attempt}")
        lateness_ns = _nonnegative(record, "lateness_ns")
        if lateness_ns != started_offset - scheduled_offset:
            raise ValueError(f"{key}: update lateness disagrees with schedule")
        update_lateness.append(lateness_ns)
        outcome = record.get("outcome")
        if outcome == "Ok":
            successes += 1
            first_successes += retry == 1
            replace_ok.append(latency)
            logical += 1
            retry = 1
        elif outcome == "Busy" and protocol == "guarded":
            busy += 1
            replace_busy.append(latency)
            retry += 1
        else:
            raise ValueError(f"{key}: unexpected update outcome {outcome!r}")

    dispatches = grouped["dispatch"]
    last_scheduled = -1
    dispatch_ok: list[int] = []
    entry: list[int] = []
    release: list[int] = []
    lateness: list[int] = []
    actual_hold: list[int] = []
    transition_busy: list[int] = []
    execution_busy: list[int] = []
    empty = 0
    for record in dispatches:
        scheduled = _nonnegative(record, "scheduled")
        if scheduled <= last_scheduled:
            raise ValueError(f"{key}: dispatch schedule is not strictly increasing")
        last_scheduled = scheduled
        dispatch_lateness = _nonnegative(record, "lateness_ns")
        if dispatch_lateness >= meta["period_ns"]:
            raise ValueError(f"{key}: expired dispatch release was executed")
        lateness.append(dispatch_lateness)
        call = _nonnegative(record, "call_ns")
        outcome = record.get("outcome")
        if outcome == "Ok":
            for field in ("entry_ns", "release_ns", "actual_hold_ns"):
                _nonnegative(record, field)
            dispatch_ok.append(call)
            entry.append(record["entry_ns"])
            release.append(record["release_ns"])
            actual_hold.append(record["actual_hold_ns"])
        elif outcome == "TransitionBusy" and protocol == "guarded":
            transition_busy.append(call)
        elif outcome == "ExecutionBusy" and protocol == "guarded":
            execution_busy.append(call)
        elif outcome == "Empty":
            empty += 1
        else:
            raise ValueError(f"{key}: unexpected dispatch outcome {outcome!r}")

    resources = {record.get("phase"): record for record in grouped["resource"]}
    if (tuple(phase for phase in RESOURCE_PHASES if phase in resources) != RESOURCE_PHASES
            or len(resources) != len(RESOURCE_PHASES)):
        raise ValueError(f"{key}: incomplete resource observations")
    for phase, expected_live in (("one_program", 1), ("two_loaded", 2),
                                 ("after_replace", 2), ("after_cleanup", 0)):
        if resources[phase].get("live_programs") != expected_live:
            raise ValueError(f"{key}: invalid {phase} live-program count")
        _nonnegative(resources[phase], "program_bytes")
    if resources["two_loaded"]["program_bytes"] != resources["after_replace"]["program_bytes"]:
        raise ValueError(f"{key}: resident program accounting changed during replacement")
    if resources["after_cleanup"]["program_bytes"] != 0:
        raise ValueError(f"{key}: resident program accounting did not clear")

    scheduled_releases = _nonnegative(end, "scheduled_releases")
    dispatch_attempts = _nonnegative(end, "dispatch_attempts")
    missed = _nonnegative(end, "missed_releases")
    if dispatch_attempts != len(dispatches) or scheduled_releases != dispatch_attempts + missed:
        raise ValueError(f"{key}: dispatch denominator mismatch")
    observed_skips = len(transition_busy) + len(execution_busy) + empty
    counter_skips = sum(_nonnegative(end, name) for name in
                        ("transition_busy_skips", "execution_busy_skips", "empty_skips"))
    if protocol == "guarded" and observed_skips != counter_skips:
        raise ValueError(f"{key}: observer outcomes disagree with slot counters")
    if protocol == "atomic" and counter_skips:
        raise ValueError(f"{key}: atomic baseline reported guarded skips")

    controlled = [_nonnegative(record, "latency_ns") for record in grouped["controlled_transition"]]
    if protocol == "atomic" and controlled:
        raise ValueError(f"{key}: atomic baseline has controlled transition samples")
    logical_started = logical + (retry > 1)
    return {
        "protocol": protocol, "hold_us": hold_us, "run": run_number,
        "attempts": len(updates), "successful_updates": successes, "busy_updates": busy,
        "logical_updates_started": logical_started, "first_attempt_successes": first_successes,
        "dispatch_attempts": dispatch_attempts, "scheduled_releases": scheduled_releases,
        "missed_releases": missed, "transition_busy_skips": len(transition_busy),
        "execution_busy_skips": len(execution_busy), "empty_skips": empty,
        "skips_per_successful_update": observed_skips / successes if successes else None,
        "first_attempt_success_rate": first_successes / logical_started if logical_started else None,
        "update_success_rate": successes / len(updates),
        "program_bytes_one": resources["one_program"]["program_bytes"],
        "program_bytes_two": resources["two_loaded"]["program_bytes"],
        "latency_ns": {
            "clock": stats([_nonnegative(record, "latency_ns") for record in grouped["clock"]]),
            "replace_ok": stats(replace_ok), "replace_busy": stats(replace_busy),
            "update_lateness": stats(update_lateness),
            "dispatch_ok": stats(dispatch_ok), "entry": stats(entry), "release": stats(release),
            "transition_busy": stats(transition_busy), "execution_busy": stats(execution_busy),
            "controlled_transition": stats(controlled), "lateness": stats(lateness),
            "actual_hold": stats(actual_hold),
        },
    }


def analyze(records: list[dict], *, expected_attempts: int = 1000, expected_runs: int = 10,
            expected_holds: tuple[int, ...] = HOLDS_US,
            expected_protocols: tuple[str, ...] = PROTOCOLS) -> dict:
    by_run: dict[tuple[str, int, int], list[dict]] = defaultdict(list)
    for record in records:
        if record.get("schema") != 1 or record.get("protocol") not in PROTOCOLS:
            raise ValueError("unknown update-cost schema/protocol")
        if record.get("kind") not in RECORD_KINDS:
            raise ValueError(f"unknown record kind {record.get('kind')!r}")
        hold, run = record.get("hold_us"), record.get("run")
        if not isinstance(hold, int) or hold < 0 or not isinstance(run, int) or run < 0:
            raise ValueError("invalid hold/run identity")
        by_run[(record["protocol"], hold, run)].append(record)
    runs = [_summarize_run(key, by_run[key], expected_attempts) for key in sorted(by_run)]
    if not runs:
        raise ValueError("empty update-cost campaign")
    expected_keys = {(protocol, hold, run) for protocol in expected_protocols
                     for hold in expected_holds for run in range(expected_runs)}
    if set(by_run) != expected_keys:
        missing = sorted(expected_keys - set(by_run))
        extra = sorted(set(by_run) - expected_keys)
        raise ValueError(f"matrix coverage mismatch: missing={missing}, extra={extra}")
    resource_sizes = {(run["program_bytes_one"], run["program_bytes_two"])
                      for run in runs}
    if len(resource_sizes) != 1:
        raise ValueError("manager-accounted resource sizes differ across runs")
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for run in runs:
        groups[(run["protocol"], run["hold_us"])].append(run)
    aggregates = []
    for (protocol, hold), members in sorted(groups.items()):
        if len(members) != expected_runs:
            raise ValueError(f"{protocol}/{hold}: {len(members)} runs, expected {expected_runs}")
        if sorted(member["run"] for member in members) != list(range(expected_runs)):
            raise ValueError(f"{protocol}/{hold}: run identities are incomplete")
        latency = {}
        for metric in runs[0]["latency_ns"]:
            medians = [member["latency_ns"][metric]["median"] for member in members
                       if member["latency_ns"][metric] is not None]
            p99s = [member["latency_ns"][metric]["p99"] for member in members
                    if member["latency_ns"][metric] is not None]
            latency[metric] = None if not medians else {
                "runs_with_samples": len(medians),
                "median_of_run_medians": stats(medians)["median"],
                "run_median_min": min(medians), "run_median_max": max(medians),
                "median_of_run_p99": stats(p99s)["median"],
                "run_p99_min": min(p99s), "run_p99_max": max(p99s),
            }
        total = lambda field: sum(member[field] for member in members)
        aggregates.append({
            "protocol": protocol, "hold_us": hold, "runs": len(members),
            "attempts": total("attempts"), "successful_updates": total("successful_updates"),
            "busy_updates": total("busy_updates"),
            "logical_updates_started": total("logical_updates_started"),
            "first_attempt_successes": total("first_attempt_successes"),
            "dispatch_attempts": total("dispatch_attempts"),
            "scheduled_releases": total("scheduled_releases"),
            "missed_releases": total("missed_releases"),
            "transition_busy_skips": total("transition_busy_skips"),
            "execution_busy_skips": total("execution_busy_skips"),
            "empty_skips": total("empty_skips"), "latency_ns": latency,
        })
    return {"runs": runs, "aggregates": aggregates,
            "denominators": {"replacement": "raw replacement calls",
                             "first_attempt": "logical update sequences started",
                             "dispatch": "dispatch calls attempted",
                             "missed": "scheduled releases",
                             "skips_per_update": "successful replacements"}}


def _fmt_latency(aggregate: dict | None) -> str:
    if aggregate is None:
        return "--"
    return f"{aggregate['median_of_run_medians'] / 1000:.2f}/{aggregate['median_of_run_p99'] / 1000:.2f}"


def write_outputs(report: dict, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "cost-analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    run_fields = [key for key in report["runs"][0] if key != "latency_ns"]
    with (destination / "cost-runs.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=run_fields)
        writer.writeheader()
        writer.writerows({key: run[key] for key in run_fields} for run in report["runs"])
    aggregate_fields = ["protocol", "hold_us", "runs", "attempts", "successful_updates",
                        "busy_updates", "logical_updates_started", "first_attempt_successes",
                        "dispatch_attempts", "scheduled_releases", "missed_releases",
                        "transition_busy_skips", "execution_busy_skips", "empty_skips"]
    with (destination / "cost-summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=aggregate_fields)
        writer.writeheader()
        writer.writerows({key: row[key] for key in aggregate_fields} for row in report["aggregates"])

    indexed = {(row["protocol"], row["hold_us"]): row for row in report["aggregates"]}
    lines = ["% Generated from retained UPDATE_COST records; latency cells are median/p99 across run statistics.\n",
             "\\begin{tabular}{rrrrr}\n", "\\toprule\n",
             "Hold ($\\mu$s) & AP lat. ($\\mu$s) & GR lat. ($\\mu$s) & "
             "GR first try & GR skips/update \\\\\n",
             "\\midrule\n"]
    for hold in sorted({row["hold_us"] for row in report["aggregates"]}):
        atomic = indexed.get(("atomic", hold))
        guarded = indexed.get(("guarded", hold))
        if atomic is None or guarded is None:
            continue
        skips = guarded["transition_busy_skips"] + guarded["execution_busy_skips"] + guarded["empty_skips"]
        skip_ratio = "--" if not guarded["successful_updates"] else f"{skips}/{guarded['successful_updates']}"
        lines.append(f"{hold} & {_fmt_latency(atomic['latency_ns']['replace_ok'])} & "
                     f"{_fmt_latency(guarded['latency_ns']['replace_ok'])} & "
                     f"{guarded['first_attempt_successes']}/{guarded['logical_updates_started']} & "
                     f"{skip_ratio} \\\\\n")
    lines += ["\\bottomrule\n", "\\end{tabular}\n"]
    (destination / "cost-table.tex").write_text("".join(lines))
    detail = ["% Generated rejection-path timing; latency cells are median/p99 ns across run statistics.\n",
              "\\begin{tabular}{rrrr}\n", "\\toprule\n",
              "Hold ($\\mu$s) & GR Busy (ns) & Natural trans. (ns) & "
              "Controlled trans. (ns) \\\\\n",
              "\\midrule\n"]
    for hold in sorted({row["hold_us"] for row in report["aggregates"]}):
        guarded = indexed.get(("guarded", hold))
        if guarded is None:
            continue
        fmt_ns = lambda value: "--" if value is None else (
            f"{value['median_of_run_medians']}/{value['median_of_run_p99']}")
        detail.append(f"{hold} & {fmt_ns(guarded['latency_ns']['replace_busy'])} & "
                      f"{fmt_ns(guarded['latency_ns']['transition_busy'])} & "
                      f"{fmt_ns(guarded['latency_ns']['controlled_transition'])} \\\\\n")
    detail += ["\\bottomrule\n", "\\end{tabular}\n"]
    (destination / "cost-contention-table.tex").write_text("".join(detail))
    holds = sorted({row["hold_us"] for row in report["aggregates"]})
    overhead_hold = 0 if 0 in holds else holds[0]
    contention_hold = 500 if 500 in holds else holds[-1]
    atomic_overhead = indexed.get(("atomic", overhead_hold))
    guarded_overhead = indexed.get(("guarded", overhead_hold))
    guarded_contention = indexed.get(("guarded", contention_hold))
    def describe(metric: dict | None) -> str:
        if metric is None:
            return "undefined"
        return (f"{metric['median_of_run_medians']} ns "
                f"(run-median range {metric['run_median_min']}--{metric['run_median_max']} ns)")
    ap_dispatch = None if atomic_overhead is None else atomic_overhead["latency_ns"]["dispatch_ok"]
    gr_dispatch = None if guarded_overhead is None else guarded_overhead["latency_ns"]["dispatch_ok"]
    gr_busy = None if guarded_contention is None else guarded_contention["latency_ns"]["replace_busy"]
    gr_controlled = (None if guarded_contention is None
                     else guarded_contention["latency_ns"]["controlled_transition"])
    busy_text = "undefined" if gr_busy is None else (
        f"{gr_busy['median_of_run_medians']}/{gr_busy['median_of_run_p99']} ns median/p99")
    controlled_text = "undefined" if gr_controlled is None else (
        f"{gr_controlled['median_of_run_medians']}/{gr_controlled['median_of_run_p99']} ns median/p99")
    representative = report["runs"][0]
    note = (
        f"At {overhead_hold}~$\\mu$s hold, successful observer round-trip was "
        f"{describe(ap_dispatch)} for AP and {describe(gr_dispatch)} for GR. "
        f"At {contention_hold}~$\\mu$s hold, GR Busy return latency was {busy_text}; "
        f"the separately controlled TransitionBusy return was {controlled_text}. "
        f"The manager-accounted resident bytecode was {representative['program_bytes_one']} bytes "
        f"for one loaded candidate and {representative['program_bytes_two']} bytes for two; "
        "these counters exclude allocator, metadata, and process RSS.\n"
    )
    (destination / "cost-note.tex").write_text(note)
    checksum_paths = [path for path in sorted(destination.rglob("*"))
                      if path.is_file() and path.name != "SHA256SUMS"]
    (destination / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(destination)}\n"
        for path in checksum_paths))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--attempts-per-run", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    records = [json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()]
    report = analyze(records, expected_attempts=args.attempts_per_run, expected_runs=args.runs)
    write_outputs(report, args.output_dir or args.trace.parent)
    print(f"PASS: {len(report['runs'])} retained runs; update-cost denominators and resources hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
