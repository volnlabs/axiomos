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
V2_HOLDS_US = (0, 10, 100, 500, 900, 1100)
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
    if type(value) is not int or value < 0:
        raise ValueError(f"{record.get('kind')} has invalid {key}")
    return value


def _installation_identity(record: dict, key: str) -> tuple[int, int]:
    value = record.get(key)
    if (not isinstance(value, list) or len(value) != 2
            or any(type(part) is not int for part in value)
            or not 0 <= value[0] <= 2**32 - 1
            or not 1 <= value[1] <= 2**64 - 1):
        raise ValueError(f"{record.get('kind')} has invalid {key}")
    return value[0], value[1]


def _summarize_run(key: tuple[str, int, int], records: list[dict], expected_attempts: int,
                   schema: int = 1) -> dict:
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
    if (type(meta.get("attempts")) is not int or meta["attempts"] != expected_attempts
            or type(meta.get("period_ns")) is not int or meta["period_ns"] != 1_000_000):
        raise ValueError(f"{key}: measurement contract mismatch")
    if type(meta.get("warmup")) is not int or meta["warmup"] < 0:
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
    previous_return = None
    previous_installation = None
    for attempt, record in enumerate(updates):
        identity = (record.get("attempt"), record.get("logical_update"),
                    record.get("retry_ordinal"))
        if any(type(value) is not int for value in identity):
            raise ValueError(f"{key}: invalid attempt identity at attempt {attempt}")
        if identity != (attempt, logical, retry):
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
        called_offset = started_offset
        if schema >= 2:
            if latency == 0:
                raise ValueError(f"{key}: update has invalid zero latency sentinel at {attempt}")
            called_offset = _nonnegative(record, "called_offset_ns")
            if called_offset < started_offset:
                raise ValueError(f"{key}: update call precedes attempt start at {attempt}")
            if previous_return is not None and called_offset < previous_return:
                raise ValueError(f"{key}: serialized update calls overlap at attempt {attempt}")
            previous_return = called_offset + latency
            if "post_swap_observed_offset_ns" not in record:
                raise ValueError(f"{key}: update lacks post-swap timestamp at {attempt}")
        before_installation = after_installation = None
        if schema == 3:
            before_installation = _installation_identity(record, "before_installation")
            after_installation = _installation_identity(record, "after_installation")
            if (previous_installation is not None
                    and before_installation != previous_installation):
                raise ValueError(f"{key}: update identity continuity failed at attempt {attempt}")
        outcome = record.get("outcome")
        if outcome == "Ok":
            if schema >= 2:
                published = record["post_swap_observed_offset_ns"]
                if (not isinstance(published, int) or isinstance(published, bool)
                        or not called_offset <= published <= called_offset + latency):
                    raise ValueError(f"{key}: successful update has invalid post-swap timestamp")
            if (schema == 3 and (after_installation[0] == before_installation[0]
                    or after_installation[1] != before_installation[1] + 1)):
                raise ValueError(f"{key}: successful update identity is invalid at attempt {attempt}")
            successes += 1
            first_successes += retry == 1
            replace_ok.append(latency)
            logical += 1
            retry = 1
        elif outcome == "Busy" and protocol == "guarded":
            if schema >= 2 and record["post_swap_observed_offset_ns"] is not None:
                raise ValueError(f"{key}: Busy update has a post-swap timestamp")
            if schema == 3 and after_installation != before_installation:
                raise ValueError(f"{key}: Busy update changed installation at attempt {attempt}")
            busy += 1
            replace_busy.append(latency)
            retry += 1
        else:
            raise ValueError(f"{key}: unexpected update outcome {outcome!r}")
        if schema == 3:
            previous_installation = after_installation

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

    resource_records = grouped["resource"]
    resources = {record.get("phase"): record for record in resource_records}
    if (len(resource_records) != len(RESOURCE_PHASES)
            or tuple(phase for phase in RESOURCE_PHASES if phase in resources) != RESOURCE_PHASES
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


LOGICAL_METRICS = (
    "scheduled_to_publication",
    "first_attempt_to_publication",
    "scheduled_to_return",
    "first_attempt_to_return",
)
THRESHOLDS_NS = (1_000_000, 5_000_000, 10_000_000, 20_000_000)


def _stats_v2(values: list[int]) -> dict[str, int] | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = lambda q: ordered[math.ceil(q * len(ordered)) - 1]
    return {
        "count": len(values), "median": rank(0.5), "p95": rank(0.95),
        "p99": rank(0.99), "max": ordered[-1],
    }


def _thresholds(requests: list[dict], metric: str) -> dict[str, dict]:
    result = {}
    value_key = f"{metric}_ns"
    start = "scheduled" if metric.startswith("scheduled_") else "first_attempt"
    censor_key = f"{start}_to_censor_ns"
    for threshold in THRESHOLDS_NS:
        known_met = known_missed = unknown = 0
        for request in requests:
            if request["completed"]:
                if request[value_key] <= threshold:
                    known_met += 1
                else:
                    known_missed += 1
            elif request[censor_key] >= threshold:
                known_missed += 1
            else:
                unknown += 1
        denominator = len(requests)
        result[f"{threshold // 1_000_000}ms"] = {
            "denominator": denominator,
            "known_met": known_met,
            "known_missed": known_missed,
            "unknown": unknown,
            "lower_rate": known_met / denominator if denominator else None,
            "upper_rate": (known_met + unknown) / denominator if denominator else None,
        }
    return result


def _logical_analysis(by_run: dict[tuple[str, int, int], list[dict]],
                      cost_runs: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    requests = []
    run_summaries = []
    cost_index = {(run["protocol"], run["hold_us"], run["run"]): run for run in cost_runs}
    for key in sorted(by_run):
        protocol, hold_us, run_number = key
        updates = [record for record in by_run[key] if record.get("kind") == "update"]
        first = None
        busy_attempts = 0
        run_requests = []
        for record in updates:
            if first is None:
                first = record
                busy_attempts = 0
            if record["outcome"] == "Busy":
                busy_attempts += 1
                continue
            returned = record["called_offset_ns"] + record["latency_ns"]
            published = record["post_swap_observed_offset_ns"]
            request = {
                "protocol": protocol, "hold_us": hold_us, "run": run_number,
                "logical_update": record["logical_update"],
                "attempts": record["retry_ordinal"], "busy_attempts": busy_attempts,
                "completed": True, "censored": False,
                "first_scheduled_offset_ns": first["scheduled_offset_ns"],
                "first_started_offset_ns": first["started_offset_ns"],
                "first_called_offset_ns": first["called_offset_ns"],
                "post_swap_observed_offset_ns": published,
                "returned_offset_ns": returned,
                "scheduled_to_publication_ns": published - first["scheduled_offset_ns"],
                "first_attempt_to_publication_ns": published - first["called_offset_ns"],
                "scheduled_to_return_ns": returned - first["scheduled_offset_ns"],
                "first_attempt_to_return_ns": returned - first["called_offset_ns"],
                "scheduled_to_censor_ns": None,
                "first_attempt_to_censor_ns": None,
            }
            requests.append(request)
            run_requests.append(request)
            first = None
        if first is not None:
            last = updates[-1]
            censor = last["called_offset_ns"] + last["latency_ns"]
            request = {
                "protocol": protocol, "hold_us": hold_us, "run": run_number,
                "logical_update": first["logical_update"],
                "attempts": last["retry_ordinal"], "busy_attempts": busy_attempts,
                "completed": False, "censored": True,
                "first_scheduled_offset_ns": first["scheduled_offset_ns"],
                "first_started_offset_ns": first["started_offset_ns"],
                "first_called_offset_ns": first["called_offset_ns"],
                "post_swap_observed_offset_ns": None, "returned_offset_ns": None,
                "scheduled_to_publication_ns": None,
                "first_attempt_to_publication_ns": None,
                "scheduled_to_return_ns": None,
                "first_attempt_to_return_ns": None,
                "scheduled_to_censor_ns": censor - first["scheduled_offset_ns"],
                "first_attempt_to_censor_ns": censor - first["called_offset_ns"],
            }
            requests.append(request)
            run_requests.append(request)

        completed = [request for request in run_requests if request["completed"]]
        cost = cost_index[key]
        run_summaries.append({
            "protocol": protocol, "hold_us": hold_us, "run": run_number,
            "raw_attempts": len(updates), "requests_started": len(run_requests),
            "completed": len(completed), "censored": len(run_requests) - len(completed),
            "busy_attempts": sum(request["busy_attempts"] for request in run_requests),
            "first_attempt_successes": sum(request["completed"] and request["attempts"] == 1
                                           for request in run_requests),
            "retried_successes": sum(request["completed"] and request["attempts"] > 1
                                     for request in run_requests),
            "transition_busy_skips": cost["transition_busy_skips"],
            "execution_busy_skips": cost["execution_busy_skips"],
            "empty_skips": cost["empty_skips"],
            "latency_ns": {
                metric: _stats_v2([request[f"{metric}_ns"] for request in completed])
                for metric in LOGICAL_METRICS
            },
            "thresholds": {metric: _thresholds(run_requests, metric)
                           for metric in LOGICAL_METRICS},
        })

    aggregates = []
    for protocol, hold_us in sorted({(run["protocol"], run["hold_us"])
                                     for run in run_summaries}):
        members = [run for run in run_summaries
                   if (run["protocol"], run["hold_us"]) == (protocol, hold_us)]
        group_requests = [request for request in requests
                          if (request["protocol"], request["hold_us"]) == (protocol, hold_us)]
        total = lambda field: sum(member[field] for member in members)
        latency = {}
        for metric in LOGICAL_METRICS:
            summaries = [member["latency_ns"][metric] for member in members
                         if member["latency_ns"][metric] is not None]
            latency[metric] = None if not summaries else {
                "runs_with_completions": len(summaries),
                "median_of_run_medians": stats([summary["median"] for summary in summaries])["median"],
                "median_of_run_p95s": stats([summary["p95"] for summary in summaries])["median"],
                "median_of_run_p99s": stats([summary["p99"] for summary in summaries])["median"],
                "observed_max": max(summary["max"] for summary in summaries),
            }
        aggregates.append({
            "protocol": protocol, "hold_us": hold_us, "runs": len(members),
            "raw_attempts": total("raw_attempts"),
            "requests_started": total("requests_started"),
            "completed": total("completed"), "censored": total("censored"),
            "busy_attempts": total("busy_attempts"),
            "first_attempt_successes": total("first_attempt_successes"),
            "retried_successes": total("retried_successes"),
            "transition_busy_skips": total("transition_busy_skips"),
            "execution_busy_skips": total("execution_busy_skips"),
            "empty_skips": total("empty_skips"), "latency_ns": latency,
            "thresholds": {metric: _thresholds(group_requests, metric)
                           for metric in LOGICAL_METRICS},
        })
    return requests, run_summaries, aggregates


def analyze(records: list[dict], *, expected_attempts: int = 1000, expected_runs: int = 10,
            expected_holds: tuple[int, ...] | None = None,
            expected_protocols: tuple[str, ...] = PROTOCOLS) -> dict:
    schemas = {record.get("schema") for record in records}
    if (len(schemas) != 1 or any(type(schema) is not int for schema in schemas)
            or not schemas <= {1, 2, 3}):
        raise ValueError("unknown or mixed update-cost schema")
    schema = next(iter(schemas), None)
    expected_holds = expected_holds or (V2_HOLDS_US if schema >= 2 else HOLDS_US)
    by_run: dict[tuple[str, int, int], list[dict]] = defaultdict(list)
    for record in records:
        if record.get("protocol") not in PROTOCOLS:
            raise ValueError("unknown update-cost schema/protocol")
        if record.get("kind") not in RECORD_KINDS:
            raise ValueError(f"unknown record kind {record.get('kind')!r}")
        hold, run = record.get("hold_us"), record.get("run")
        if type(hold) is not int or hold < 0 or type(run) is not int or run < 0:
            raise ValueError("invalid hold/run identity")
        by_run[(record["protocol"], hold, run)].append(record)
    runs = [_summarize_run(key, by_run[key], expected_attempts, schema) for key in sorted(by_run)]
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
    report = {"runs": runs, "aggregates": aggregates,
              "denominators": {"replacement": "raw replacement calls",
                               "first_attempt": "logical update sequences started",
                               "dispatch": "dispatch calls attempted",
                               "missed": "scheduled releases",
                               "skips_per_update": "successful replacements"}}
    if schema >= 2:
        logical = _logical_analysis(by_run, runs)
        report.update({
            "schema": 2,
            "logical_metric": {
                "publication_event": "post-swap and reader-epoch-flip clock observation before reclamation wait",
                "return_event": "clock observation immediately after successful replacement API return",
                "first_attempt_start": "called_offset_ns sampled immediately before the first replacement API call",
                "attempt_started": "started_offset_ns sampled when wait_until returns, before pre-call candidate setup",
                "scheduled_start": "scheduled_offset_ns target for the first request release",
                "thresholds_ns": list(THRESHOLDS_NS),
                "censor": "final Busy API return at the fixed attempt limit",
            },
            "logical_requests": logical[0],
            "logical_runs": logical[1],
            "logical_aggregates": logical[2],
        })
        if schema == 3:
            report.update({
                "raw_schema": 3,
                "raw_identity": (
                    "each update records actual before_installation and post-timing "
                    "after_installation as [program, epoch]"
                ),
            })
    return report


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
    if "logical_aggregates" in report:
        base = ["protocol", "hold_us", "metric", "runs", "raw_attempts",
                "requests_started", "completed", "censored", "busy_attempts",
                "first_attempt_successes", "retried_successes",
                "transition_busy_skips", "execution_busy_skips", "empty_skips",
                "runs_with_completions", "median_of_run_medians_ns",
                "median_of_run_p95s_ns", "median_of_run_p99s_ns", "observed_max_ns"]
        threshold_fields = [f"{threshold}_{field}" for threshold in ("1ms", "5ms", "10ms", "20ms")
                            for field in ("denominator", "known_met", "known_missed", "unknown",
                                          "lower_rate", "upper_rate")]
        rows = []
        for aggregate in report["logical_aggregates"]:
            for metric in LOGICAL_METRICS:
                summary = aggregate["latency_ns"][metric] or {}
                row = {key: aggregate[key] for key in base[3:14]}
                row.update({"protocol": aggregate["protocol"], "hold_us": aggregate["hold_us"],
                            "metric": metric,
                            "runs_with_completions": summary.get("runs_with_completions", 0),
                            "median_of_run_medians_ns": summary.get("median_of_run_medians", ""),
                            "median_of_run_p95s_ns": summary.get("median_of_run_p95s", ""),
                            "median_of_run_p99s_ns": summary.get("median_of_run_p99s", ""),
                            "observed_max_ns": summary.get("observed_max", "")})
                for threshold, counts in aggregate["thresholds"][metric].items():
                    row.update({f"{threshold}_{field}": value for field, value in counts.items()})
                rows.append(row)
        with (destination / "cost-logical-latency.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=base + threshold_fields)
            writer.writeheader()
            writer.writerows(rows)
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
