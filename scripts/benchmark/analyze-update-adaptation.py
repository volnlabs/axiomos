#!/usr/bin/env python3
"""Independently replay and analyze the deterministic adaptation trace."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

PROTOCOLS = ("frozen", "atomic", "guarded")
KINDS = {"config", "candidate", "attempt", "control", "invocation", "completion", "summary"}
PROPOSAL_TIMES_US = (4_250_000, 4_500_000, 4_750_000, 5_000_000)


def close(actual, expected, label):
    if not math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-10):
        raise ValueError(f"{label}: got {actual}, expected {expected}")


def identity(value, label):
    if (not isinstance(value, list) or len(value) != 2
            or not all(type(part) is int for part in value)
            or not 0 <= value[0] <= 2**32 - 1
            or not 1 <= value[1] <= 2**64 - 1):
        raise ValueError(f"malformed {label} installation identity")
    return tuple(value)


def mass_at(config, time_us):
    return 1.0 if time_us < config["mass_change_us"] else 2.0


def reference_at(time_us):
    return 1.0 if (time_us // 1_000_000) % 2 == 0 else -1.0


def command_for(gain, reference, velocity):
    return max(-4.0, min(4.0, gain * (reference - velocity)))


def handle_gains(config):
    result = {}
    for pair in config["handle_gains"]:
        if (not isinstance(pair, list) or len(pair) != 2
                or type(pair[0]) is not int or not 0 <= pair[0] <= 2**32 - 1
                or pair[0] in result
                or type(pair[1]) not in (int, float) or not math.isfinite(pair[1])):
            raise ValueError("malformed or duplicate handle_gains entry")
        result[pair[0]] = pair[1]
    return result


def publication_at(initial, publications, time_us, inclusive):
    current = initial
    for publication in publications:
        if publication["published_us"] < time_us or (
                inclusive and publication["published_us"] == time_us):
            current = publication["installation"]
    return current


def validate_attempts(config, attempts):
    gains = handle_gains(config)
    current = identity(config["initial_installation"], "initial")
    if current[0] not in gains:
        raise ValueError("initial installation has no handle/gain mapping")
    close(gains[current[0]], config["initial_gain"], "initial handle gain")
    committed = config["initial_committed"]
    if type(committed) is not int or committed <= 0:
        raise ValueError("initial committed charge must be a positive integer")
    initial_receipt = config["initial_receipt"]
    if identity(initial_receipt["installed"], "initial receipt") != current:
        raise ValueError("initial receipt installation mismatch")
    if (initial_receipt["previous"] is not None
            or initial_receipt["committed"] != committed
            or initial_receipt["admission_delta"] != committed):
        raise ValueError("initial receipt ledger mismatch")
    publications = []
    metrics = dict(actual_attempts=0, busy_attempts=0, retry_attempts=0,
                   successful_retries=0, activations=0, stale_errors=0,
                   stale_accepted=0, accounting_errors=0)
    seen = set()
    for attempt in sorted(attempts, key=lambda row: (row["scheduled_us"], row["ordinal"])):
        key = (attempt["proposal"], attempt["ordinal"])
        if key in seen:
            raise ValueError(f"duplicate attempt {key}")
        seen.add(key)
        before = identity(attempt["before_installation"], "attempt before")
        after = identity(attempt["after_installation"], "attempt after")
        expected = identity(attempt["expected"], "attempt expected")
        if before != current or attempt["before_committed"] != committed:
            raise ValueError("attempt before-state does not follow publication history")
        candidate = attempt["candidate_handle"]
        if candidate not in gains:
            raise ValueError("attempt candidate has no handle/gain mapping")
        close(attempt["candidate_gain"], gains[candidate], "attempt candidate gain")
        outcome = attempt["outcome"]
        attempted = attempt["attempted"]
        valid_accounting = False
        if not attempted:
            if (outcome != "NotAttempted" or attempt["receipt"] is not None
                    or attempt["published_us"] is not None or before != after
                    or attempt["before_committed"] != attempt["after_committed"]):
                raise ValueError("NotAttempted event mutated manager state")
            valid_accounting = True
        else:
            metrics["actual_attempts"] += 1
            metrics["retry_attempts"] += attempt["ordinal"] > 0
            if outcome == "Ok":
                receipt = attempt["receipt"]
                if receipt is None:
                    raise ValueError("successful attempt has no receipt")
                installed = identity(receipt["installed"], "receipt installed")
                previous = identity(receipt["previous"], "receipt previous")
                valid_receipt = (
                    previous == before and installed == after
                    and installed[0] == candidate and installed[1] == before[1] + 1
                    and attempt["before_committed"] == config["initial_committed"]
                    and attempt["after_committed"] == config["initial_committed"]
                    and receipt["admission_delta"] == 0
                    and receipt["committed"] == config["initial_committed"]
                    and attempt["published_us"] is not None
                    and attempt["published_us"] == attempt["scheduled_us"]
                    and attempt["published_us"] <= attempt["completed_us"]
                )
                if not valid_receipt:
                    raise ValueError("successful receipt/ledger transition is inconsistent")
                metrics["stale_accepted"] += expected != before
                metrics["activations"] += 1
                metrics["successful_retries"] += attempt["ordinal"] > 0
                current, committed = after, attempt["after_committed"]
                publications.append({
                    "published_us": attempt["published_us"],
                    "installation": current,
                    "gain": gains[candidate],
                    "predecessor": before,
                    "predecessor_gain": gains[before[0]],
                    "proposal": attempt["proposal"],
                })
                valid_accounting = True
            elif outcome in ("Busy", "StaleInstallation"):
                if (attempt["receipt"] is not None or attempt["published_us"] is not None
                        or before != after
                        or attempt["before_committed"] != attempt["after_committed"]):
                    raise ValueError(f"{outcome} attempt did not preserve manager state")
                if outcome == "Busy":
                    metrics["busy_attempts"] += 1
                else:
                    if expected == before:
                        raise ValueError("StaleInstallation returned for current identity")
                    metrics["stale_errors"] += 1
                valid_accounting = True
            else:
                raise ValueError(f"unknown attempted outcome: {outcome}")
        if attempt["accounting_ok"] != valid_accounting:
            metrics["accounting_errors"] += 1
    return {"final_installation": current, "final_committed": committed,
            "publications": publications, **metrics}


def seed_candidates(config, candidates):
    if not candidates:
        return []
    schedules = [candidate["scheduled_us"] for candidate in sorted(candidates, key=lambda row: row["proposal"])]
    schedule_set = set(schedules)
    velocity = 0.0
    held_command = 0.0
    gain = config["initial_gain"]
    errors = {}
    result = []
    for time_us in range(0, max(schedules) + 1, config["step_us"]):
        if time_us % config["control_period_us"] == 0:
            reference = reference_at(time_us)
            errors[time_us] = (reference - velocity) ** 2
            if time_us in schedule_set:
                start = time_us - 250_000
                ticks = list(range(start, time_us, config["control_period_us"]))
                if any(tick not in errors for tick in ticks):
                    raise ValueError("candidate window lacks seed control ticks")
                prior_rmse = math.sqrt(sum(errors[tick] for tick in ticks) / len(ticks))
                previous_gain = gain
                if prior_rmse > 0.1:
                    gain = min(16.0, gain * 2.0)
                result.append((time_us, start, prior_rmse, previous_gain, gain))
            held_command = command_for(gain, reference, velocity)
        velocity += (config["step_us"] / 1_000_000.0) * (
            held_command - velocity) / mass_at(config, time_us)
    return result


def counterfactual_probe(config, start_us, velocity, gain):
    held_command = 0.0
    errors = []
    end_us = start_us + 250_000
    for time_us in range(start_us, end_us, config["step_us"]):
        if time_us % config["control_period_us"] == 0:
            reference = reference_at(time_us)
            errors.append((reference - velocity) ** 2)
            held_command = command_for(gain, reference, velocity)
        velocity += (config["step_us"] / 1_000_000.0) * (
            held_command - velocity) / mass_at(config, time_us)
    return math.sqrt(sum(errors) / len(errors))


def analyze_protocol(config, records):
    grouped = {kind: [] for kind in KINDS}
    for record in records:
        grouped[record["kind"]].append(record)
    if len(grouped["summary"]) != 1:
        raise ValueError("protocol requires exactly one summary")
    controls = sorted(grouped["control"], key=lambda row: row["tick"])
    invocations = sorted(grouped["invocation"], key=lambda row: row["invocation"])
    completions = sorted(grouped["completion"], key=lambda row: (row["completion_us"], row["invocation"]))
    attempts = grouped["attempt"]
    candidates = sorted(grouped["candidate"], key=lambda row: row["proposal"])
    summary = grouped["summary"][0]
    if len(controls) != config["duration_us"] // config["control_period_us"]:
        raise ValueError("wrong control tick count")
    if len(invocations) != len(controls):
        raise ValueError("control/invocation count mismatch")

    attempt_report = validate_attempts(config, attempts)
    initial = identity(config["initial_installation"], "initial")
    publications = attempt_report["publications"]
    gains = handle_gains(config)
    completion_by_invocation = {}
    for completion in completions:
        invocation_id = completion["invocation"]
        if invocation_id in completion_by_invocation:
            raise ValueError("duplicate completion")
        completion_by_invocation[invocation_id] = completion

    velocity = 0.0
    held_command = 0.0
    controls_by_time = {row["scheduled_us"]: row for row in controls}
    completions_by_time = {}
    for completion in completions:
        completions_by_time.setdefault(completion["completion_us"], []).append(completion)
    invocation_by_tick = {row["tick"]: row for row in invocations}
    if (len(controls_by_time) != len(controls) or len(invocation_by_tick) != len(invocations)
            or len({row["invocation"] for row in invocations}) != len(invocations)):
        raise ValueError("duplicate control/invocation identity")
    active_invocations = []
    version_overlaps = 0
    same_version_overlaps = 0
    retired_commands = 0
    transition_skips = 0
    execution_skips = 0
    execution_skip_times = []
    empty_slot_observations = 0
    error_squares = {"pre": [], "post": []}

    for time_us in range(0, config["duration_us"], config["step_us"]):
        for completion in sorted(completions_by_time.get(time_us, []), key=lambda row: row["invocation"]):
            held_command = completion["captured_command"]
        if time_us % config["control_period_us"] == 0:
            tick = time_us // config["control_period_us"]
            if time_us not in controls_by_time or tick not in invocation_by_tick:
                raise ValueError("missing scheduled control/invocation")
            control = controls_by_time[time_us]
            invocation = invocation_by_tick[tick]
            phase = "pre" if tick < config["pre_ticks"] else "post"
            if (control["tick"] != tick or control["phase"] != phase
                    or invocation["invocation"] != tick
                    or invocation["start_us"] != time_us):
                raise ValueError("control schedule/phase mismatch")
            close(control["mass"], mass_at(config, time_us), "mass")
            close(control["reference"], reference_at(time_us), "reference")
            close(control["velocity"], velocity, "plant evolution")
            close(control["held_command"], held_command, "completion-order ZOH command")
            expected_error_sq = (control["reference"] - velocity) ** 2
            close(control["error_sq"], expected_error_sq, "control squared error")
            close(invocation["captured_velocity"], velocity, "captured velocity")
            close(invocation["captured_reference"], control["reference"], "captured reference")
            if control["dispatch_outcome"] != invocation["outcome"]:
                raise ValueError("control/invocation outcome mismatch")
            requested_hold = (config["long_hold_us"] if time_us == config["long_start_us"]
                              else config["guard_hold_us"])
            if invocation["requested_hold_us"] != requested_hold:
                raise ValueError("invocation hold schedule mismatch")
            error_squares[phase].append(control["error_sq"])
            active_invocations = [prior for prior in active_invocations
                                  if prior["completion_us"] > time_us]
            if invocation["outcome"] == "Started":
                captured = identity(invocation["captured_installation"], "captured")
                current = publication_at(initial, publications, time_us, inclusive=True)
                if captured != current:
                    raise ValueError("invocation captured stale publication identity")
                close(invocation["captured_gain"], gains[captured[0]], "captured gain")
                expected_command = command_for(invocation["captured_gain"],
                                               control["reference"], velocity)
                close(invocation["captured_command"], expected_command, "captured command")
                if invocation["completion_us"] != time_us + requested_hold:
                    raise ValueError("invocation completion schedule mismatch")
                completion = completion_by_invocation.get(invocation["invocation"])
                if completion is None:
                    raise ValueError("started invocation has no completion")
                if (identity(completion["captured_installation"], "completion captured") != captured
                        or completion["completion_us"] != invocation["completion_us"]):
                    raise ValueError("completion captured identity/time differs from invocation")
                close(completion["captured_gain"], invocation["captured_gain"],
                      "completion captured gain")
                close(completion["captured_command"], invocation["captured_command"],
                      "completion captured command")
                published = publication_at(initial, publications, completion["completion_us"],
                                           inclusive=False)
                if identity(completion["published_installation"], "completion published") != published:
                    raise ValueError("completion published identity mismatch")
                retired = captured != published
                if completion["retired_after_publication"] != retired:
                    raise ValueError("retired command classification mismatch")
                retired_commands += retired
                for prior in active_invocations:
                    if prior["installation"] == captured:
                        same_version_overlaps += 1
                    else:
                        version_overlaps += 1
                active_invocations.append({"start_us": time_us,
                                           "completion_us": invocation["completion_us"],
                                           "installation": captured})
            else:
                if invocation["outcome"] not in ("ExecutionBusy", "TransitionBusy"):
                    raise ValueError("unknown invocation outcome")
                if any(invocation[field] is not None for field in (
                        "captured_installation", "captured_gain", "captured_command", "completion_us")):
                    raise ValueError("skipped invocation captured a command")
                if (invocation["outcome"] == "ExecutionBusy"
                        and not any(prior["start_us"] == config["long_start_us"]
                                    and prior["completion_us"] > time_us
                                    for prior in active_invocations)):
                    raise ValueError("ExecutionBusy lacks the long-held predecessor invocation")
                transition_skips += invocation["outcome"] == "TransitionBusy"
                execution_skips += invocation["outcome"] == "ExecutionBusy"
                if invocation["outcome"] == "ExecutionBusy":
                    execution_skip_times.append(time_us)
        velocity += (config["step_us"] / 1_000_000.0) * (
            held_command - velocity) / mass_at(config, time_us)

    if set(completion_by_invocation) != {
            row["invocation"] for row in invocations if row["outcome"] == "Started"}:
        raise ValueError("completion population mismatch")
    pre_rmse = math.sqrt(sum(error_squares["pre"]) / len(error_squares["pre"]))
    post_rmse = math.sqrt(sum(error_squares["post"]) / len(error_squares["post"]))
    computed = {
        "pre_ticks": len(error_squares["pre"]),
        "post_ticks": len(error_squares["post"]),
        "pre_rmse": pre_rmse,
        "post_rmse": post_rmse,
        "started_invocations": sum(row["outcome"] == "Started" for row in invocations),
        "completed_invocations": len(completions),
        "guard_version_overlaps": version_overlaps,
        "same_version_overlaps": same_version_overlaps,
        "retired_commands_after_publication": retired_commands,
        "transition_skips": transition_skips,
        "execution_skips": execution_skips,
        "execution_skip_times_us": execution_skip_times,
        "empty_slot_observations": empty_slot_observations,
        "scheduled_attempt_events": len(attempts),
        **{key: attempt_report[key] for key in (
            "actual_attempts", "busy_attempts", "retry_attempts", "successful_retries",
            "activations", "stale_errors", "stale_accepted", "accounting_errors")},
        "final_installation": list(attempt_report["final_installation"]),
        "final_gain": gains[attempt_report["final_installation"][0]],
        "final_committed": attempt_report["final_committed"],
    }
    for key, value in computed.items():
        if key in ("same_version_overlaps", "execution_skip_times_us",
                   "empty_slot_observations"):
            continue
        if key not in summary:
            raise ValueError(f"summary missing {key}")
        if isinstance(value, float):
            close(summary[key], value, "RMSE summary" if "rmse" in key else f"summary {key}")
        elif summary[key] != value:
            label = "overlap" if "overlap" in key else key
            raise ValueError(f"summary {label} mismatch")

    seed = seed_candidates(config, candidates)
    if len(seed) != len(candidates):
        raise ValueError("candidate count mismatch")
    for candidate, expected in zip(candidates, seed):
        scheduled, window_start, prior_rmse, previous_gain, candidate_gain = expected
        if (candidate["scheduled_us"] != scheduled
                or candidate["window_start_us"] != window_start
                or candidate["window_end_us"] != scheduled):
            raise ValueError("candidate seed window mismatch")
        close(candidate["prior_rmse"], prior_rmse, "candidate seed RMSE")
        close(candidate["previous_gain"], previous_gain, "candidate previous gain")
        close(candidate["candidate_gain"], candidate_gain, "candidate gain")

    probes = []
    for publication in publications:
        control = controls_by_time[publication["published_us"]]
        predecessor_rmse = counterfactual_probe(
            config, publication["published_us"], control["velocity"],
            publication["predecessor_gain"])
        candidate_rmse = counterfactual_probe(
            config, publication["published_us"], control["velocity"], publication["gain"])
        probes.append({
            "proposal": publication["proposal"],
            "published_us": publication["published_us"],
            "predecessor_rmse": predecessor_rmse,
            "candidate_rmse": candidate_rmse,
            "useful": candidate_rmse < predecessor_rmse,
        })
    computed["local_utility"] = probes
    computed["useful_activations"] = sum(probe["useful"] for probe in probes)
    return computed


def analyze(records):
    groups = {protocol: [] for protocol in PROTOCOLS}
    configs = {}
    for record in records:
        if record.get("schema") != 1 or record.get("protocol") not in PROTOCOLS:
            raise ValueError("unknown adaptation schema/protocol")
        if record.get("kind") not in KINDS:
            raise ValueError("unknown adaptation record kind")
        protocol = record["protocol"]
        groups[protocol].append(record)
        if record["kind"] == "config":
            if protocol in configs:
                raise ValueError("duplicate config")
            configs[protocol] = record
    present = [protocol for protocol in PROTOCOLS if groups[protocol]]
    if not present or set(present) != set(configs):
        raise ValueError("every protocol requires one config")
    excluded = ("protocol", "initial_installation", "initial_receipt", "handle_gains",
                "initial_committed")
    comparable = {
        key: value for key, value in configs[present[0]].items()
        if key not in excluded
    }
    initial_committed = configs[present[0]]["initial_committed"]
    if type(initial_committed) is not int or initial_committed <= 0:
        raise ValueError("initial committed charge must be a positive integer")
    for protocol in present[1:]:
        other = {key: value for key, value in configs[protocol].items()
                 if key not in excluded}
        if other != comparable:
            raise ValueError("protocol configurations differ")
        if configs[protocol]["initial_committed"] != initial_committed:
            raise ValueError("protocol initial committed charges differ")
        if sorted(handle_gains(configs[protocol]).values()) != sorted(
                handle_gains(configs[present[0]]).values()):
            raise ValueError("protocol gain fixtures differ")
    report = {"config": comparable, "initial_committed": initial_committed,
              "protocols": {}}
    for protocol in present:
        report["protocols"][protocol] = analyze_protocol(configs[protocol], groups[protocol])
    return report


def validate_campaign(report, records):
    config = report["config"]
    expected_config = {
        "schema": 1, "kind": "config", "duration_us": 8_000_000,
        "step_us": 100, "control_period_us": 1_000,
        "mass_change_us": 4_000_000, "guard_hold_us": 100,
        "long_start_us": 4_249_000, "long_hold_us": 2_000,
        "initial_gain": 1.0, "pre_ticks": 4_000, "post_ticks": 4_000,
        "candidate_count": 4,
    }
    if config != expected_config or set(report["protocols"]) != set(PROTOCOLS):
        raise ValueError("fixed adaptation campaign configuration is incomplete")
    for protocol in PROTOCOLS:
        protocol_config = next(row for row in records if row["protocol"] == protocol
                               and row["kind"] == "config")
        candidates = sorted((row for row in records if row["protocol"] == protocol
                             and row["kind"] == "candidate"), key=lambda row: row["proposal"])
        attempts = [row for row in records if row["protocol"] == protocol
                    and row["kind"] == "attempt"]
        if ([row["scheduled_us"] for row in candidates] != list(PROPOSAL_TIMES_US)
                or [row["proposal"] for row in candidates] != list(range(4))
                or len(attempts) != 8):
            raise ValueError("fixed candidate/attempt schedule is incomplete")
        indexed_attempts = {(row["proposal"], row["ordinal"]): row for row in attempts}
        if set(indexed_attempts) != {(proposal, ordinal) for proposal in range(4)
                                    for ordinal in (0, 1)}:
            raise ValueError("fixed primary/retry attempt schedule is incomplete")
        for candidate in candidates:
            proposal = candidate["proposal"]
            primary = indexed_attempts[(proposal, 0)]
            retry = indexed_attempts[(proposal, 1)]
            expected_primary_completion = (candidate["scheduled_us"] + 1_000
                                           if protocol == "atomic" and proposal == 0
                                           else candidate["scheduled_us"])
            if (primary["scheduled_us"] != candidate["scheduled_us"]
                    or retry["scheduled_us"] != candidate["scheduled_us"] + 1_000
                    or primary["completed_us"] != expected_primary_completion
                    or retry["completed_us"] != retry["scheduled_us"]
                    or primary["candidate_handle"] != retry["candidate_handle"]
                    or primary["candidate_gain"] != retry["candidate_gain"]
                    or primary["expected"] != retry["expected"]):
                raise ValueError("primary/retry candidate schedule differs")
            close(primary["candidate_gain"], candidate["candidate_gain"],
                  "primary candidate gain")
            expected_outcomes = {
                "frozen": ("NotAttempted", "NotAttempted"),
                "atomic": ("Ok", "StaleInstallation"),
                "guarded": (("Busy", "Ok") if proposal == 0
                            else ("Ok", "StaleInstallation")),
            }[protocol]
            if (primary["outcome"], retry["outcome"]) != expected_outcomes:
                raise ValueError("primary/retry outcome schedule differs")
        mapped = handle_gains(protocol_config)
        candidate_handles = [indexed_attempts[(proposal, 0)]["candidate_handle"]
                             for proposal in range(4)]
        if (len(mapped) != 5 or len(set(candidate_handles)) != 4
                or identity(protocol_config["initial_installation"], "initial")[0]
                in candidate_handles
                or [mapped[handle] for handle in candidate_handles]
                != [candidate["candidate_gain"] for candidate in candidates]):
            raise ValueError("candidate handle/gain mapping is incomplete")
        metrics = report["protocols"][protocol]
        if metrics["same_version_overlaps"]:
            raise ValueError("same-version guard overlap is forbidden")
        expected = {
            "frozen": (0, 0, 1, 0, 0, 0, 0, 0),
            "atomic": (4, 4, 0, 0, 0, 1, 1, 1),
            "guarded": (4, 3, 1, 1, 1, 0, 0, 1),
        }[protocol]
        actual = (metrics["activations"], metrics["stale_errors"],
                  metrics["execution_skips"], metrics["busy_attempts"],
                  metrics["successful_retries"], metrics["guard_version_overlaps"],
                  metrics["retired_commands_after_publication"], metrics["actual_attempts"] == 8)
        wanted = (*expected[:-1], bool(expected[-1]))
        if actual != wanted:
            raise ValueError(f"unexpected deterministic schedule outcome for {protocol}: {actual}")
        if metrics["stale_accepted"] or metrics["accounting_errors"]:
            raise ValueError(f"identity/accounting invariant violated for {protocol}")
        if metrics["empty_slot_observations"]:
            raise ValueError(f"empty installation observed for {protocol}")
        expected_skip_times = ([] if protocol == "atomic"
                               else [config["long_start_us"] + config["control_period_us"]])
        if metrics["execution_skip_times_us"] != expected_skip_times:
            raise ValueError(f"ExecutionBusy occurred at the wrong time for {protocol}")
        expected_population = {
            "frozen": (7_999, 7_999, 0, 0),
            "atomic": (8_000, 8_000, 4, 8),
            "guarded": (7_999, 7_999, 4, 8),
        }[protocol]
        population = (metrics["started_invocations"], metrics["completed_invocations"],
                      metrics["retry_attempts"], metrics["actual_attempts"])
        if (population != expected_population or metrics["pre_ticks"] != 4_000
                or metrics["post_ticks"] != 4_000 or metrics["transition_skips"] != 0
                or metrics["scheduled_attempt_events"] != 8):
            raise ValueError(f"event population mismatch for {protocol}: {population}")


def write_artifacts(trace, report, destination):
    destination.mkdir(parents=True, exist_ok=True)
    fields = (
        "protocol", "pre_ticks", "post_ticks", "pre_rmse", "post_rmse",
        "activations", "useful_activations", "guard_version_overlaps",
        "same_version_overlaps", "retired_commands_after_publication",
        "transition_skips", "execution_skips", "busy_attempts", "retry_attempts",
        "successful_retries", "stale_errors", "stale_accepted", "accounting_errors",
        "empty_slot_observations",
        "started_invocations", "completed_invocations", "final_gain", "final_committed",
    )
    with (destination / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for protocol in PROTOCOLS:
            row = report["protocols"][protocol]
            writer.writerow({field: protocol if field == "protocol" else row[field]
                             for field in fields})
    payload = {**report, "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
               "rmse_denominator": "all 4,000 scheduled control ticks in each phase, including skips",
               "utility_scope": "paired 250 ms synchronous counterfactual from each actual activation state"}
    (destination / "analysis.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    labels = {"frozen": "Frozen", "atomic": "AP", "guarded": "GR"}
    rows = []
    rows.append(("RMSE pre/post", *(
        f"{report['protocols'][p]['pre_rmse']:.3f}/{report['protocols'][p]['post_rmse']:.3f}"
        for p in PROTOCOLS)))
    rows.append(("Local utility probe", *(
        ("--" if not report["protocols"][p]["activations"] else
         f"{report['protocols'][p]['useful_activations']}/{report['protocols'][p]['activations']}")
        for p in PROTOCOLS)))
    rows.append(("Old/new / same guard overlap", *(
        f"{report['protocols'][p]['guard_version_overlaps']}/{report['protocols'][p]['same_version_overlaps']}"
        for p in PROTOCOLS)))
    rows.append(("Retired commands", *(
        str(report["protocols"][p]["retired_commands_after_publication"]) for p in PROTOCOLS)))
    rows.append(("Dispatch skips / successful retries", *(
        f"{report['protocols'][p]['transition_skips'] + report['protocols'][p]['execution_skips']}/"
        f"{report['protocols'][p]['successful_retries']}" for p in PROTOCOLS)))
    lines = ["% Generated from deterministic replay evidence; do not hand-edit.\n",
             r"\begin{tabular}{lrrr}" + "\n", r"\toprule" + "\n",
             "Metric & " + " & ".join(labels[p] for p in PROTOCOLS) + r" \\" + "\n",
             r"\midrule" + "\n"]
    lines += [" & ".join(row) + r" \\" + "\n" for row in rows]
    lines += [r"\bottomrule" + "\n", r"\end{tabular}" + "\n"]
    (destination / "adaptation-table.tex").write_text("".join(lines))
    checksum_paths = [path for path in sorted(destination.rglob("*"))
                      if path.is_file() and path.name != "SHA256SUMS"]
    (destination / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(destination)}\n"
        for path in checksum_paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--write-artifacts", action="store_true")
    parser.add_argument("--output-dir", type=Path,
                        help="write derived files here (implies --write-artifacts)")
    args = parser.parse_args()
    records = [json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()]
    report = analyze(records)
    validate_campaign(report, records)
    if args.write_artifacts or args.output_dir:
        write_artifacts(args.trace, report, args.output_dir or args.trace.parent)
    print("PASS: deterministic plant, controller, identity, guard, retry, and ledger replay hold")


if __name__ == "__main__":
    main()
