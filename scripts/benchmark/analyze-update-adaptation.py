#!/usr/bin/env python3
"""Independently replay and analyze the deterministic adaptation trace."""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path

PROTOCOLS = ("frozen", "atomic", "guarded")
KINDS = {"config", "candidate", "attempt", "control", "invocation", "completion", "summary"}
PROPOSAL_TIMES_US = (4_250_000, 4_500_000, 4_750_000, 5_000_000)
GRID_PROTOCOLS = ("atomic", "guarded")
GRID_HOLDS_US = (0, 100, 500, 900, 1100)
GRID_PHASES_US = tuple(range(0, 1000, 20))


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def close(actual, expected, label):
    if not math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-10):
        raise ValueError(f"{label}: got {actual}, expected {expected}")


def conditional_rate(numerator, denominator):
    return None if denominator == 0 else numerator / denominator


def _nonnegative(record, key):
    value = record.get(key)
    if type(value) is not int or value < 0:
        raise ValueError(f"{record.get('kind')} has invalid {key}")
    return value


def _one(records, kind):
    selected = [record for record in records if record.get("kind") == kind]
    if len(selected) != 1:
        raise ValueError(f"expected one {kind} record")
    return selected[0]


def _recompute_schedule(start, records, attempts):
    hold = start["hold_us"]
    phase = start["phase_us"]
    duration = start.get("duration_us")
    if (duration != 8_000_000 or start.get("step_max_us") != 100
            or start.get("control_period_us") != 1000
            or start.get("mass_change_us") != 4_000_000
            or start.get("initial_gain") != 1):
        raise ValueError("schedule-grid plant configuration mismatch")
    current = identity(start.get("initial_installation"), "grid initial")
    gains = {current[0]: start["initial_gain"]}
    publications = {}
    manager_current = current
    for attempt in sorted(attempts, key=lambda row: row["scheduled_us"]):
        before = identity(attempt["before_installation"], "grid attempt before")
        after = identity(attempt["after_installation"], "grid attempt after")
        expected = identity(attempt.get("expected"), "grid attempt expected")
        if before != manager_current or attempt.get("before_committed") != start["initial_committed"]:
            raise ValueError("schedule-grid attempt manager history mismatch")
        if expected != before:
            raise ValueError("schedule-grid attempt expected identity is stale")
        candidate = attempt.get("candidate_handle")
        candidate_gain = attempt.get("candidate_gain")
        if (type(candidate) is not int or candidate == current[0]
                or type(candidate_gain) is not int):
            raise ValueError("schedule-grid candidate is malformed")
        if candidate in gains and gains[candidate] != candidate_gain:
            raise ValueError("schedule-grid candidate gain changed")
        gains[candidate] = candidate_gain
        if attempt["outcome"] == "Busy":
            if (after != before or attempt.get("after_committed") != start["initial_committed"]
                    or attempt.get("published_us") is not None or attempt.get("receipt") is not None):
                raise ValueError("schedule-grid Busy attempt mutated publication")
        elif attempt["outcome"] == "Ok":
            receipt = attempt.get("receipt")
            if (receipt is None or identity(receipt.get("previous"), "grid receipt previous") != before
                    or identity(receipt.get("installed"), "grid receipt installed") != after
                    or after != (candidate, before[1] + 1)
                    or attempt.get("after_committed") != start["initial_committed"]
                    or receipt.get("admission_delta") != 0
                    or receipt.get("committed") != start["initial_committed"]):
                raise ValueError("schedule-grid receipt history mismatch")
            when = attempt.get("published_us")
            if type(when) is not int or when != attempt.get("scheduled_us"):
                raise ValueError("schedule-grid publication timestamp mismatch")
            if when in publications:
                raise ValueError("duplicate schedule-grid publication timestamp")
            publications[when] = after
            manager_current = after
        else:
            raise ValueError("unexpected schedule-grid attempt outcome")

    dispatch_records = [record for record in records if record.get("kind") == "dispatch"]
    dispatches = {record.get("scheduled_us"): record for record in dispatch_records}
    if (len(dispatch_records) != 8000 or len(dispatches) != len(dispatch_records)
            or set(dispatches) != set(range(0, duration, 1000))):
        raise ValueError("schedule-grid dispatch coverage mismatch")
    completions_by_time = defaultdict(list)
    seen_completions = set()
    for record in records:
        if record.get("kind") == "completion":
            invocation = record.get("invocation")
            if type(invocation) is not int or invocation in seen_completions:
                raise ValueError("duplicate or malformed schedule-grid completion")
            seen_completions.add(invocation)
            completions_by_time[record["completion_us"]].append(record)
    mesh = set(range(0, duration + 1, 100))
    mesh.update(tick + hold for tick in range(0, duration, 1000))
    for base in start["proposal_bases_us"]:
        primary = base + phase
        ordinal = 0
        while True:
            scheduled = (primary if ordinal == 0 else base + ordinal * 1000
                         + (phase + start["retry_phase_step_us"] * ordinal) % 1000)
            if scheduled >= primary + start["retry_deadline_us"]:
                break
            mesh.add(scheduled)
            ordinal += 1

    velocity = 0.0
    held_command = 0.0
    prior = 0
    current_snapshot = current
    active = {}
    pre_errors, post_errors = [], []
    command_integral = 0.0
    max_command = 0.0
    max_error = 0.0
    saturated = violations = overlaps = retired = completed = 0
    transition = execution = empty = 0
    for time_us in sorted(mesh):
        if prior < duration:
            end = min(time_us, duration)
            delta = end - prior
            command_integral += abs(held_command) * delta
            if delta:
                mass = 1.0 if prior < 4_000_000 else 2.0
                velocity += (delta / 1_000_000.0) * (held_command - velocity) / mass
        prior = time_us
        for completion in sorted(completions_by_time.get(time_us, []),
                                 key=lambda row: row["invocation"]):
            if hold == 0:
                continue
            invocation = completion["invocation"]
            dispatch = active.pop(invocation, None)
            if dispatch is None:
                raise ValueError("schedule-grid completion lacks a started dispatch")
            captured = identity(completion["captured_installation"], "grid completion")
            if captured != identity(dispatch["captured_installation"], "grid dispatch"):
                raise ValueError("schedule-grid completion identity changed")
            if completion.get("gain") != dispatch.get("gain"):
                raise ValueError("schedule-grid completion gain changed")
            command_value = completion.get("command")
            close(command_value, dispatch["command"], "grid completion command")
            is_retired = captured != current_snapshot
            if completion.get("retired_after_publication") != is_retired:
                raise ValueError("schedule-grid retired completion classification mismatch")
            if identity(completion.get("published_installation"),
                        "grid completion publication") != current_snapshot:
                raise ValueError("schedule-grid completion publication mismatch")
            retired += is_retired
            completed += 1
            held_command = command_value
            max_command = max(max_command, abs(command_value))
            saturated += abs(command_value) == 4.0
            violations += abs(command_value) > start.get("command_bound", 4.0)
        if time_us in publications:
            current_snapshot = publications[time_us]
        if time_us < duration and time_us % 1000 == 0:
            dispatch = dispatches[time_us]
            reference = reference_at(time_us)
            error = reference - velocity
            (pre_errors if time_us < 4_000_000 else post_errors).append(error * error)
            max_error = max(max_error, abs(error))
            close(dispatch.get("velocity"), velocity, "schedule-grid plant evolution")
            close(dispatch.get("reference"), reference, "schedule-grid reference")
            outcome = dispatch.get("outcome")
            if outcome == "Started":
                captured = identity(dispatch["captured_installation"], "grid dispatch")
                if captured != current_snapshot:
                    raise ValueError("schedule-grid dispatch captured stale publication")
                if dispatch.get("gain") != gains.get(captured[0]):
                    raise ValueError("schedule-grid dispatch gain/identity mismatch")
                expected_command = command_for(dispatch["gain"], reference, velocity)
                close(dispatch.get("command"), expected_command, "schedule-grid command")
                if dispatch.get("completion_us") != time_us + hold:
                    raise ValueError("schedule-grid completion timestamp mismatch")
                overlaps += sum(identity(prior_dispatch["captured_installation"], "active grid dispatch")
                                != captured for prior_dispatch in active.values())
                if hold != 0:
                    active[dispatch["tick"]] = dispatch
            elif outcome == "TransitionBusy":
                transition += 1
            elif outcome == "ExecutionBusy":
                execution += 1
            elif outcome == "Empty":
                empty += 1
            else:
                raise ValueError("unexpected schedule-grid dispatch outcome")
        if hold == 0:
            for completion in completions_by_time.get(time_us, []):
                dispatch = dispatches.get(time_us)
                if dispatch is None or completion["invocation"] != dispatch["tick"]:
                    raise ValueError("zero-hold completion lacks its dispatch")
                if dispatch.get("outcome") != "Started":
                    raise ValueError("zero-hold completion follows skipped dispatch")
                captured = identity(completion["captured_installation"], "grid completion")
                if captured != current_snapshot:
                    raise ValueError("zero-hold completion captured stale publication")
                if completion.get("gain") != dispatch.get("gain"):
                    raise ValueError("zero-hold completion gain changed")
                close(completion["command"], dispatch["command"], "grid completion command")
                if completion.get("retired_after_publication"):
                    raise ValueError("zero-hold completion cannot be retired")
                if identity(completion.get("published_installation"),
                            "grid completion publication") != current_snapshot:
                    raise ValueError("zero-hold completion publication mismatch")
                completed += 1
                held_command = completion["command"]
                max_command = max(max_command, abs(held_command))
                saturated += abs(held_command) == 4.0
                violations += abs(held_command) > start.get("command_bound", 4.0)
    if active:
        raise ValueError("schedule-grid invocation outlived event mesh")
    started = sum(dispatch.get("outcome") == "Started" for dispatch in dispatch_records)
    if completed != started or completed != len(seen_completions):
        raise ValueError("schedule-grid started/completed invocation mismatch")
    return {
        "scheduled_ticks": 8000, "completed_invocations": completed,
        "pre_rmse": math.sqrt(sum(pre_errors) / len(pre_errors)),
        "post_rmse": math.sqrt(sum(post_errors) / len(post_errors)),
        "max_abs_error": max_error, "max_abs_command": max_command,
        "abs_command_integral_us": command_integral,
        "saturated_completions": saturated, "command_bound_violations": violations,
        "old_new_overlaps": overlaps, "retired_commands": retired,
        "transition_skips": transition, "execution_skips": execution, "empty_skips": empty,
        "final_installation": manager_current,
    }


def reduce_schedule_run(records):
    start, end = _one(records, "run_start"), _one(records, "run_end")
    key = (start.get("protocol"), start.get("hold_us"), start.get("phase_us"))
    if key[0] not in GRID_PROTOCOLS or key[1] not in GRID_HOLDS_US or key[2] not in GRID_PHASES_US:
        raise ValueError("invalid schedule-grid run identity")
    if any((record.get("protocol"), record.get("hold_us"), record.get("phase_us")) != key
           for record in records):
        raise ValueError("schedule-grid record identity changed within a run")
    if any(record.get("schema") != 1 or record.get("experiment") != "schedule_grid"
           or record.get("kind") not in {"run_start", "attempt", "dispatch", "completion", "run_end"}
           for record in records):
        raise ValueError("schedule-grid record schema/kind mismatch")
    integer_fields = (
        "scheduled_ticks", "completed_invocations", "attempted_updates", "successful_updates",
        "busy_attempts", "retry_attempts", "deadline_censored", "old_new_overlaps",
        "retired_commands", "saturated_completions", "command_bound_violations",
        "transition_skips", "execution_skips", "empty_skips", "final_gain", "final_committed",
    )
    for field in integer_fields:
        _nonnegative(end, field)
    if end["scheduled_ticks"] != 8000:
        raise ValueError("schedule-grid run has wrong control denominator")
    if end["successful_updates"] + end["deadline_censored"] != 4:
        raise ValueError("schedule-grid update denominator mismatch")
    attempts = [record for record in records if record.get("kind") == "attempt"]
    if len(attempts) != end["attempted_updates"]:
        raise ValueError("schedule-grid attempt denominator mismatch")
    for attempt in attempts:
        proposal = attempt.get("proposal")
        if type(proposal) is not int or proposal not in range(4):
            raise ValueError("schedule-grid attempt has invalid proposal")
        if attempt.get("scheduled_us", 0) >= attempt.get("deadline_us", 0):
            raise ValueError("schedule-grid attempt reached its deadline")
        for name in ("expected", "before_installation", "after_installation"):
            identity(attempt.get(name), f"grid {name}")
        published = attempt.get("published_us")
        returned = attempt.get("returned_us")
        if type(returned) is not int or returned < attempt["scheduled_us"]:
            raise ValueError("grid return time is invalid")
        if published is not None and (type(published) is not int or published > returned):
            raise ValueError("grid publication/return order is invalid")
    request_rows = []
    bases = start.get("proposal_bases_us")
    if not isinstance(bases, list) or len(bases) != 4:
        raise ValueError("schedule-grid proposal bases are incomplete")
    for proposal, base in enumerate(bases):
        members = sorted((attempt for attempt in attempts if attempt.get("proposal") == proposal),
                         key=lambda attempt: attempt["ordinal"])
        if not members or [attempt["ordinal"] for attempt in members] != list(range(len(members))):
            raise ValueError("schedule-grid request attempt sequence is incomplete")
        primary = base + key[2]
        deadline = primary + start.get("retry_deadline_us", 0)
        expected = identity(members[0].get("before_installation"), "grid request expected")
        candidate = members[0].get("candidate_handle")
        candidate_gain = (2, 4, 8, 16)[proposal]
        if (any(identity(member.get("expected"), "grid request expected") != expected
                or member.get("candidate_handle") != candidate
                or member.get("candidate_gain") != candidate_gain for member in members)
                or any(member["deadline_us"] != deadline for member in members)
                or any(member["scheduled_us"] != (
                    primary if ordinal == 0 else base + ordinal * 1000
                    + (key[2] + start["retry_phase_step_us"] * ordinal) % 1000)
                    for ordinal, member in enumerate(members))):
            raise ValueError("schedule-grid request schedule is inconsistent")
        success = [attempt for attempt in members if attempt.get("outcome") == "Ok"]
        censored = not success
        if len(success) > 1:
            raise ValueError("schedule-grid request completion is inconsistent")
        published = None if censored else success[0]["published_us"]
        returned = None if censored else success[0]["returned_us"]
        request_rows.append({
            "protocol": key[0], "hold_us": key[1], "phase_us": key[2],
            "proposal": proposal, "primary_us": primary, "deadline_us": deadline,
            "attempts": len(members),
            "busy_attempts": sum(m.get("outcome") == "Busy" for m in members),
            "retries": len(members) - 1, "completed": not censored, "censored": censored,
            "published_us": published, "returned_us": returned,
            "publication_delay_us": None if censored else published - primary,
            "return_delay_us": None if censored else returned - primary,
        })
    if sum(request["censored"] for request in request_rows) != end["deadline_censored"]:
        raise ValueError("schedule-grid censored-request count mismatch")
    raw_counts = {
        "successful_updates": sum(attempt.get("outcome") == "Ok" for attempt in attempts),
        "busy_attempts": sum(attempt.get("outcome") == "Busy" for attempt in attempts),
        "retry_attempts": sum(attempt.get("ordinal", 0) > 0 for attempt in attempts),
    }
    for field, value in raw_counts.items():
        if end[field] != value:
            raise ValueError(f"schedule-grid {field} disagrees with attempts")
    computed = _recompute_schedule(start, records, attempts)
    for field in ("scheduled_ticks", "completed_invocations", "saturated_completions",
                  "command_bound_violations", "old_new_overlaps", "retired_commands",
                  "transition_skips", "execution_skips", "empty_skips"):
        if computed[field] != end[field]:
            raise ValueError(f"schedule-grid {field} disagrees with raw events")
    for field in ("pre_rmse", "post_rmse", "max_abs_error", "max_abs_command",
                  "abs_command_integral_us"):
        close(end[field], computed[field], f"schedule-grid {field}")
    if identity(end.get("final_installation"), "grid final") != computed["final_installation"]:
        raise ValueError("schedule-grid final installation disagrees with attempts")
    final_handle = computed["final_installation"][0]
    final_gain = (start["initial_gain"] if final_handle == start["initial_installation"][0]
                  else next(attempt["candidate_gain"] for attempt in attempts
                            if attempt["candidate_handle"] == final_handle))
    if end["final_gain"] != final_gain:
        raise ValueError("schedule-grid final gain disagrees with attempts")
    if end["final_committed"] != start.get("initial_committed"):
        raise ValueError("schedule-grid final committed charge changed")
    row = {"protocol": key[0], "hold_us": key[1], "phase_us": key[2]}
    row.update({field: end[field] for field in integer_fields})
    for field in ("pre_rmse", "post_rmse", "max_abs_error", "max_abs_command",
                  "abs_command_integral_us"):
        value = end.get(field)
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"schedule-grid invalid {field}")
        row[field] = value
    busy_primaries = sum(request["busy_attempts"] > 0 for request in request_rows)
    retried_successes = sum(request["completed"] and request["retries"] > 0
                            for request in request_rows)
    row.update({
        "busy_primaries": busy_primaries,
        "retried_successes": retried_successes,
        "activation_rate": conditional_rate(end["successful_updates"], 4),
        "busy_rate_per_attempt": conditional_rate(end["busy_attempts"], end["attempted_updates"]),
        "retry_success_rate": conditional_rate(retried_successes, busy_primaries),
        "overlaps_per_activation": conditional_rate(end["old_new_overlaps"], end["successful_updates"]),
        "retired_commands_per_activation": conditional_rate(
            end["retired_commands"], end["successful_updates"]),
    })
    return row, request_rows


def _integral_abs_command(records, start_us, end_us, initial):
    changes = sorted((record["completion_us"], record["command"])
                     for record in records if record.get("kind") == "completion")
    command = initial
    cursor = start_us
    total = 0.0
    for when, next_command in changes:
        if when <= start_us:
            command = next_command
            continue
        if when >= end_us:
            break
        total += abs(command) * (when - cursor)
        cursor, command = when, next_command
    return total + abs(command) * (end_us - cursor)


def _recompute_corrective(start, records, attempts):
    duration = start["duration_us"]
    fault = start["fault_us"]
    period = start["control_period_us"]
    initial = identity(start["initial_installation"], "corrective initial")
    zero_handle = _nonnegative(start, "zero_handle")
    current = initial
    publications = {}
    for attempt in sorted(attempts, key=lambda row: row["scheduled_us"]):
        before = identity(attempt.get("before_installation"), "corrective attempt before")
        after = identity(attempt.get("after_installation"), "corrective attempt after")
        expected = identity(attempt.get("expected"), "corrective expected")
        if before != current or expected != initial or attempt.get("candidate_handle") != zero_handle:
            raise ValueError("corrective attempt identity history mismatch")
        if (attempt.get("before_committed") != start["initial_committed"]
                or attempt.get("after_committed") != start["initial_committed"]):
            raise ValueError("corrective attempt ledger history mismatch")
        outcome = attempt.get("outcome")
        if outcome == "Busy":
            if (after != before or attempt.get("receipt") is not None
                    or attempt.get("published_us") is not None):
                raise ValueError("corrective Busy attempt mutated publication")
        elif outcome == "Ok":
            receipt = attempt.get("receipt")
            if (receipt is None
                    or identity(receipt.get("previous"), "corrective receipt previous") != before
                    or identity(receipt.get("installed"), "corrective receipt installed") != after
                    or after != (zero_handle, before[1] + 1)
                    or receipt.get("admission_delta") != 0
                    or receipt.get("committed") != start["initial_committed"]):
                raise ValueError("corrective receipt history mismatch")
            published = attempt.get("published_us")
            returned = attempt.get("returned_us")
            if not isinstance(published, int) or not isinstance(returned, int) or published > returned:
                raise ValueError("corrective publication/return order is invalid")
            if published in publications:
                raise ValueError("duplicate corrective publication timestamp")
            publications[published] = after
            current = after
        else:
            raise ValueError("unexpected corrective attempt outcome")

    dispatch_records = [record for record in records if record.get("kind") == "dispatch"]
    dispatches = {record.get("scheduled_us"): record for record in dispatch_records}
    expected_ticks = set(range(0, duration, period))
    if len(dispatches) != len(dispatch_records) or set(dispatches) != expected_ticks:
        raise ValueError("corrective dispatch coverage mismatch")
    completions_by_time = defaultdict(list)
    completion_records = [record for record in records if record.get("kind") == "completion"]
    seen_completions = set()
    for completion in completion_records:
        invocation = completion.get("invocation")
        if type(invocation) is not int or invocation in seen_completions:
            raise ValueError("duplicate or malformed corrective completion")
        seen_completions.add(invocation)
        completions_by_time[completion.get("completion_us")].append(completion)

    mesh = set(range(0, duration + 1, start["step_max_us"]))
    for tick in expected_ticks:
        hold = start["long_hold_us"] if tick == start["long_start_us"] else start["normal_hold_us"]
        mesh.add(tick + hold)
    ordinal = 0
    while True:
        scheduled = (fault if ordinal == 0 else fault + ordinal * 1000
                     + (start["retry_phase_step_us"] * ordinal) % 1000)
        if scheduled >= fault + start["retry_deadline_us"]:
            break
        mesh.add(scheduled)
        ordinal += 1

    velocity = start["initial_velocity"]
    held_command = start["initial_command"]
    reference = start["reference"]
    prior = 0
    snapshot = initial
    active = {}
    fault_integral = 0.0
    publication_integral = 0.0
    successful = [attempt for attempt in attempts if attempt["outcome"] == "Ok"]
    publication = successful[0]["published_us"] if len(successful) == 1 else None
    max_velocity = 0.0
    max_error = 0.0
    below_since = None
    stop_entry = None
    stop_confirmed = None
    retired = saturated = violations = completed = 0
    transition = execution = empty_count = 0
    for time_us in sorted(mesh):
        if prior < duration:
            end = min(time_us, duration)
            if end > prior:
                if end > fault:
                    fault_integral += abs(held_command) * (end - max(prior, fault))
                if publication is not None and end > publication:
                    publication_integral += abs(held_command) * (end - max(prior, publication))
                velocity += ((end - prior) / 1_000_000.0) * (held_command - velocity) / start["mass"]
        prior = time_us

        for completion in sorted(completions_by_time.get(time_us, []),
                                 key=lambda row: row["invocation"]):
            invocation = completion["invocation"]
            dispatch = active.pop(invocation, None)
            if dispatch is None:
                raise ValueError("corrective completion lacks a started dispatch")
            captured = identity(completion.get("captured_installation"),
                                "corrective completion")
            if captured != identity(dispatch.get("captured_installation"),
                                    "corrective dispatch"):
                raise ValueError("corrective completion identity changed")
            if completion.get("gain") != dispatch.get("gain"):
                raise ValueError("corrective completion gain changed")
            close(completion.get("command"), dispatch.get("command"),
                  "corrective completion command")
            if completion.get("hold_us") != completion["completion_us"] - dispatch["scheduled_us"]:
                raise ValueError("corrective completion hold mismatch")
            is_retired = captured != snapshot
            if completion.get("retired_after_publication") != is_retired:
                raise ValueError("corrective retired completion classification mismatch")
            if identity(completion.get("published_installation"),
                        "corrective completion publication") != snapshot:
                raise ValueError("corrective completion publication mismatch")
            retired += is_retired
            held_command = completion["command"]
            saturated += abs(held_command) == start["command_bound"]
            violations += abs(held_command) > start["command_bound"]
            completed += 1

        if time_us in publications:
            snapshot = publications[time_us]

        if time_us in dispatches:
            dispatch = dispatches[time_us]
            if dispatch.get("tick") != time_us // period:
                raise ValueError("corrective dispatch tick mismatch")
            close(dispatch.get("velocity"), velocity, "corrective plant evolution")
            close(dispatch.get("reference"), reference, "corrective reference")
            outcome = dispatch.get("outcome")
            if outcome == "Started":
                captured = identity(dispatch.get("captured_installation"),
                                    "corrective dispatch")
                if captured != snapshot:
                    raise ValueError("corrective dispatch captured stale publication")
                gain = dispatch.get("gain")
                expected_gain = 1 if captured == initial else 0
                if gain != expected_gain:
                    raise ValueError("corrective dispatch gain/identity mismatch")
                close(dispatch.get("command"), command_for(gain, reference, velocity),
                      "corrective command")
                hold = (start["long_hold_us"] if time_us == start["long_start_us"]
                        else start["normal_hold_us"])
                if dispatch.get("completion_us") != time_us + hold:
                    raise ValueError("corrective completion timestamp mismatch")
                active[dispatch["tick"]] = dispatch
            elif outcome == "TransitionBusy":
                transition += 1
            elif outcome == "ExecutionBusy":
                execution += 1
            elif outcome == "Empty":
                empty_count += 1
            else:
                raise ValueError("unexpected corrective dispatch outcome")

        if fault <= time_us <= duration:
            max_velocity = max(max_velocity, abs(velocity))
            max_error = max(max_error, abs(reference - velocity))
            if stop_confirmed is None:
                if abs(velocity) <= start["stop_band"]:
                    if below_since is None:
                        below_since = time_us
                    if time_us - below_since >= start["stop_dwell_us"]:
                        stop_entry, stop_confirmed = below_since, time_us
                else:
                    below_since = None
    if active:
        raise ValueError("corrective invocation outlived event mesh")
    return {
        "published_us": publication, "stop_entry_us": stop_entry,
        "stop_confirmed_us": stop_confirmed, "stop_censored": stop_confirmed is None,
        "fault_abs_command_integral_us": fault_integral,
        "publication_abs_command_integral_us": publication_integral,
        "max_post_fault_abs_velocity": max_velocity,
        "max_post_fault_abs_error": max_error,
        "attempts": len(attempts),
        "busy_attempts": sum(attempt["outcome"] == "Busy" for attempt in attempts),
        "retries": sum(attempt["ordinal"] > 0 for attempt in attempts),
        "transition_skips": transition, "execution_skips": execution,
        "empty_skips": empty_count, "retired_commands": retired,
        "saturated_completions": saturated, "command_bound_violations": violations,
        "final_installation": current, "final_gain": 0 if current[0] == zero_handle else 1,
        "completed_invocations": completed,
    }


def reduce_corrective_run(records):
    start, end = _one(records, "run_start"), _one(records, "run_end")
    duration = _nonnegative(start, "duration_us")
    fault = _nonnegative(start, "fault_us")
    initial_command = start.get("initial_command")
    if not isinstance(initial_command, (int, float)) or not math.isfinite(initial_command):
        raise ValueError("invalid corrective initial command")
    fault_integral = _integral_abs_command(records, fault, duration, initial_command)
    close(end.get("fault_abs_command_integral_us"), fault_integral, "command integral from fault")
    published = end.get("published_us")
    if not isinstance(published, int) or not fault <= published < duration:
        raise ValueError("invalid corrective publication time")
    publication_integral = _integral_abs_command(records, published, duration, initial_command)
    close(end.get("publication_abs_command_integral_us"), publication_integral,
          "command integral from publication")
    if start.get("protocol") not in GRID_PROTOCOLS or any(
            record.get("protocol") != start["protocol"]
            or record.get("experiment") != "corrective_stop" for record in records):
        raise ValueError("corrective run identity changed")
    required = {
        "duration_us": 8_000_000, "step_max_us": 100, "control_period_us": 1000,
        "retry_phase_step_us": 137, "retry_deadline_us": 20_000,
        "fault_us": 4_250_000, "long_start_us": 4_249_000,
        "long_hold_us": 2_000, "normal_hold_us": 100,
        "initial_velocity": 1.0, "initial_command": 1.0,
        "reference": 2.0, "mass": 1.0, "command_bound": 4.0,
        "stop_band": 0.05, "stop_dwell_us": 100_000,
    }
    if any(start.get(key) != value for key, value in required.items()):
        raise ValueError("corrective configuration mismatch")
    attempts = sorted((record for record in records if record.get("kind") == "attempt"),
                      key=lambda row: row.get("ordinal", -1))
    if (not attempts or [attempt.get("ordinal") for attempt in attempts] != list(range(len(attempts)))
            or sum(attempt.get("outcome") == "Ok" for attempt in attempts) != 1):
        raise ValueError("corrective attempt sequence is incomplete")
    deadline = fault + start["retry_deadline_us"]
    for ordinal, attempt in enumerate(attempts):
        scheduled = (fault if ordinal == 0 else fault + ordinal * 1000
                     + (start["retry_phase_step_us"] * ordinal) % 1000)
        if (attempt.get("scheduled_us") != scheduled or attempt.get("deadline_us") != deadline
                or scheduled >= deadline):
            raise ValueError("corrective retry schedule mismatch")
    computed = _recompute_corrective(start, records, attempts)
    integer_fields = (
        "published_us", "attempts", "busy_attempts", "retries", "transition_skips",
        "execution_skips", "empty_skips", "retired_commands", "saturated_completions",
        "command_bound_violations", "final_gain",
    )
    for field in integer_fields:
        _nonnegative(end, field)
        if end[field] != computed[field]:
            raise ValueError(f"corrective {field} disagrees with raw events")
    if identity(end.get("final_installation"), "corrective final") != computed["final_installation"]:
        raise ValueError("corrective final installation disagrees with attempts")
    for field in ("fault_abs_command_integral_us", "publication_abs_command_integral_us",
                  "max_post_fault_abs_velocity", "max_post_fault_abs_error"):
        close(end.get(field), computed[field], f"corrective {field}")
    for field in ("stop_entry_us", "stop_confirmed_us", "stop_censored"):
        if end.get(field) != computed[field]:
            raise ValueError(f"corrective {field} disagrees with raw events")
    row = {"protocol": start["protocol"], **{key: end[key] for key in end
           if key not in ("schema", "experiment", "kind", "protocol")}}
    row["fault_us"] = fault
    row["request_publication_delay_us"] = published - fault
    return row


def analyze_stream(trace):
    legacy = []
    schedule_rows = []
    request_rows = []
    corrective_rows = []
    active = None
    with trace.open() as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            experiment = record.get("experiment")
            if experiment is None:
                legacy.append(record)
                continue
            if (record.get("schema") != 1 or record.get("protocol") not in GRID_PROTOCOLS
                    or experiment not in ("schedule_grid", "corrective_stop")):
                raise ValueError("unknown adaptation experiment")
            if record.get("kind") == "run_start":
                if active is not None:
                    raise ValueError("nested adaptation run")
                active = [record]
                continue
            if active is None:
                raise ValueError("adaptation record outside a run")
            if experiment != active[0]["experiment"]:
                raise ValueError("adaptation experiment changed within a run")
            active.append(record)
            if record.get("kind") == "run_end":
                if active[0]["experiment"] == "schedule_grid":
                    row, requests = reduce_schedule_run(active)
                    schedule_rows.append(row)
                    request_rows.extend(requests)
                else:
                    corrective_rows.append(reduce_corrective_run(active))
                active = None
    if active is not None:
        raise ValueError("unterminated adaptation run")
    report = analyze(legacy) if legacy else {}
    if schedule_rows:
        expected = {(protocol, hold, phase) for protocol in GRID_PROTOCOLS
                    for hold in GRID_HOLDS_US for phase in GRID_PHASES_US}
        actual = {(row["protocol"], row["hold_us"], row["phase_us"])
                  for row in schedule_rows}
        if actual != expected or len(schedule_rows) != len(expected):
            raise ValueError("schedule-grid coverage is incomplete")
        report["schedule_grid"] = schedule_rows
        report["schedule_requests"] = request_rows
    if corrective_rows:
        if {row["protocol"] for row in corrective_rows} != set(GRID_PROTOCOLS) or len(corrective_rows) != 2:
            raise ValueError("corrective-stop coverage is incomplete")
        report["corrective_stop"] = corrective_rows
    return report


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
    payload = {**report, "trace_sha256": file_digest(trace),
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
        f"{file_digest(path)}  {path.relative_to(destination)}\n"
        for path in checksum_paths))


def _write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def distribution(values):
    values = sorted(values)
    if not values:
        return None
    pick = lambda q: values[math.ceil(q * len(values)) - 1]
    return {"count": len(values), "median": pick(0.5), "p99": pick(0.99), "max": values[-1]}


def schedule_aggregates(rows, requests):
    aggregates = []
    for protocol in GRID_PROTOCOLS:
        for hold in GRID_HOLDS_US:
            members = [row for row in rows if row["protocol"] == protocol and row["hold_us"] == hold]
            request_members = [row for row in requests
                               if row["protocol"] == protocol and row["hold_us"] == hold]
            total = lambda field: sum(row[field] for row in members)
            aggregates.append({
                "protocol": protocol, "hold_us": hold, "runs": len(members),
                "scheduled_requests": len(request_members),
                "successful_requests": sum(row["completed"] for row in request_members),
                "censored_requests": sum(row["censored"] for row in request_members),
                "attempts": sum(row["attempts"] for row in request_members),
                "busy_attempts": sum(row["busy_attempts"] for row in request_members),
                "retries": sum(row["retries"] for row in request_members),
                "scheduled_ticks": total("scheduled_ticks"),
                "completed_invocations": total("completed_invocations"),
                "transition_skips": total("transition_skips"),
                "execution_skips": total("execution_skips"),
                "empty_skips": total("empty_skips"),
                "old_new_overlaps": total("old_new_overlaps"),
                "retired_commands": total("retired_commands"),
                "saturated_completions": total("saturated_completions"),
                "command_bound_violations": total("command_bound_violations"),
                "schedules_with_old_new_overlap": sum(row["old_new_overlaps"] > 0 for row in members),
                "schedules_with_retired_command": sum(row["retired_commands"] > 0 for row in members),
                "schedules_with_dispatch_skip": sum(
                    row["transition_skips"] + row["execution_skips"] + row["empty_skips"] > 0
                    for row in members),
                "activation_rate": conditional_rate(
                    sum(row["completed"] for row in request_members), len(request_members)),
                "busy_rate_per_attempt": conditional_rate(
                    sum(row["busy_attempts"] for row in request_members),
                    sum(row["attempts"] for row in request_members)),
                "retry_success_rate": conditional_rate(
                    sum(row["completed"] and row["retries"] > 0 for row in request_members),
                    sum(row["busy_attempts"] > 0 for row in request_members)),
                "publication_delay_us": distribution([
                    row["publication_delay_us"] for row in request_members
                    if row["publication_delay_us"] is not None]),
                "return_delay_us": distribution([
                    row["return_delay_us"] for row in request_members
                    if row["return_delay_us"] is not None]),
                "post_rmse": distribution([row["post_rmse"] for row in members]),
                "max_abs_error": distribution([row["max_abs_error"] for row in members]),
                "max_abs_command": distribution([row["max_abs_command"] for row in members]),
                "abs_command_integral_us": distribution([
                    row["abs_command_integral_us"] for row in members]),
            })
    return aggregates


def write_experiment_artifacts(report, destination):
    rows = report.get("schedule_grid")
    if rows:
        _write_csv(destination / "schedule-grid.csv", rows)
        requests = report["schedule_requests"]
        _write_csv(destination / "schedule-requests.csv", requests)
        aggregates = schedule_aggregates(rows, requests)
        payload = {
            "schema": 1,
            "experiment": "schedule_grid",
            "coverage": {
                "protocols": list(GRID_PROTOCOLS),
                "primary_holds_us": list(GRID_HOLDS_US[:-1]),
                "stress_holds_us": [GRID_HOLDS_US[-1]],
                "phases_us": list(GRID_PHASES_US),
                "runs": len(rows),
                "logical_requests": len(requests),
            },
            "rows": rows,
            "requests": requests,
            "aggregates": aggregates,
            "denominators": {
                "activation_rate": "4 scheduled logical updates per replay",
                "busy_rate_per_attempt": "all attempted primary and retry replacements",
                "retry_success_rate": "primary Busy outcomes; null when none",
                "overlaps_per_activation": "successful activations; null when none",
                "retired_commands_per_activation": "successful activations; null when none",
                "task_metrics": "all 8,000 scheduled control ticks; command integral uses command*us",
            },
        }
        (destination / "schedule-grid.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n")
        lines = [
            "% Generated from the validated deterministic schedule grid.\n",
            r"\begin{tabular}{llrrrr}" + "\n", r"\toprule" + "\n",
            r"Protocol & Hold ($\mu$s) & Runs & Activations/scheduled & Busy/attempts & Censored \\" + "\n",
            r"\midrule" + "\n",
        ]
        for protocol in GRID_PROTOCOLS:
            for hold in GRID_HOLDS_US:
                members = [row for row in rows
                           if row["protocol"] == protocol and row["hold_us"] == hold]
                lines.append(
                    f"{protocol} & {hold} & {len(members)} & "
                    f"{sum(r['successful_updates'] for r in members)}/{4 * len(members)} & "
                    f"{sum(r['busy_attempts'] for r in members)}/"
                    f"{sum(r['attempted_updates'] for r in members)} & "
                    f"{sum(r['deadline_censored'] for r in members)} \\\\\n")
        lines += [r"\bottomrule" + "\n", r"\end{tabular}" + "\n"]
        (destination / "schedule-grid.tex").write_text("".join(lines))
    corrective = report.get("corrective_stop")
    if corrective:
        _write_csv(destination / "corrective-stop.csv", corrective)
        (destination / "corrective-stop.json").write_text(json.dumps({
            "schema": 1,
            "experiment": "corrective_stop",
            "rows": corrective,
            "integral_units": "absolute command times microseconds",
            "common_horizon": "fault_us through duration_us",
            "publication_horizon": "protocol-specific successful publication through duration_us",
        }, indent=2, sort_keys=True) + "\n")
        lines = [
            "% Generated from the validated corrective-stop replay.\n",
            r"\begin{tabular}{lrrrr}" + "\n", r"\toprule" + "\n",
            r"Protocol & Stop entry ($\mu$s) & Confirmed ($\mu$s) & $\int_{fault}|u|dt$ & $\int_{pub}|u|dt$ \\" + "\n",
            r"\midrule" + "\n",
        ]
        for row in corrective:
            entry = "--" if row["stop_entry_us"] is None else str(row["stop_entry_us"])
            confirmed = "--" if row["stop_confirmed_us"] is None else str(row["stop_confirmed_us"])
            lines.append(f"{row['protocol']} & {entry} & {confirmed} & "
                         f"{row['fault_abs_command_integral_us']:.0f} & "
                         f"{row['publication_abs_command_integral_us']:.0f} \\\\\n")
        lines += [r"\bottomrule" + "\n", r"\end{tabular}" + "\n"]
        (destination / "corrective-stop.tex").write_text("".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--write-artifacts", action="store_true")
    parser.add_argument("--output-dir", type=Path,
                        help="write derived files here (implies --write-artifacts)")
    args = parser.parse_args()
    report = analyze_stream(args.trace)
    records = []
    with args.trace.open() as stream:
        for line in stream:
            if line.strip() and '"experiment"' not in line:
                records.append(json.loads(line))
    legacy = {key: report[key] for key in ("config", "initial_committed", "protocols")}
    validate_campaign(legacy, records)
    if args.write_artifacts or args.output_dir:
        destination = args.output_dir or args.trace.parent
        write_experiment_artifacts(report, destination)
        write_artifacts(args.trace, legacy, destination)
    print("PASS: deterministic plant, controller, identity, guard, retry, and ledger replay hold")


if __name__ == "__main__":
    main()
