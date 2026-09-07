#!/usr/bin/env python3
"""Negative-oracle tests for the deterministic adaptation replay."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load_analyzer():
    spec = importlib.util.spec_from_file_location(
        "adaptation_analysis", Path(__file__).with_name("analyze-update-adaptation.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture():
    protocol = "frozen"
    identity = [0, 1]
    receipt = {"previous": None, "installed": identity,
               "admission_delta": 10, "committed": 10}
    config = {
        "schema": 1, "protocol": protocol, "kind": "config",
        "duration_us": 2000, "step_us": 100, "control_period_us": 1000,
        "mass_change_us": 1000, "guard_hold_us": 100,
        "long_start_us": 99_000, "long_hold_us": 2000,
        "initial_gain": 1.0, "pre_ticks": 1, "post_ticks": 1,
        "candidate_count": 0, "initial_installation": identity,
        "initial_receipt": receipt, "initial_committed": 10,
        "handle_gains": [[0, 1.0]],
    }
    velocity_at_one_ms = 1.0 - 0.9999 ** 9
    controls = [
        {"schema": 1, "protocol": protocol, "kind": "control", "tick": 0,
         "scheduled_us": 0, "phase": "pre", "mass": 1.0, "reference": 1.0,
         "velocity": 0.0, "error_sq": 1.0, "held_command": 0.0,
         "dispatch_outcome": "Started"},
        {"schema": 1, "protocol": protocol, "kind": "control", "tick": 1,
         "scheduled_us": 1000, "phase": "post", "mass": 2.0, "reference": 1.0,
         "velocity": velocity_at_one_ms, "error_sq": (1.0 - velocity_at_one_ms) ** 2,
         "held_command": 1.0, "dispatch_outcome": "Started"},
    ]
    invocations = []
    completions = []
    for tick, control in enumerate(controls):
        command = control["reference"] - control["velocity"]
        invocations.append({
            "schema": 1, "protocol": protocol, "kind": "invocation",
            "invocation": tick, "tick": tick, "start_us": control["scheduled_us"],
            "requested_hold_us": 100, "outcome": "Started",
            "captured_installation": identity, "captured_gain": 1.0,
            "captured_velocity": control["velocity"],
            "captured_reference": control["reference"],
            "captured_command": command, "completion_us": control["scheduled_us"] + 100,
        })
        completions.append({
            "schema": 1, "protocol": protocol, "kind": "completion",
            "invocation": tick, "completion_us": control["scheduled_us"] + 100,
            "captured_installation": identity, "captured_gain": 1.0,
            "captured_command": command, "published_installation": identity,
            "retired_after_publication": False,
        })
    summary = {
        "schema": 1, "protocol": protocol, "kind": "summary",
        "pre_ticks": 1, "post_ticks": 1, "pre_rmse": 1.0,
        "post_rmse": abs(1.0 - velocity_at_one_ms),
        "started_invocations": 2, "completed_invocations": 2,
        "guard_version_overlaps": 0, "retired_commands_after_publication": 0,
        "transition_skips": 0, "execution_skips": 0,
        "scheduled_attempt_events": 0, "actual_attempts": 0,
        "busy_attempts": 0, "retry_attempts": 0, "successful_retries": 0,
        "activations": 0, "stale_errors": 0, "stale_accepted": 0,
        "accounting_errors": 0, "final_installation": identity,
        "final_gain": 1.0, "final_committed": 10,
    }
    return [config, *controls, *invocations, *completions, summary]


def one_valid_grid_run():
    duration = 8_000_000
    bases = [4_250_000, 4_500_000, 4_750_000, 5_000_000]
    start = {
        "schema": 1, "experiment": "schedule_grid", "protocol": "atomic",
        "kind": "run_start", "hold_us": 0, "phase_us": 0,
        "duration_us": duration, "step_max_us": 100, "control_period_us": 1000,
        "mass_change_us": 4_000_000, "initial_gain": 1,
        "proposal_bases_us": bases, "retry_phase_step_us": 137,
        "retry_deadline_us": 20_000, "command_bound": 4.0,
        "initial_installation": [0, 1], "initial_committed": 10,
    }
    records = [start]
    current = [0, 1]
    publications = {}
    for proposal, (base, gain) in enumerate(zip(bases, (2, 4, 8, 16))):
        installed = [proposal + 1, proposal + 2]
        records.append({
            "schema": 1, "experiment": "schedule_grid", "protocol": "atomic",
            "kind": "attempt", "hold_us": 0, "phase_us": 0,
            "proposal": proposal, "ordinal": 0, "scheduled_us": base,
            "deadline_us": base + 20_000, "expected": current,
            "candidate_handle": proposal + 1, "candidate_gain": gain, "outcome": "Ok",
            "published_us": base, "returned_us": base,
            "receipt": {"previous": current, "installed": installed,
                        "admission_delta": 0, "committed": 10},
            "before_installation": current, "after_installation": installed,
            "before_committed": 10, "after_committed": 10,
        })
        publications[base] = (installed, gain)
        current = installed

    current = [0, 1]
    gain = 1
    velocity = 0.0
    held_command = 0.0
    pre_errors, post_errors = [], []
    max_error = max_command = command_integral = 0.0
    saturated = 0
    mesh = set(range(0, duration + 1, 100))
    for base in bases:
        ordinal = 0
        while True:
            scheduled = base if ordinal == 0 else base + ordinal * 1000 + (137 * ordinal) % 1000
            if scheduled >= base + 20_000:
                break
            mesh.add(scheduled)
            ordinal += 1
    prior = 0
    for time_us in sorted(mesh):
        if time_us:
            delta = time_us - prior
            mass = 1.0 if prior < 4_000_000 else 2.0
            command_integral += abs(held_command) * delta
            velocity += (delta / 1_000_000.0) * (held_command - velocity) / mass
        prior = time_us
        if time_us == duration or time_us % 1000:
            continue
        if time_us in publications:
            current, gain = publications[time_us]
        tick = time_us // 1000
        reference = 1.0 if (time_us // 1_000_000) % 2 == 0 else -1.0
        error = reference - velocity
        (pre_errors if time_us < 4_000_000 else post_errors).append(error * error)
        max_error = max(max_error, abs(error))
        command = max(-4.0, min(4.0, gain * error))
        max_command = max(max_command, abs(command))
        saturated += abs(command) == 4.0
        dispatch = {
            "schema": 1, "experiment": "schedule_grid", "protocol": "atomic",
            "kind": "dispatch", "hold_us": 0, "phase_us": 0, "tick": tick,
            "scheduled_us": time_us, "outcome": "Started",
            "captured_installation": current, "gain": gain, "velocity": velocity,
            "reference": reference, "command": command, "completion_us": time_us,
        }
        records.extend([dispatch, {
            "schema": 1, "experiment": "schedule_grid", "protocol": "atomic",
            "kind": "completion", "hold_us": 0, "phase_us": 0,
            "invocation": tick, "completion_us": time_us,
            "captured_installation": current, "gain": gain, "command": command,
            "published_installation": current, "retired_after_publication": False,
        }])
        held_command = command
    records.append({
        "schema": 1, "experiment": "schedule_grid", "protocol": "atomic",
        "kind": "run_end", "hold_us": 0, "phase_us": 0,
        "scheduled_ticks": 8000, "completed_invocations": 8000,
        "attempted_updates": 4, "successful_updates": 4, "busy_attempts": 0,
        "retry_attempts": 0, "deadline_censored": 0, "old_new_overlaps": 0,
        "retired_commands": 0,
        "pre_rmse": (sum(pre_errors) / 4000) ** 0.5,
        "post_rmse": (sum(post_errors) / 4000) ** 0.5,
        "max_abs_error": max_error, "max_abs_command": max_command,
        "abs_command_integral_us": command_integral,
        "saturated_completions": saturated, "command_bound_violations": 0,
        "transition_skips": 0, "execution_skips": 0, "empty_skips": 0,
        "final_installation": current, "final_gain": gain, "final_committed": 10,
    })
    return records


def one_valid_corrective_run():
    duration, fault, period = 8_000_000, 4_250_000, 1000
    initial, installed = [0, 1], [1, 2]
    start = {
        "schema": 1, "experiment": "corrective_stop", "protocol": "atomic",
        "kind": "run_start", "duration_us": duration, "step_max_us": 100,
        "control_period_us": period, "retry_phase_step_us": 137,
        "retry_deadline_us": 20_000, "fault_us": fault, "stop_band": 0.05,
        "stop_dwell_us": 100_000, "initial_velocity": 1.0,
        "initial_command": 1.0, "reference": 2.0, "mass": 1.0,
        "command_bound": 4.0, "long_start_us": 4_249_000,
        "long_hold_us": 2_000, "normal_hold_us": 100,
        "initial_installation": initial, "initial_committed": 10, "zero_handle": 1,
    }
    records = [start, {
        "schema": 1, "experiment": "corrective_stop", "protocol": "atomic",
        "kind": "attempt", "ordinal": 0, "scheduled_us": fault,
        "deadline_us": fault + 20_000, "expected": initial,
        "candidate_handle": 1, "outcome": "Ok", "published_us": fault,
        "returned_us": 4_251_000,
        "receipt": {"previous": initial, "installed": installed,
                    "admission_delta": 0, "committed": 10},
        "before_installation": initial, "after_installation": installed,
        "before_committed": 10, "after_committed": 10,
    }]
    mesh = set(range(0, duration + 1, 100))
    for tick in range(0, duration, period):
        mesh.add(tick + (2000 if tick == 4_249_000 else 100))
    ordinal = 0
    while True:
        scheduled = fault if ordinal == 0 else fault + ordinal * 1000 + (137 * ordinal) % 1000
        if scheduled >= fault + 20_000:
            break
        mesh.add(scheduled)
        ordinal += 1

    velocity = held_command = 1.0
    current = initial
    prior = 0
    active = {}
    completions = {}
    fault_integral = publication_integral = 0.0
    max_velocity = max_error = 0.0
    below_since = stop_entry = stop_confirmed = None
    retired = saturated = violations = 0
    for time_us in sorted(mesh):
        if time_us:
            delta = time_us - prior
            if time_us > fault:
                fault_integral += abs(held_command) * (time_us - max(prior, fault))
                publication_integral += abs(held_command) * (time_us - max(prior, fault))
            velocity += (delta / 1_000_000.0) * (held_command - velocity)
        prior = time_us
        for tick in sorted(completions.get(time_us, [])):
            dispatch = active.pop(tick)
            held_command = dispatch["command"]
            is_retired = dispatch["captured_installation"] != current
            retired += is_retired
            saturated += abs(held_command) == 4.0
            violations += abs(held_command) > 4.0
            records.append({
                "schema": 1, "experiment": "corrective_stop", "protocol": "atomic",
                "kind": "completion", "hold_us": time_us - dispatch["scheduled_us"],
                "phase_us": None, "invocation": tick, "completion_us": time_us,
                "captured_installation": dispatch["captured_installation"],
                "gain": dispatch["gain"], "command": dispatch["command"],
                "published_installation": current,
                "retired_after_publication": is_retired,
            })
        if time_us == fault:
            current = installed
        if time_us < duration and time_us % period == 0:
            tick = time_us // period
            gain = 1 if current == initial else 0
            command = max(-4.0, min(4.0, gain * (2.0 - velocity)))
            hold = 2000 if time_us == 4_249_000 else 100
            dispatch = {
                "schema": 1, "experiment": "corrective_stop", "protocol": "atomic",
                "kind": "dispatch", "tick": tick, "scheduled_us": time_us,
                "outcome": "Started", "captured_installation": current,
                "gain": gain, "velocity": velocity, "reference": 2.0,
                "command": command, "completion_us": time_us + hold,
            }
            records.append(dispatch)
            active[tick] = dispatch
            completions.setdefault(time_us + hold, []).append(tick)
        if time_us >= fault:
            max_velocity = max(max_velocity, abs(velocity))
            max_error = max(max_error, abs(2.0 - velocity))
            if stop_confirmed is None:
                if abs(velocity) <= 0.05:
                    if below_since is None:
                        below_since = time_us
                    if time_us - below_since >= 100_000:
                        stop_entry, stop_confirmed = below_since, time_us
                else:
                    below_since = None
    records.append({
        "schema": 1, "experiment": "corrective_stop", "protocol": "atomic",
        "kind": "run_end", "published_us": fault, "stop_entry_us": stop_entry,
        "stop_confirmed_us": stop_confirmed, "stop_censored": stop_confirmed is None,
        "fault_abs_command_integral_us": fault_integral,
        "publication_abs_command_integral_us": publication_integral,
        "max_post_fault_abs_velocity": max_velocity,
        "max_post_fault_abs_error": max_error, "attempts": 1, "busy_attempts": 0,
        "retries": 0, "transition_skips": 0, "execution_skips": 0,
        "empty_skips": 0, "retired_commands": retired,
        "saturated_completions": saturated, "command_bound_violations": violations,
        "final_installation": installed, "final_gain": 0,
    })
    return records


class AdaptationAnalyzerTest(unittest.TestCase):
    def test_recomputes_plant_and_rmse(self):
        report = load_analyzer().analyze(fixture())
        self.assertEqual(report["protocols"]["frozen"]["pre_ticks"], 1)
        self.assertEqual(report["protocols"]["frozen"]["post_ticks"], 1)
        self.assertEqual(report["protocols"]["frozen"]["empty_slot_observations"], 0)

    def test_rejects_corrupt_plant_state(self):
        records = fixture()
        next(record for record in records
             if record["kind"] == "control" and record["tick"] == 1)["velocity"] += 0.01
        with self.assertRaisesRegex(ValueError, "plant evolution"):
            load_analyzer().analyze(records)

    def test_rejects_completion_identity_not_captured_at_start(self):
        records = fixture()
        next(record for record in records if record["kind"] == "completion")[
            "captured_installation"] = [True, 2]
        with self.assertRaisesRegex(ValueError, "malformed.*identity"):
            load_analyzer().analyze(records)

    def test_execution_busy_requires_live_long_held_predecessor(self):
        records = fixture()
        next(record for record in records
             if record["kind"] == "control" and record["tick"] == 1)[
                 "dispatch_outcome"] = "ExecutionBusy"
        invocation = next(record for record in records
                          if record["kind"] == "invocation" and record["tick"] == 1)
        invocation.update({"outcome": "ExecutionBusy", "captured_installation": None,
                           "captured_gain": None, "captured_command": None,
                           "completion_us": None})
        records = [record for record in records
                   if not (record["kind"] == "completion" and record["invocation"] == 1)]
        with self.assertRaisesRegex(ValueError, "long-held predecessor"):
            load_analyzer().analyze(records)

    def test_rmse_includes_every_control_tick(self):
        records = fixture()
        next(record for record in records if record["kind"] == "summary")["post_rmse"] = 0.0
        with self.assertRaisesRegex(ValueError, "RMSE"):
            load_analyzer().analyze(records)

    def test_rejects_corrupt_guard_overlap_summary(self):
        records = fixture()
        next(record for record in records if record["kind"] == "summary")[
            "guard_version_overlaps"] = 1
        with self.assertRaisesRegex(ValueError, "overlap"):
            load_analyzer().analyze(records)

    def test_success_receipt_must_match_identity_and_ledger_delta(self):
        analyzer = load_analyzer()
        config = next(record for record in fixture() if record["kind"] == "config")
        config = {**config, "handle_gains": [[0, 1.0], [1, 2.0]]}
        attempt = {
            "schema": 1, "protocol": "atomic", "kind": "attempt",
            "proposal": 0, "ordinal": 0, "scheduled_us": 1000,
            "attempted": True, "expected": [0, 1], "candidate_handle": 1,
            "candidate_gain": 2.0, "outcome": "Ok", "published_us": 1000,
            "completed_us": 1000,
            "receipt": {"previous": [0, 1], "installed": [1, 2],
                        "admission_delta": 10, "committed": 20},
            "before_installation": [0, 1], "after_installation": [1, 2],
            "before_committed": 10, "after_committed": 20,
            "accounting_ok": True,
        }
        with self.assertRaisesRegex(ValueError, "receipt"):
            analyzer.validate_attempts(config, [attempt])

    def test_conditional_rate_is_null_for_zero_denominator(self):
        analyzer = load_analyzer()
        self.assertIsNone(analyzer.conditional_rate(0, 0))
        self.assertEqual(analyzer.conditional_rate(1, 4), 0.25)

    def test_streaming_schedule_grid_requires_complete_coverage(self):
        analyzer = load_analyzer()
        records = one_valid_grid_run()
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text("".join(json.dumps(row) + "\n" for row in records))
            with self.assertRaisesRegex(ValueError, "coverage"):
                analyzer.analyze_stream(trace)

    def test_corrective_reducer_rejects_wrong_command_integral(self):
        analyzer = load_analyzer()
        records = one_valid_corrective_run()
        records[-1]["fault_abs_command_integral_us"] += 1
        with self.assertRaisesRegex(ValueError, "command integral"):
            analyzer.reduce_corrective_run(records)

    def test_corrective_reducer_replays_stop_from_raw_events(self):
        analyzer = load_analyzer()
        records = one_valid_corrective_run()
        row = analyzer.reduce_corrective_run(records)
        self.assertEqual(row["request_publication_delay_us"], 0)
        records[-1]["stop_confirmed_us"] += 100
        with self.assertRaisesRegex(ValueError, "stop_confirmed"):
            analyzer.reduce_corrective_run(records)

    def test_grid_reducer_rejects_duplicate_dispatch_and_bad_ledger(self):
        analyzer = load_analyzer()
        records = one_valid_grid_run()
        records.insert(-1, next(row.copy() for row in records if row.get("kind") == "dispatch"))
        with self.assertRaisesRegex(ValueError, "dispatch coverage"):
            analyzer.reduce_schedule_run(records)
        records = one_valid_grid_run()
        next(row for row in records if row.get("kind") == "attempt")["after_committed"] += 1
        with self.assertRaisesRegex(ValueError, "manager history|mutated publication|receipt history"):
            analyzer.reduce_schedule_run(records)


if __name__ == "__main__":
    unittest.main()
