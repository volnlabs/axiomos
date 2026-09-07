#!/usr/bin/env python3
"""Negative-oracle tests for the deterministic adaptation replay."""

import importlib.util
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
