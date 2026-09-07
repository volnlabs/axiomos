#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

import render_tables


def update(*, protocol="guarded", hold=100, run=0, attempt=0, logical=0,
           retry=1, outcome="Ok", started=100, latency=20, scheduled=90):
    return {
        "schema": 1,
        "protocol": protocol,
        "hold_us": hold,
        "run": run,
        "kind": "update",
        "attempt": attempt,
        "logical_update": logical,
        "retry_ordinal": retry,
        "outcome": outcome,
        "latency_ns": latency,
        "scheduled_offset_ns": scheduled,
        "started_offset_ns": started,
        "lateness_ns": started - scheduled,
    }


class CompletionAnalysisTests(unittest.TestCase):
    def test_singleton_request_completes(self):
        requests, runs, aggregates = render_tables.completion_analysis([update()])

        self.assertEqual(requests[0]["elapsed_ns"], 20)
        self.assertTrue(requests[0]["completed"])
        self.assertEqual(runs[0]["completed"], 1)
        self.assertEqual(aggregates[0]["completed"], 1)

    def test_busy_then_ok_includes_wait_until_retry(self):
        records = [
            update(outcome="Busy", latency=10),
            update(attempt=1, logical=0, retry=2, started=1_100, scheduled=1_090,
                   latency=30),
        ]

        requests, _, _ = render_tables.completion_analysis(records)

        self.assertEqual(requests[0]["attempts"], 2)
        self.assertEqual(requests[0]["elapsed_ns"], 1_030)
        self.assertEqual(requests[0]["outcome"], "Ok")

    def test_logical_ids_restart_per_process(self):
        records = [update(run=0), update(run=1, started=200, scheduled=190)]

        requests, runs, aggregates = render_tables.completion_analysis(records)

        self.assertEqual([(row["run"], row["logical_update"]) for row in requests],
                         [(0, 0), (1, 0)])
        self.assertEqual(len(runs), 2)
        self.assertEqual(aggregates[0]["requests_started"], 2)

    def test_final_busy_request_is_right_censored(self):
        records = [update(outcome="Busy", latency=15)]

        requests, runs, aggregates = render_tables.completion_analysis(records)

        self.assertFalse(requests[0]["completed"])
        self.assertTrue(requests[0]["censored"])
        self.assertEqual(requests[0]["elapsed_ns"], 15)
        self.assertEqual(runs[0]["censored"], 1)
        self.assertEqual(aggregates[0]["censored"], 1)
        self.assertIsNone(aggregates[0]["elapsed_ns"])

    def test_malformed_retry_order_is_rejected(self):
        records = [update(retry=2)]

        with self.assertRaisesRegex(ValueError, "retry sequence"):
            render_tables.completion_analysis(records)

    def test_overlapping_attempts_are_rejected_across_requests(self):
        records = [
            update(started=100, scheduled=90, latency=50),
            update(attempt=1, logical=1, started=149, scheduled=140, latency=10),
        ]

        with self.assertRaisesRegex(ValueError, "overlapping update attempts"):
            render_tables.completion_analysis(records)

    def test_atomic_elapsed_equals_successful_call_latency(self):
        record = update(protocol="atomic", hold=0, latency=37)

        requests, _, _ = render_tables.completion_analysis([record])

        self.assertEqual(requests[0]["elapsed_ns"], record["latency_ns"])


def logical_row(protocol, hold, base):
    latency = {}
    thresholds = {}
    for offset, metric in enumerate((
            "scheduled_to_publication", "first_attempt_to_publication",
            "scheduled_to_return", "first_attempt_to_return")):
        median = (base + offset) * 1_000
        latency[metric] = {
            "runs_with_completions": 1,
            "median_of_run_medians": median,
            "median_of_run_p95s": median + 1_000,
            "median_of_run_p99s": median + 2_000,
            "observed_max": median + 3_000,
        }
        thresholds[metric] = {
            name: {"denominator": 4, "known_met": met, "known_missed": 4 - met,
                   "unknown": 0, "lower_rate": met / 4, "upper_rate": met / 4}
            for name, met in (("1ms", 1), ("5ms", 2), ("10ms", 3), ("20ms", 4))
        }
    return {
        "protocol": protocol, "hold_us": hold, "runs": 1,
        "raw_attempts": 5, "requests_started": 4, "completed": 3, "censored": 1,
        "busy_attempts": 2, "first_attempt_successes": 2, "retried_successes": 1,
        "transition_busy_skips": 1, "execution_busy_skips": 2, "empty_skips": 0,
        "latency_ns": latency, "thresholds": thresholds,
    }


def sweep_row(protocol, hold, *, overlap, retired, skipped, rmse):
    def distribution(value):
        return {"count": 1, "min": value, "median": value, "p99": value, "max": value}
    return {
        "protocol": protocol, "hold_us": hold, "runs": 1,
        "scheduled_requests": 4, "successful_requests": 3,
        "censored_requests": 1, "attempts": 5, "busy_attempts": 2, "retries": 1,
        "scheduled_ticks": 8000, "completed_invocations": 7999,
        "transition_skips": skipped, "execution_skips": 0, "empty_skips": 0,
        "old_new_overlaps": overlap, "retired_commands": retired,
        "saturated_completions": 0, "command_bound_violations": 0,
        "schedules_with_old_new_overlap": int(bool(overlap)),
        "schedules_with_retired_command": int(bool(retired)),
        "schedules_with_dispatch_skip": int(bool(skipped)),
        "activation_rate": .75, "busy_rate_per_attempt": .4,
        "retry_success_rate": .5,
        "publication_delay_us": distribution(10), "return_delay_us": distribution(20),
        "post_rmse": distribution(rmse), "max_abs_error": distribution(2),
        "max_abs_command": distribution(3),
        "abs_command_integral_us": distribution(4_000_000),
    }


class V3RenderingTests(unittest.TestCase):
    def test_renders_only_from_compact_validated_aggregates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            publication, adaptation, output = root / "publication", root / "adaptation", root / "out"
            publication.mkdir()
            adaptation.mkdir()
            costs = {
                "schema": 2,
                "logical_metric": {"first_attempt_start": "first replacement API call"},
                "logical_aggregates": [
                    logical_row("atomic", 100, 1), logical_row("guarded", 100, 2),
                ],
            }
            schedule = {
                "schema": 1, "experiment": "schedule_grid",
                "coverage": {"protocols": ["atomic", "guarded"],
                             "primary_holds_us": [100], "stress_holds_us": [1100],
                             "phases_us": [0], "runs": 4, "logical_requests": 16},
                "denominators": {},
                "aggregates": [
                    sweep_row("atomic", 100, overlap=1, retired=0, skipped=0, rmse=.25),
                    sweep_row("guarded", 100, overlap=0, retired=1, skipped=1, rmse=.20),
                    sweep_row("atomic", 1100, overlap=1, retired=1, skipped=1, rmse=.30),
                    sweep_row("guarded", 1100, overlap=0, retired=0, skipped=1, rmse=.35),
                ],
                "rows": [{"must_not_be_read": True}],
                "requests": [{"must_not_be_read": True}],
            }
            corrective = {
                "schema": 1, "experiment": "corrective_stop",
                "integral_units": "absolute command times microseconds",
                "common_horizon": "fault_us through duration_us",
                "publication_horizon": "protocol-specific successful publication through duration_us",
                "rows": [
                    {"protocol": "atomic", "fault_us": 4_250_000, "published_us": 4_251_000,
                     "request_publication_delay_us": 1_000, "stop_entry_us": 4_253_000,
                     "stop_confirmed_us": 4_353_000, "stop_censored": False,
                     "fault_abs_command_integral_us": 2_000_000,
                     "publication_abs_command_integral_us": 1_000_000,
                     "max_post_fault_abs_velocity": 1, "max_post_fault_abs_error": 1,
                     "attempts": 1, "busy_attempts": 0, "retries": 0,
                     "transition_skips": 0, "execution_skips": 0,
                     "retired_commands": 1, "command_bound_violations": 0,
                     "final_installation": [2, 2], "final_gain": 0},
                    {"protocol": "guarded", "fault_us": 4_250_000, "published_us": 4_252_000,
                     "request_publication_delay_us": 2_000, "stop_entry_us": 4_254_000,
                     "stop_confirmed_us": 4_354_000, "stop_censored": False,
                     "fault_abs_command_integral_us": 3_000_000,
                     "publication_abs_command_integral_us": 2_000_000,
                     "max_post_fault_abs_velocity": 1, "max_post_fault_abs_error": 1,
                     "attempts": 2, "busy_attempts": 1, "retries": 1,
                     "transition_skips": 1, "execution_skips": 2,
                     "retired_commands": 0, "command_bound_violations": 0,
                     "final_installation": [2, 2], "final_gain": 0},
                ],
            }
            (publication / "cost-analysis.json").write_text(json.dumps(costs))
            (adaptation / "schedule-grid.json").write_text(json.dumps(schedule))
            (adaptation / "corrective-stop.json").write_text(json.dumps(corrective))

            render_tables.render(publication, adaptation, output)

            self.assertIn("100 & 1.00/3.00 & 2.00/4.00 & 3/4", (output / "costs.tex").read_text())
            details = (output / "latency-details.tex").read_text()
            self.assertIn("100 & QF-AP & 2.00/3.00/4.00/5.00", details)
            self.assertIn("100 & GR", details)
            self.assertIn("1/3/0", (output / "latency-thresholds.tex").read_text())
            self.assertIn("0.250", (output / "sweep.tex").read_text())
            self.assertIn("QF-AP & 1000 & 3.000 & 2000.000 & 1 & 0/0", (output / "stop.tex").read_text())
            headlines = (output / "headline-results.tex").read_text()
            self.assertIn("QF-AP/GR recorded 1/0 old/new-overlap schedules", headlines)
            self.assertIn("completed only 3/4", headlines)
            self.assertFalse((publication / "cost-trace.jsonl").exists())

    def test_rejects_incomplete_schedule_aggregate_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            publication, adaptation = root / "publication", root / "adaptation"
            publication.mkdir()
            adaptation.mkdir()
            (publication / "cost-analysis.json").write_text(json.dumps({
                "schema": 2, "logical_aggregates": [logical_row("atomic", 100, 1)]}))
            (adaptation / "schedule-grid.json").write_text(json.dumps({
                "schema": 1, "experiment": "schedule_grid",
                "coverage": {"protocols": ["atomic", "guarded"],
                             "primary_holds_us": [100], "stress_holds_us": [],
                             "phases_us": [0], "runs": 2, "logical_requests": 8},
                "aggregates": [sweep_row("atomic", 100, overlap=0, retired=0,
                                         skipped=0, rmse=.2)]}))
            (adaptation / "corrective-stop.json").write_text(json.dumps({
                "schema": 1, "experiment": "corrective_stop", "rows": []}))

            with self.assertRaisesRegex(ValueError, "schedule-grid aggregate coverage"):
                render_tables.render(publication, adaptation, root / "out")


if __name__ == "__main__":
    unittest.main()
