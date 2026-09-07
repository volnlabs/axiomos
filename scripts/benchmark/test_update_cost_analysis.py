#!/usr/bin/env python3
"""Synthetic contract checks for the hosted update-cost reducer."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


def load_analyzer():
    spec = importlib.util.spec_from_file_location(
        "update_cost_analysis", Path(__file__).with_name("analyze-update-cost.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(protocol="guarded"):
    common = {"schema": 1, "protocol": protocol, "hold_us": 10, "run": 0}
    records = [
        {**common, "kind": "meta", "attempts": 3, "warmup": 1,
         "period_ns": 1_000_000, "clock_resolution_ns": 1,
         "dispatch_cpu": 12, "update_cpu": 14, "dispatch_core": 6,
         "update_core": 7, "dispatch_package": 0, "update_package": 0,
         "resource_label": "manager-accounted resident bytecode bytes"},
        {**common, "kind": "clock", "latency_ns": 8},
        {**common, "kind": "resource", "phase": "one_program",
         "live_programs": 1, "program_bytes": 16},
        {**common, "kind": "resource", "phase": "two_loaded",
         "live_programs": 2, "program_bytes": 32},
        {**common, "kind": "update", "attempt": 0, "logical_update": 0,
         "retry_ordinal": 1, "outcome": "Busy", "latency_ns": 30, "lateness_ns": 4,
         "scheduled_offset_ns": 0, "started_offset_ns": 4},
        {**common, "kind": "update", "attempt": 1, "logical_update": 0,
         "retry_ordinal": 2, "outcome": "Ok", "latency_ns": 90, "lateness_ns": 5,
         "scheduled_offset_ns": 1_137_000, "started_offset_ns": 1_137_005},
        {**common, "kind": "update", "attempt": 2, "logical_update": 1,
         "retry_ordinal": 1, "outcome": "Ok", "latency_ns": 70, "lateness_ns": 6,
         "scheduled_offset_ns": 2_274_000, "started_offset_ns": 2_274_006},
        {**common, "kind": "dispatch", "scheduled": 0, "outcome": "Ok",
         "call_ns": 20, "entry_ns": 5, "release_ns": 5,
         "lateness_ns": 2, "actual_hold_ns": 11_000},
        {**common, "kind": "dispatch", "scheduled": 1,
         "outcome": "TransitionBusy", "call_ns": 7,
         "entry_ns": None, "release_ns": None, "lateness_ns": 3,
         "actual_hold_ns": None},
        {**common, "kind": "controlled_transition", "latency_ns": 6},
        {**common, "kind": "resource", "phase": "after_replace",
         "live_programs": 2, "program_bytes": 32},
        {**common, "kind": "resource", "phase": "after_cleanup",
         "live_programs": 0, "program_bytes": 0},
        {**common, "kind": "end", "scheduled_releases": 3,
         "dispatch_attempts": 2, "missed_releases": 1,
         "transition_busy_skips": 1, "execution_busy_skips": 0,
         "empty_skips": 0},
    ]
    records[2:2] = [{**common, "kind": "clock", "latency_ns": 8} for _ in range(999)]
    if protocol == "guarded":
        end = next(i for i, record in enumerate(records) if record["kind"] == "resource"
                   and record["phase"] == "after_replace")
        records[end:end] = [
            {**common, "kind": "controlled_transition", "latency_ns": 6}
            for _ in range(99)
        ]
    return records


def v2_fixture(protocol="guarded"):
    records = fixture(protocol)
    for record in records:
        record["schema"] = 2
        if record["kind"] == "update":
            record["called_offset_ns"] = record["started_offset_ns"] + 5
            record["post_swap_observed_offset_ns"] = (
                record["started_offset_ns"] + record["latency_ns"] // 2
                if record["outcome"] == "Ok" else None
            )
    return records


def v3_fixture(protocol="guarded"):
    records = v2_fixture(protocol)
    current = [0, 1]
    for record in records:
        record["schema"] = 3
        if record["kind"] == "update":
            record["before_installation"] = list(current)
            if record["outcome"] == "Ok":
                current = [1 - current[0], current[1] + 1]
            record["after_installation"] = list(current)
    return records


class UpdateCostAnalysisTest(unittest.TestCase):
    def test_v3_validates_full_identity_continuity_without_changing_logical_schema(self):
        analyzer = load_analyzer()
        report = analyzer.analyze(v3_fixture(), expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))

        self.assertEqual(report["schema"], 2)
        self.assertEqual(report["raw_schema"], 3)
        self.assertIn("before_installation", report["raw_identity"])
        self.assertEqual(report["logical_aggregates"][0]["completed"], 2)

    def test_v3_rejects_identity_discontinuity_and_outcome_mutation(self):
        analyzer = load_analyzer()
        cases = (
            (1, "before_installation", [9, 9], "identity continuity"),
            (0, "after_installation", [1, 2], "Busy update changed installation"),
            (1, "after_installation", [1, 9], "successful update identity"),
        )
        for index, field, value, message in cases:
            with self.subTest(index=index, field=field):
                records = v3_fixture()
                updates = [record for record in records if record["kind"] == "update"]
                updates[index][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                                     expected_holds=(10,), expected_protocols=("guarded",))

    def test_v2_logical_latency_includes_busy_retry_gap(self):
        analyzer = load_analyzer()
        report = analyzer.analyze(v2_fixture(), expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))

        first = report["logical_requests"][0]
        self.assertEqual(first["busy_attempts"], 1)
        self.assertEqual(first["first_attempt_to_publication_ns"], 1_137_041)
        self.assertEqual(first["scheduled_to_publication_ns"], 1_137_050)
        self.assertEqual(first["first_attempt_to_return_ns"], 1_137_091)
        self.assertEqual(first["scheduled_to_return_ns"], 1_137_100)
        aggregate = report["logical_aggregates"][0]
        self.assertEqual(aggregate["retried_successes"], 1)
        self.assertIn("immediately before", report["logical_metric"]["first_attempt_start"])
        self.assertIn("before pre-call", report["logical_metric"]["attempt_started"])
        self.assertEqual(
            aggregate["latency_ns"]["first_attempt_to_publication"]["median_of_run_p95s"],
            1_137_041,
        )

    def test_v2_thresholds_distinguish_known_miss_from_censored_unknown(self):
        analyzer = load_analyzer()
        records = v2_fixture()
        updates = [record for record in records if record["kind"] == "update"]
        updates[-1].update(outcome="Busy", post_swap_observed_offset_ns=None)
        report = analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))

        aggregate = report["logical_aggregates"][0]
        threshold = aggregate["thresholds"]["first_attempt_to_publication"]["1ms"]
        self.assertEqual(threshold, {
            "denominator": 2,
            "known_met": 0,
            "known_missed": 1,
            "unknown": 1,
            "lower_rate": 0.0,
            "upper_rate": 0.5,
        })
        self.assertEqual(aggregate["completed"], 1)
        self.assertEqual(aggregate["censored"], 1)

    def test_v2_requires_one_bounded_publication_marker_on_success_only(self):
        analyzer = load_analyzer()
        cases = (
            (1, 1, "successful update has invalid post-swap timestamp"),
            (1, None, "successful update has invalid post-swap timestamp"),
            (0, 100, "Busy update has a post-swap timestamp"),
        )
        for index, value, message in cases:
            with self.subTest(index=index, value=value):
                records = v2_fixture()
                records[next(i for i, row in enumerate(records)
                             if row["kind"] == "update") + index][
                                 "post_swap_observed_offset_ns"
                             ] = value
                with self.assertRaisesRegex(ValueError, message):
                    analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                                     expected_holds=(10,), expected_protocols=("guarded",))

    def test_v2_rejects_failed_post_commit_clock_read_sentinel(self):
        analyzer = load_analyzer()
        records = v2_fixture()
        update = next(record for record in records if record["kind"] == "update")
        update["latency_ns"] = 0
        with self.assertRaisesRegex(ValueError, "invalid zero latency sentinel"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_v2_rejects_overlapping_serialized_update_calls(self):
        analyzer = load_analyzer()
        records = v2_fixture()
        first = next(record for record in records if record["kind"] == "update")
        first["latency_ns"] = 2_000_000
        with self.assertRaisesRegex(ValueError, "serialized update calls overlap"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_v2_writes_one_logical_csv_row_per_metric(self):
        analyzer = load_analyzer()
        report = analyzer.analyze(v2_fixture(), expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer.write_outputs(report, root)
            lines = (root / "cost-logical-latency.csv").read_text().splitlines()
            checksums = (root / "SHA256SUMS").read_text()

        self.assertEqual(len(lines), 5)
        self.assertIn("median_of_run_p95s_ns", lines[0])
        self.assertIn("1ms_known_missed", lines[0])
        self.assertIn("cost-logical-latency.csv", checksums)

    def test_v1_output_files_remain_byte_identical(self):
        analyzer = load_analyzer()
        report = analyzer.analyze(fixture(), expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))
        expected = {
            "SHA256SUMS": "83a4fede75bae7a75bd14340562948153f315e960dfd8488bcde8fb34d3cdaa9",
            "cost-analysis.json": "08bd5c9382a0b89ca43ddd0b91f90875be4d7b39a7528a78b00b668ad489439a",
            "cost-contention-table.tex": "59839917b1a5dfca2429f794534a74ab4339ab50c60911345665dcead6b59c66",
            "cost-note.tex": "c3a1424248e04f8d74cab87a6f9cf15ea30ce0ff66a0887c5007b7209460d933",
            "cost-runs.csv": "d68581dfd0a4f3cc94382314b8529d305e15d88f0490963efdfb101f6c8d37e1",
            "cost-summary.csv": "52f06aa275dae31037d840bd45b36138019877b7b2efb347fc859cebe0e8380b",
            "cost-table.tex": "7063555a94c97a3dd43842cd662694d009e03ad13e2751bfcd38539cdecaf6ae",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer.write_outputs(report, root)
            actual = {
                path.name: __import__("hashlib").sha256(path.read_bytes()).hexdigest()
                for path in root.iterdir()
            }
        self.assertEqual(actual, expected)

    def test_v2_output_files_remain_byte_identical(self):
        analyzer = load_analyzer()
        report = analyzer.analyze(v2_fixture(), expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))
        expected = {
            "SHA256SUMS": "28b40d12ef435a67699815c294172fd1132870e772d76abb5ae2c770ac51cb3c",
            "cost-analysis.json": "d424627df5128eb54dfab68551ec0018e0d7effe22b32729ed965af1895433c1",
            "cost-contention-table.tex": "59839917b1a5dfca2429f794534a74ab4339ab50c60911345665dcead6b59c66",
            "cost-logical-latency.csv": "f45a9676d3d2c5cd528b9d0d6ab88181f7dfce38ccd2806435b1b5cc86020c40",
            "cost-note.tex": "c3a1424248e04f8d74cab87a6f9cf15ea30ce0ff66a0887c5007b7209460d933",
            "cost-runs.csv": "d68581dfd0a4f3cc94382314b8529d305e15d88f0490963efdfb101f6c8d37e1",
            "cost-summary.csv": "52f06aa275dae31037d840bd45b36138019877b7b2efb347fc859cebe0e8380b",
            "cost-table.tex": "7063555a94c97a3dd43842cd662694d009e03ad13e2751bfcd38539cdecaf6ae",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer.write_outputs(report, root)
            actual = {
                path.name: __import__("hashlib").sha256(path.read_bytes()).hexdigest()
                for path in root.iterdir()
            }
        self.assertEqual(actual, expected)

    def test_reports_outcome_specific_populations_and_denominators(self):
        analyzer = load_analyzer()
        report = analyzer.analyze(fixture(), expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("guarded",))
        run = report["runs"][0]
        self.assertEqual(run["successful_updates"], 2)
        self.assertEqual(run["busy_updates"], 1)
        self.assertEqual(run["logical_updates_started"], 2)
        self.assertEqual(run["first_attempt_successes"], 1)
        self.assertEqual(run["skips_per_successful_update"], 0.5)
        self.assertEqual(run["latency_ns"]["replace_ok"]["median"], 70)
        self.assertEqual(run["latency_ns"]["replace_busy"]["count"], 1)
        self.assertEqual(run["latency_ns"]["update_lateness"]["p99"], 6)
        self.assertEqual(run["latency_ns"]["transition_busy"]["max"], 7)
        self.assertEqual(run["latency_ns"]["controlled_transition"]["p99"], 6)

    def test_empty_latency_population_is_null(self):
        analyzer = load_analyzer()
        records = fixture("atomic")
        records = [r for r in records if r["kind"] != "controlled_transition"]
        for record in records:
            if record["kind"] == "update" and record["outcome"] == "Busy":
                record.update(outcome="Ok", logical_update=record["attempt"], retry_ordinal=1)
            elif record["kind"] == "update":
                record.update(logical_update=record["attempt"], retry_ordinal=1)
            if record["kind"] == "dispatch" and record["outcome"] == "TransitionBusy":
                record.update(outcome="Ok", entry_ns=4, release_ns=4, actual_hold_ns=10_000)
            if record["kind"] == "end":
                record.update(transition_busy_skips=0)
        report = analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,), expected_protocols=("atomic",))
        run = report["runs"][0]
        self.assertIsNone(run["latency_ns"]["replace_busy"])
        self.assertIsNone(run["latency_ns"]["transition_busy"])
        self.assertIsNone(run["latency_ns"]["controlled_transition"])

    def test_resource_growth_after_setup_is_rejected(self):
        analyzer = load_analyzer()
        records = fixture()
        next(r for r in records if r.get("phase") == "after_replace")["program_bytes"] = 48
        with self.assertRaisesRegex(ValueError, "resident program accounting changed"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_duplicate_resource_phase_is_rejected(self):
        analyzer = load_analyzer()
        records = fixture()
        resource = next(record for record in records if record.get("phase") == "one_program")
        records.append(dict(resource))
        with self.assertRaisesRegex(ValueError, "resource observations"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_boolean_update_identity_is_rejected(self):
        analyzer = load_analyzer()
        records = fixture()
        next(record for record in records if record.get("attempt") == 0)["attempt"] = False
        with self.assertRaisesRegex(ValueError, "invalid attempt identity"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_resource_sizes_must_match_across_runs(self):
        analyzer = load_analyzer()
        records = fixture() + fixture()
        for record in records[len(records) // 2:]:
            record["run"] = 1
            if record["kind"] == "update":
                record["scheduled_offset_ns"] += 97_000
                record["started_offset_ns"] += 97_000
            if record.get("phase") == "one_program":
                record["program_bytes"] = 24
        with self.assertRaisesRegex(ValueError, "resource sizes differ"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=2,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_outputs_include_raw_availability_counts_and_checksums(self):
        analyzer = load_analyzer()
        records = fixture() + [
            {**record, "protocol": "atomic"}
            for record in fixture("atomic")
            if record["kind"] != "controlled_transition"
        ]
        for record in records:
            if record["protocol"] == "atomic" and record["kind"] == "update":
                record.update(outcome="Ok", logical_update=record["attempt"], retry_ordinal=1)
            if record["protocol"] == "atomic" and record["kind"] == "dispatch" and record["outcome"] != "Ok":
                record.update(outcome="Ok", entry_ns=4, release_ns=4, actual_hold_ns=10_000)
            if record["protocol"] == "atomic" and record["kind"] == "end":
                record.update(transition_busy_skips=0)
        report = analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                                  expected_holds=(10,))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            analyzer.write_outputs(report, destination)
            table = (destination / "cost-table.tex").read_text()
            self.assertIn("GR first try", table)
            self.assertIn(r"Hold ($\mu$s)", table)
            self.assertIn(r"AP lat. ($\mu$s)", table)
            self.assertIn("1/2", table)
            note = (destination / "cost-note.tex").read_text()
            self.assertIn("observer round-trip", note)
            self.assertIn("controlled", note)
            self.assertIn("manager-accounted", note)
            checksums = (destination / "SHA256SUMS").read_text()
            self.assertIn("cost-analysis.json", checksums)
            self.assertNotIn("SHA256SUMS", checksums)

    def test_missing_regime_and_unknown_record_kind_are_rejected(self):
        analyzer = load_analyzer()
        with self.assertRaisesRegex(ValueError, "matrix coverage"):
            analyzer.analyze(fixture(), expected_attempts=3, expected_runs=1)
        records = fixture()
        records.append({"schema": 1, "protocol": "guarded", "hold_us": 10,
                        "run": 0, "kind": "mystery"})
        with self.assertRaisesRegex(ValueError, "unknown record kind"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_cli_can_write_derived_files_away_from_raw_trace(self):
        analyzer = load_analyzer()
        records = []
        for hold in analyzer.HOLDS_US:
            for protocol in analyzer.PROTOCOLS:
                regime = fixture(protocol)
                for record in regime:
                    record["hold_us"] = hold
                    if protocol == "atomic" and record["kind"] == "update":
                        record.update(outcome="Ok", logical_update=record["attempt"],
                                      retry_ordinal=1)
                    if (protocol == "atomic" and record["kind"] == "dispatch"
                            and record["outcome"] != "Ok"):
                        record.update(outcome="Ok", entry_ns=4, release_ns=4,
                                      actual_hold_ns=10_000)
                    if protocol == "atomic" and record["kind"] == "end":
                        record.update(transition_busy_skips=0)
                records.extend(record for record in regime
                               if not (protocol == "atomic"
                                       and record["kind"] == "controlled_transition"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "raw" / "cost-trace.jsonl"
            output = root / "derived"
            trace.parent.mkdir()
            trace.write_text("".join(json.dumps(record) + "\n" for record in records))
            argv = ["analyze-update-cost.py", str(trace), "--attempts-per-run", "3",
                    "--runs", "1", "--output-dir", str(output)]
            with mock.patch.object(sys, "argv", argv):
                self.assertEqual(analyzer.main(), 0)
            self.assertTrue((output / "cost-analysis.json").is_file())
            self.assertFalse((trace.parent / "cost-analysis.json").exists())

    def test_schedule_and_physical_core_contract_are_enforced(self):
        analyzer = load_analyzer()
        records = fixture()
        records[0]["update_core"] = 6
        with self.assertRaisesRegex(ValueError, "physical cores"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))

    def test_incomplete_clock_and_controlled_populations_are_rejected(self):
        analyzer = load_analyzer()
        records = fixture()
        records.remove(next(r for r in records if r["kind"] == "clock"))
        with self.assertRaisesRegex(ValueError, "clock samples"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))
        records = fixture()
        records.remove(next(r for r in records if r["kind"] == "controlled_transition"))
        with self.assertRaisesRegex(ValueError, "controlled transition samples"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))
        records = fixture()
        next(r for r in records if r.get("attempt") == 1)["scheduled_offset_ns"] += 1
        with self.assertRaisesRegex(ValueError, "phase schedule"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))
        records = fixture()
        next(r for r in records if r["kind"] == "dispatch")["lateness_ns"] = 1_000_000
        with self.assertRaisesRegex(ValueError, "expired dispatch"):
            analyzer.analyze(records, expected_attempts=3, expected_runs=1,
                             expected_holds=(10,), expected_protocols=("guarded",))


if __name__ == "__main__":
    unittest.main()
