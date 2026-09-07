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


class UpdateCostAnalysisTest(unittest.TestCase):
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
