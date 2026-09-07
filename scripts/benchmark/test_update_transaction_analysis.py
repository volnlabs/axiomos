#!/usr/bin/env python3
"""Small negative-oracle check; fixtures here are synthetic analyzer tests only."""
import importlib.util
from pathlib import Path
import unittest


def load_analyzer():
    spec = importlib.util.spec_from_file_location(
        "analysis", Path(__file__).with_name("analyze-update-transaction.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AnalyzerTest(unittest.TestCase):
    def test_recomputes_overlap_accounting_and_failed_preservation(self):
        analyzer = load_analyzer()
        state = lambda ids, charge: {"snapshot": ids, "committed": charge,
                                    "installation": None, "executing": []}
        record = {"schema": 1, "protocol": "attach_first", "case": "interruption",
                  "request_id": 1, "before": state([1], 10),
                  "observations": [state([1, 2], 99)], "after": state([1, 2], 30),
                  "costs": {"1": 10, "2": 20}, "ordinary_charge": 0,
                  "outcome": "Interrupted", "expected": None, "candidate": 2,
                  "skipped_dispatches": 0}
        summary = analyzer.analyze([record])["attach_first"]
        self.assertEqual(summary["dual_snapshots"], 2)
        self.assertEqual(summary["accounting_mismatches"], 1)
        self.assertEqual(summary["failed_preserved"], 0)
        self.assertEqual(summary["failed_requests"], 1)

    def test_unknown_protocol_is_invalid_evidence(self):
        analyzer = load_analyzer()
        with self.assertRaises(ValueError):
            analyzer.analyze([{"schema": 1, "protocol": "unknown"}])

    def v2_state(self, program, epoch, committed, receipt, guards=None):
        identity = [program, epoch]
        return {"snapshot": [program], "installation": identity,
                "committed": committed, "receipt": receipt,
                "guards": guards if guards is not None else [identity]}

    def v2_record(self, protocol, case="snapshot_prep_failure"):
        receipt = {"previous": None, "installed": [1, 1],
                   "admission_delta": 10, "committed": 10}
        state = self.v2_state(1, 1, 110, receipt)
        return {"schema": 2, "protocol": protocol, "scope": "bpf_manager",
                "case": case, "request_id": 1, "before": state,
                "observations": [], "after": dict(state),
                "costs": {"1": 10, "2": 20}, "ordinary_charge": 100,
                "outcome": "SnapshotAllocationFailed", "expected": [1, 1],
                "candidate": 2, "attempts": [
                    {"candidate": 2, "outcome": "SnapshotAllocationFailed"}],
                "skipped_dispatches": 0}

    def test_paired_validation_rejects_corrupt_accounting(self):
        analyzer = load_analyzer()
        records = [self.v2_record("atomic_publication"),
                   self.v2_record("transactional")]
        records[0]["before"]["committed"] = 999
        records[0]["after"]["committed"] = 999
        with self.assertRaisesRegex(ValueError, "accounting"):
            analyzer.validate_paired(records)

    def test_paired_validation_rejects_guard_overlap_in_transactional(self):
        analyzer = load_analyzer()
        records = [self.v2_record("atomic_publication"),
                   self.v2_record("transactional")]
        records[1]["after"]["guards"] = [[1, 1], [2, 2]]
        with self.assertRaisesRegex(ValueError, "guard overlap"):
            analyzer.validate_paired(records)

    def test_paired_validation_rejects_multi_program_publication(self):
        analyzer = load_analyzer()
        records = [self.v2_record("atomic_publication"),
                   self.v2_record("transactional")]
        records[0]["observations"] = [
            {"snapshot": [1, 2], "installation": [2, 2], "committed": 130,
             "receipt": records[0]["before"]["receipt"], "guards": [[2, 2]]}]
        with self.assertRaisesRegex(ValueError, "cardinality"):
            analyzer.validate_paired(records)

    def test_failed_request_must_preserve_receipt(self):
        analyzer = load_analyzer()
        records = [self.v2_record("atomic_publication"),
                   self.v2_record("transactional")]
        records[0]["after"]["receipt"] = {
            "previous": [1, 1], "installed": [2, 2],
            "admission_delta": 10, "committed": 20}
        with self.assertRaisesRegex(ValueError, "failed preservation"):
            analyzer.validate_paired(records)

    def test_atomic_overlap_is_only_allowed_in_held_a_schedule(self):
        analyzer = load_analyzer()
        records = [self.v2_record("atomic_publication"),
                   self.v2_record("transactional")]
        records[0]["observations"] = [
            self.v2_state(2, 2, None, None, [[1, 1], [2, 2]])]
        with self.assertRaisesRegex(ValueError, "guard overlap"):
            analyzer.validate_paired(records)


if __name__ == "__main__":
    unittest.main()
