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


if __name__ == "__main__":
    unittest.main()
