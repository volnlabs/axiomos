import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("analyze_v05", ROOT / "scripts/benchmark/analyze-v05.py")
v05 = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(v05)
SOURCE, ARTIFACT_A, ARTIFACT_B = "1" * 40, "a" * 64, "b" * 64


class V05ReducerTests(unittest.TestCase):
    def setUp(self):
        self.config = v05.load_json(ROOT / "docs/performance/v0.5-acceptance.json")
        self.digest = v05.file_sha256(ROOT / "docs/performance/v0.5-acceptance.json")

    def records(self):
        rows = [
            {"type": "header", "schema": "axiomos.v05.trace.v1", "evidence_kind": "synthetic", "boot_id": "session-boot-a", "clock_hz": 1_000_000_000, "source_id": SOURCE, "artifact_id": ARTIFACT_A, "acceptance_config_sha256": self.digest},
            {"type": "operation_request", "ticks": 1, "operation_id": 1, "operation": "activate", "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "operation_accepted", "ticks": 100_000_002, "operation_id": 1, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "handoff_enter", "ticks": 100_000_003, "operation_id": 1, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "sink_safe_ready", "ticks": 100_000_004, "operation_id": 1, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "cycle_release", "ticks": 110_000_000, "cycle": 1, "scheduled_ticks": 110_000_000, "mode": "controller", "generation": 2},
            {"type": "operation_committed", "ticks": 110_000_001, "operation_id": 1, "cycle": 1, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "behavior_enter", "ticks": 110_000_002, "cycle": 1, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "behavior_exit", "ticks": 110_000_003, "cycle": 1, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "cycle_complete", "ticks": 110_000_004, "cycle": 1, "mode": "controller", "generation": 2},
            {"type": "operation_response", "ticks": 110_000_005, "operation_id": 1, "outcome": "successful"},
            {"type": "cycle_release", "ticks": 120_000_000, "cycle": 2, "scheduled_ticks": 120_000_000, "mode": "controller", "generation": 2},
            {"type": "behavior_enter", "ticks": 120_000_001, "cycle": 2, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "behavior_exit", "ticks": 120_000_002, "cycle": 2, "generation": 2, "artifact_id": ARTIFACT_B},
            {"type": "cycle_complete", "ticks": 120_000_003, "cycle": 2, "mode": "controller", "generation": 2},
            {"type": "cycle_release", "ticks": 130_000_000, "cycle": 3, "scheduled_ticks": 130_000_000, "mode": "safe", "generation": 2},
            {"type": "cycle_complete", "ticks": 130_000_001, "cycle": 3, "mode": "safe", "generation": 2},
        ]
        for seq, row in enumerate(rows[1:], 1): row["seq"] = seq
        rows.append({"type": "terminal", "seq": len(rows), "ticks": 130_000_002, "event_count": len(rows) - 1, "last_event_seq": len(rows) - 1})
        return rows

    def expectations(self, rows=None):
        rows = rows or self.records(); counts = {}
        for row in rows[1:-1]: counts[row["type"]] = counts.get(row["type"], 0) + 1
        return {"schema": "axiomos.v05.expectations.v1", "acceptance_config_sha256": self.digest, "boots": {"session-boot-a": {"source_id": SOURCE, "artifact_id": ARTIFACT_A, "event_counts": counts, "operation_outcomes": {"successful": 1, "failed": 0, "rejected": 0, "canceled": 0}, "release_cycles": {"first": 1, "count": 3}}}}

    def test_long_preparation_safe_cycle_and_repeated_execution_pass(self):
        report = v05.reduce_records(self.records(), self.expectations(), self.config, self.digest)
        self.assertEqual((report["trace_verdict"], report["release_verdict"]), ("pass", "blocked"))
        self.assertEqual(report["boots"][0]["release_count"], 3)
        self.assertEqual(report["gate_results"]["trace_subset"], "pass")
        self.assertEqual(report["gate_results"]["physical_campaign"], "blocked")
        self.assertEqual(report["gate_results"]["authentication_and_loading"], "not_evaluated")

    def test_handoff_timeout_and_exact_deadline_edge(self):
        rows = self.records()
        rows[2]["ticks"], rows[3]["ticks"], rows[4]["ticks"] = 2, 3, 4
        for row, scheduled in ((rows[5], 90_000_004), (rows[11], 100_000_004), (rows[15], 110_000_004)):
            row["ticks"] = row["scheduled_ticks"] = scheduled
        last = rows[5]["ticks"]
        for row in rows[6:]:
            if row["type"] != "cycle_release": row["ticks"] = max(last + 1, row["ticks"] - 20_000_000)
            last = row["ticks"]
        with self.assertRaisesRegex(ValueError, "handoff timeout"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)
        rows = self.records(); rows[9]["ticks"] = rows[5]["scheduled_ticks"] + 10_000_000
        for row in rows[10:]: row["ticks"] = max(row["ticks"], rows[9]["ticks"])
        with self.assertRaisesRegex(ValueError, "deadline"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)

    def test_missing_or_stale_safe_ack_and_wrong_generation_fail(self):
        rows = self.records(); rows.pop(4); self._renumber(rows)
        with self.assertRaisesRegex(ValueError, "handoff stage"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)
        rows = self.records(); rows[4]["operation_id"] = 2
        with self.assertRaisesRegex(ValueError, "handoff stage|request"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)
        rows = self.records(); rows[7]["generation"] = 3
        with self.assertRaisesRegex(ValueError, "identity|generation"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)

    def test_header_identity_and_malformed_expectations_fail(self):
        rows = self.records(); rows[0]["source_id"] = "source-a"
        with self.assertRaisesRegex(ValueError, "source_id"): v05.reduce_records(rows, self.expectations(), self.config, self.digest)
        for value in (True, -1):
            expected = self.expectations(); expected["boots"]["session-boot-a"]["release_cycles"]["count"] = value
            with self.assertRaisesRegex(ValueError, "expectations"): v05.reduce_records(self.records(), expected, self.config, self.digest)
        acceptance = dict(self.config); acceptance["cpu"] = {**acceptance["cpu"], "period_ns": True}
        with self.assertRaisesRegex(ValueError, "acceptance cpu"): v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest)

    def test_all_unsuccessful_outcomes_count_and_cannot_commit_or_enter(self):
        for outcome in ("failed", "rejected", "canceled"):
            rows = self.records()
            rows[1:-1] = [rows[1], {"type": "operation_response", "ticks": 2, "operation_id": 1, "outcome": outcome, "seq": 2}]
            rows[-1].update(seq=3, ticks=3, event_count=2, last_event_seq=2)
            expected = self.expectations(rows)
            expected["boots"]["session-boot-a"]["release_cycles"]["count"] = 0
            expected["boots"]["session-boot-a"]["operation_outcomes"] = {name: int(name == outcome) for name in ("successful", "failed", "rejected", "canceled")}
            report = v05.reduce_records(rows, expected, self.config, self.digest)
            self.assertEqual(report["boots"][0]["failures"], 1)
        rows = self.records(); rows[10]["outcome"] = "failed"
        expected = self.expectations(rows); expected["boots"]["session-boot-a"]["operation_outcomes"] = {"successful": 0, "failed": 1, "rejected": 0, "canceled": 0}
        with self.assertRaisesRegex(ValueError, "unsuccessful operation"): v05.reduce_records(rows, expected, self.config, self.digest)

    def test_duplicate_json_key_and_sequence_gap_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate key"): v05.parse_jsonl('{"type":"header","type":"header"}\n')
        rows = self.records(); rows[2]["seq"] = 1
        with self.assertRaisesRegex(ValueError, "duplicate, missing, or reordered"): v05.reduce_records(rows, self.expectations(), self.config, self.digest)

    def test_cycle_source_order_and_uncommitted_installation_change_fail(self):
        rows = self.records(); entry = rows.pop(12); entry["ticks"] = rows[11]["ticks"]; rows.insert(11, entry); self._renumber(rows)
        with self.assertRaisesRegex(ValueError, "lifecycle|no release"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)
        rows = self.records()
        for index in (11, 12, 13, 14): rows[index]["generation"] = 999
        for index in (12, 13): rows[index]["artifact_id"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "installation|commit"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)

    def test_rollback_may_restore_same_artifact_under_new_generation(self):
        rows = self.records(); rows[1]["operation"] = "rollback"
        for row in rows:
            if row.get("artifact_id") == ARTIFACT_B: row["artifact_id"] = ARTIFACT_A
        self.assertEqual(v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)["trace_verdict"], "pass")

    def test_unsuccessful_prefix_and_equal_tick_ready_order_fail(self):
        rows = self.records(); rows[10]["outcome"] = "failed"; rows.pop(6); rows.pop(3); self._renumber(rows)
        expected = self.expectations(rows); expected["boots"]["session-boot-a"]["operation_outcomes"] = {"successful": 0, "failed": 1, "rejected": 0, "canceled": 0}
        with self.assertRaisesRegex(ValueError, "prefix|unsuccessful"): v05.reduce_records(rows, expected, self.config, self.digest)
        rows = self.records(); ready = rows.pop(4); ready["ticks"] = rows[4]["ticks"]; rows.insert(5, ready); self._renumber(rows)
        with self.assertRaisesRegex(ValueError, "eligible release"): v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)
        rows = self.records(); rows[4]["ticks"] = rows[5]["scheduled_ticks"]
        self.assertEqual(v05.reduce_records(rows, self.expectations(rows), self.config, self.digest)["trace_verdict"], "pass")

    def test_malformed_containers_nonfinite_json_and_capture_edges_fail(self):
        for change in (lambda value: value.update(boots=[]),
                       lambda value: value["boots"]["session-boot-a"].update(release_cycles=[])):
            expected = self.expectations(); change(expected)
            with self.assertRaisesRegex(ValueError, "expectations"): v05.reduce_records(self.records(), expected, self.config, self.digest)
        with self.assertRaisesRegex(ValueError, "non-finite"): v05.parse_json('{"x":NaN}')
        with self.assertRaisesRegex(ValueError, "terminal"): v05.reduce_records(self.records()[:-1], self.expectations(), self.config, self.digest)
        with self.assertRaisesRegex(ValueError, "final newline"): v05.parse_jsonl(json.dumps(self.records()[0]))

    def test_cli_malformed_input_returns_structured_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"; expected = Path(directory) / "expected.json"
            trace.write_text('{"type":[]}\n', encoding="utf-8"); expected.write_text(json.dumps(self.expectations()), encoding="utf-8")
            result = subprocess.run(["python3", "-B", str(ROOT / "scripts/benchmark/analyze-v05.py"), "--expectations", str(expected), str(trace)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["trace_verdict"], "fail")

    def test_enum_and_discriminator_containers_are_value_errors(self):
        cases = ((0, "evidence_kind", []), (1, "type", []), (1, "type", {}),
                 (1, "operation", []), (5, "mode", {}), (10, "outcome", []))
        for index, key, value in cases:
            rows = self.records(); rows[index][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                v05.reduce_records(rows, self.expectations(), self.config, self.digest)
        acceptance = json.loads(json.dumps(self.config))
        acceptance["required_gates"]["physical_campaign"]["missing_policy"] = []
        with self.assertRaisesRegex(ValueError, "required_gates"):
            v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest)

    @staticmethod
    def _renumber(rows):
        for seq, row in enumerate(rows[1:-1], 1): row["seq"] = seq
        rows[-1].update(seq=len(rows) - 1, event_count=len(rows) - 2, last_event_seq=len(rows) - 2)


if __name__ == "__main__": unittest.main()
