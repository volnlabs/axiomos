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

    def test_config_cannot_enable_unevaluated_gates(self):
        for name in ("physical_campaign", "fault_matrix"):
            for retain_policy in (True, False):
                acceptance = json.loads(json.dumps(self.config))
                gate = acceptance["required_gates"][name]
                gate["implemented_by_reducer"] = True
                if not retain_policy:
                    del gate["missing_policy"]
                with self.subTest(gate=name, retain_policy=retain_policy), self.assertRaisesRegex(ValueError, "unsupported reducer gate"):
                    v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest)
        report = v05.reduce_records(self.records(), self.expectations(), self.config, self.digest)
        self.assertEqual(report["gate_results"]["physical_campaign"], "blocked")
        self.assertEqual(report["gate_results"]["resource_reclamation"], "not_evaluated")
        self.assertEqual(report["release_verdict"], "blocked")
        self.assertEqual(report["release_blockers"], [name for name, gate in self.config["required_gates"].items()
                                                     if gate["required"] and report["gate_results"][name] != "pass"])

    def software_fixture(self, directory):
        directory = Path(directory)
        manifest = dict(schema="axiomos.v05.software.v1", source_id=SOURCE,
                        acceptance_config_sha256=self.digest, executables={}, cases=[])
        for executable, name in v05.SOFTWARE_EXECUTABLES.items():
            path = directory / name
            path.write_bytes(f"synthetic {executable} fixture, not qualification".encode())
            manifest["executables"][executable] = dict(path=name, sha256=v05.file_sha256(path))
        for gate, cases in v05.SOFTWARE_CASES.items():
            for case, (executable, test) in cases.items():
                row = dict(gate=gate, case=case, executable=executable, test=test, returncode=0)
                for stream in ("stdout", "stderr"):
                    path = directory / f"{gate}-{case}.{stream}"
                    path.write_text("" if stream == "stderr" else
                                    f"\nrunning 1 test\ntest {test} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 123 filtered out; finished in 0.01s\n\n")
                    row[stream], row[stream + "_sha256"] = path.name, v05.file_sha256(path)
                manifest["cases"].append(row)
        path = directory / "software.json"
        path.write_text(json.dumps(manifest))
        return path, manifest

    def test_software_requires_complete_evidence_and_honors_disabled_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.software_fixture(directory)
            acceptance = json.loads(json.dumps(self.config))
            for gate in v05.SOFTWARE_CASES:
                acceptance["required_gates"][gate]["implemented_by_reducer"] = True
            missing = v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest)
            result = v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest, software=path)
            for gate in v05.SOFTWARE_CASES:
                self.assertEqual(missing["gate_results"][gate], "not_evaluated")
                self.assertEqual(result["gate_results"][gate], "pass")
                for policy in ("not_evaluated", "blocked"):
                    acceptance["required_gates"][gate].update(implemented_by_reducer=False, missing_policy=policy)
                    report = v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest, software=path)
                    self.assertEqual(report["gate_results"][gate], policy)
                    acceptance["required_gates"][gate]["implemented_by_reducer"] = True
            self.assertEqual(result["release_verdict"], "blocked")
            self.assertEqual(len(result["software_evidence"]["cases"]), 28)

    def test_software_rejects_identity_hash_case_and_executable_substitution(self):
        mutations = [
            lambda m: m.update(schema="unknown"),
            lambda m: m.update(source_id="2" * 40),
            lambda m: m.update(acceptance_config_sha256="e" * 64),
            lambda m: m["cases"].pop(),
            lambda m: m["cases"].__setitem__(1, m["cases"][0]),
            lambda m: m["cases"][0].update(gate=[]),
            lambda m: m["cases"][0].update(test="another::test"),
            lambda m: m["cases"][0].update(executable="kernel"),
            lambda m: m["cases"][0].update(returncode=True),
            lambda m: m["cases"][0].update(returncode=1),
            lambda m: m["cases"][0].update(stdout="../outside"),
            lambda m: m["cases"][0].update(stdout_sha256="0" * 64),
            lambda m: m["executables"]["kernel_bpf"].update(path="host-test"),
            lambda m: m["executables"]["kernel_bpf"].update(sha256="0" * 64),
            lambda m: m["executables"].pop("kernel_bpf"),
            lambda m: m["cases"][1].update(stderr=m["cases"][0]["stderr"]),
        ]
        for change in mutations:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path, manifest = self.software_fixture(directory)
                change(manifest)
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    v05.validate_software(path, SOURCE, self.digest)

    def test_software_rejects_rehashed_incomplete_failed_or_reordered_logs(self):
        mutations = [
            lambda text: text.replace("running 1 test", "running 0 tests"),
            lambda text: text.replace(" ... ok", " ... ignored"),
            lambda text: text.replace("1 passed", "0 passed"),
            lambda text: text[:text.index("test result:")],
            lambda text: text.rstrip(),
            lambda text: "\n".join(reversed(text.splitlines())) + "\n",
            lambda text: text + "test unexpected::test ... ok\n",
            lambda text: text + text,
        ]
        for change in mutations:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path, manifest = self.software_fixture(directory)
                row = manifest["cases"][0]
                log = Path(directory) / row["stdout"]
                log.write_text(change(log.read_text()))
                row["stdout_sha256"] = v05.file_sha256(log)
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    v05.validate_software(path, SOURCE, self.digest)

    def reclamation_fixture(self, directory):
        directory = Path(directory)
        (directory / "host-test").write_bytes(b"synthetic executable fixture, not a qualification")
        resource = lambda programs, program_bytes, maps, map_bytes: dict(live_programs=programs, program_bytes=program_bytes, live_maps=maps, map_bytes=map_bytes)
        table, artifact = resource(0, 100, 0, 200), resource(1, 120, 0, 200)
        active, double = resource(1, 140, 1, 220), resource(2, 160, 1, 220)
        witnesses = {
            "ownership": dict(iterations=100000, transitions=0, generation=None, baseline=table, floor=artifact, high_water=active, final=table,
                              observed_maxima={"instances_live": 1, "artifact_strong_live": 2, "instance_strong_live": 2}),
            "installation": dict(iterations=99998, transitions=100000, generation=100000, baseline=double, floor=double,
                                 high_water=resource(2, 180, 2, 240), final=double,
                                 observed_maxima={"instances_before_reclamation": 2, "active_artifact_strong_after_reclamation": 3, "previous_artifact_strong_after_reclamation": 2}),
            "deactivation": dict(iterations=50000, transitions=100000, generation=100000, baseline=artifact, floor=artifact, high_water=active, final=artifact,
                                 observed_maxima={"instances_active": 1, "retained_artifact_strong_after_reclamation": 2}),
        }
        cases = []
        for name, test in v05.RECLAMATION_CASES.items():
            stdout = "running 1 test\ntest " + test + " ... synthetic fixture\n"
            if name in witnesses:
                stdout += "V05_RESOURCE " + json.dumps(dict(schema="axiomos.v05.resources.v1", case=name, **witnesses[name])) + "\n"
            stdout += "ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 123 filtered out; finished in 0.10s\n\n"
            (directory / (name + ".stdout")).write_text(stdout)
            (directory / (name + ".stderr")).write_text("")
            cases.append(dict(case=name, test=test, stdout=name + ".stdout", stdout_sha256=v05.file_sha256(directory / (name + ".stdout")),
                              stderr=name + ".stderr", stderr_sha256=v05.file_sha256(directory / (name + ".stderr")), returncode=0))
        manifest = dict(schema="axiomos.v05.reclamation.v1", source_id=SOURCE, acceptance_config_sha256=self.digest,
                        executable=dict(path="host-test", sha256=v05.file_sha256(directory / "host-test")), cases=cases)
        path = directory / "reclamation.json"
        path.write_text(json.dumps(manifest))
        return path, manifest

    def test_reclamation_requires_actual_evidence_and_never_qualifies_release(self):
        acceptance = json.loads(json.dumps(self.config))
        acceptance["required_gates"]["resource_reclamation"]["implemented_by_reducer"] = True
        acceptance["required_gates"]["resource_reclamation"].pop("missing_policy", None)
        report = v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest)
        self.assertEqual(report["gate_results"]["resource_reclamation"], "not_evaluated")
        self.assertIn("resource_reclamation", report["release_blockers"])
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.reclamation_fixture(directory)
            report = v05.reduce_records(self.records(), self.expectations(), acceptance, self.digest, path)
        self.assertEqual(report["gate_results"]["resource_reclamation"], "pass")
        self.assertNotIn("resource_reclamation", report["release_blockers"])
        self.assertEqual(report["release_verdict"], "blocked")
        self.assertEqual(report["gate_results"]["physical_campaign"], "blocked")
        self.assertEqual(report["gate_results"]["authentication_and_loading"], "not_evaluated")
        self.assertEqual(report["reclamation_evidence"]["witnesses"]["installation"]["iterations"], 99998)

    def test_disabled_reducer_gates_keep_configured_policy_despite_valid_evidence(self):
        for name in ("trace_subset", "resource_reclamation"):
            for policy in ("blocked", "not_evaluated"):
                with self.subTest(gate=name, policy=policy), tempfile.TemporaryDirectory() as directory:
                    acceptance = json.loads(json.dumps(self.config))
                    acceptance["required_gates"][name].update(implemented_by_reducer=False, missing_policy=policy)
                    config_path = Path(directory) / "acceptance.json"
                    config_path.write_text(json.dumps(acceptance))
                    digest = v05.file_sha256(config_path)
                    rows, expected = self.records(), self.expectations()
                    rows[0]["acceptance_config_sha256"] = digest
                    expected["acceptance_config_sha256"] = digest
                    path, manifest = self.reclamation_fixture(directory)
                    manifest["acceptance_config_sha256"] = digest
                    path.write_text(json.dumps(manifest))
                    report = v05.reduce_records(rows, expected, acceptance, digest, path)
                    self.assertEqual(report["gate_results"][name], policy)
                    self.assertIn(name, report["release_blockers"])
                    self.assertEqual(report["release_verdict"], "blocked")

    def test_reclamation_rejects_identity_hash_path_and_required_case_changes(self):
        changes = (
            lambda m, p: m.update(source_id="2" * 40),
            lambda m, p: m.update(acceptance_config_sha256="f" * 64),
            lambda m, p: m["executable"].update(sha256="0" * 64),
            lambda m, p: m["cases"][0].update(stdout_sha256="0" * 64),
            lambda m, p: m["cases"][0].update(stderr_sha256="0" * 64),
            lambda m, p: m["cases"].pop(),
            lambda m, p: m["cases"].__setitem__(1, m["cases"][0]),
            lambda m, p: m["cases"][0].update(test="unrelated::test"),
            lambda m, p: m["cases"][0].update(returncode=True),
            lambda m, p: m["cases"][0].update(returncode=1),
            lambda m, p: m["cases"][0].update(stdout="../outside"),
            lambda m, p: m["cases"][0].update(stdout=str(p / "ownership.stdout")),
            lambda m, p: (p / "ownership.stdout").unlink(),
            lambda m, p: (p / "host-test").write_bytes(b"changed executable"),
            lambda m, p: (p / "ownership.stderr").write_text("changed retained stderr"),
        )
        for index, change in enumerate(changes):
            with self.subTest(change=index), tempfile.TemporaryDirectory() as directory:
                path, manifest = self.reclamation_fixture(directory)
                change(manifest, Path(directory))
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    v05.validate_reclamation(path, SOURCE, self.digest, self.config)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); evidence = parent / "evidence"; evidence.mkdir()
            path, manifest = self.reclamation_fixture(evidence)
            outside = parent / "outside"; outside.write_text((evidence / "ownership.stdout").read_text())
            (evidence / "ownership.stdout").unlink(); (evidence / "ownership.stdout").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                v05.validate_reclamation(path, SOURCE, self.digest, self.config)

    def test_reclamation_rejects_truncated_failed_or_ambiguous_test_logs(self):
        changes = (
            lambda text: text.rstrip("\n"),
            lambda text: text.split("test result:")[0],
            lambda text: text.replace("1 passed", "0 passed"),
            lambda text: text.replace("0 ignored", "1 ignored"),
            lambda text: text.replace("running 1 test", "running 2 tests"),
            lambda text: text.replace("test bpf::managed::tests::managed_ownership_lifecycle_survives_100_000_fresh_instances ... ", "test unrelated::test ... "),
            lambda text: text.replace("running 1 test\n", "running 1 test\ntest unrelated::test ... ok\n"),
            lambda text: text + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n",
            lambda text: text + "unaccounted trailing output\n",
            lambda text: "\n".join(line for line in text.splitlines() if not line.startswith("V05_RESOURCE")) + "\n",
            lambda text: text.replace("V05_RESOURCE ", "V05_RESOURCE"),
            lambda text: next(line for line in text.splitlines(keepends=True) if line.startswith("V05_RESOURCE "))
                         + "".join(line for line in text.splitlines(keepends=True) if not line.startswith("V05_RESOURCE ")),
        )
        for index, change in enumerate(changes):
            with self.subTest(change=index), tempfile.TemporaryDirectory() as directory:
                path, manifest = self.reclamation_fixture(directory)
                log = Path(directory) / manifest["cases"][0]["stdout"]
                log.write_text(change(log.read_text()))
                manifest["cases"][0]["stdout_sha256"] = v05.file_sha256(log)
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    v05.validate_reclamation(path, SOURCE, self.digest, self.config)

    def test_reclamation_obeys_rehashed_acceptance_resource_limits(self):
        limits = (("max_artifacts", 2), ("max_instances", 1), ("max_retire_batches", 0),
                  ("displaced_instances", 0), ("evicted_artifacts", 0))
        for key, value in limits:
            with self.subTest(limit=key), tempfile.TemporaryDirectory() as directory:
                path, manifest = self.reclamation_fixture(directory)
                acceptance = json.loads(json.dumps(self.config))
                resources = acceptance["resources"]
                (resources if key in resources else resources["retire_batch_capacity"])[key] = value
                config = Path(directory) / "acceptance.json"; config.write_text(json.dumps(acceptance))
                digest = v05.file_sha256(config)
                manifest["acceptance_config_sha256"] = digest; path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "resource limits"):
                    v05.validate_reclamation(path, SOURCE, digest, acceptance)

    def test_reclamation_rejects_short_churn_and_resource_or_reference_contradictions(self):
        changes = (
            ("ownership", lambda r: r.update(iterations=99999)),
            ("ownership", lambda r: r.update(iterations=1 << 64)),
            ("ownership", lambda r: r["high_water"].update(program_bytes=1 << 64)),
            ("installation", lambda r: r.update(iterations=(1 << 64) - 2, transitions=1 << 64, generation=1 << 64)),
            ("ownership", lambda r: r.update(generation=0)),
            ("ownership", lambda r: r["final"].update(program_bytes=101)),
            ("ownership", lambda r: r["observed_maxima"].update(instance_strong_live=3)),
            ("installation", lambda r: r.update(iterations=100000)),
            ("installation", lambda r: r.update(generation=99999)),
            ("installation", lambda r: r["high_water"].update(live_maps=1)),
            ("installation", lambda r: r["high_water"].update(program_bytes=r["floor"]["program_bytes"])),
            ("installation", lambda r: r["observed_maxima"].update(instances_before_reclamation=True)),
            ("deactivation", lambda r: r.update(transitions=99998, generation=99998, iterations=49999)),
            ("deactivation", lambda r: r["floor"].update(live_maps=1)),
            ("deactivation", lambda r: r["observed_maxima"].update(retained_artifact_strong_after_reclamation=1)),
        )
        for name, change in changes:
            with self.subTest(case=name, change=change), tempfile.TemporaryDirectory() as directory:
                path, manifest = self.reclamation_fixture(directory)
                case = next(case for case in manifest["cases"] if case["case"] == name)
                log = Path(directory) / case["stdout"]
                lines = log.read_text().splitlines(keepends=True)
                index = next(i for i, line in enumerate(lines) if line.startswith("V05_RESOURCE "))
                witness = json.loads(lines[index][len("V05_RESOURCE "):]); change(witness)
                lines[index] = "V05_RESOURCE " + json.dumps(witness) + "\n"
                log.write_text("".join(lines)); case["stdout_sha256"] = v05.file_sha256(log)
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    v05.validate_reclamation(path, SOURCE, self.digest, self.config)

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
