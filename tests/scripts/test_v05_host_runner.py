import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import struct
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("v05_host_runner", ROOT / "scripts/benchmark/v05-host-runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def cargo_artifact(executable, **changes):
    record = {"reason": "compiler-artifact", "target": {"name": "kernel", "kind": ["lib"]},
              "profile": {"test": True}, "executable": str(executable)}
    record.update(changes)
    return record


def cargo_output(*records):
    return "".join(json.dumps(record) + "\n" for record in records)


class V05HostRunnerTests(unittest.TestCase):
    def test_executable_is_selected_from_exact_cargo_artifact_not_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "old-kernel-test"
            newer = Path(directory) / "newer-unrelated-test"
            selected.write_bytes(b"selected")
            newer.write_bytes(b"unrelated")
            os.utime(selected, (1, 1))
            os.utime(newer, (2, 2))
            records = [
                {"reason": "build-finished", "success": True},
                cargo_artifact(newer, target={"name": "other", "kind": ["lib"]}),
                cargo_artifact(newer, target={"name": "kernel", "kind": ["bin"]}),
                cargo_artifact(newer, profile={"test": False}),
                cargo_artifact(selected),
            ]
            self.assertEqual(runner.executable_from_cargo(cargo_output(*records)), selected)
            self.assertEqual(runner.executable_from_cargo(cargo_output(*reversed(records))), selected)

    def test_bpf_executable_selection_excludes_kernel_binary_and_non_test_artifacts(self):
        selected = Path("retained-bpf-test")
        records = [cargo_artifact("kernel-test"),
                   cargo_artifact("bpf-bin", target={"name": "kernel_bpf", "kind": ["bin"]}),
                   cargo_artifact("bpf-lib", target={"name": "kernel_bpf", "kind": ["lib"]}, profile={"test": False}),
                   cargo_artifact(selected, target={"name": "kernel_bpf", "kind": ["lib"]})]
        self.assertEqual(runner.executable_from_cargo(cargo_output(*records), "kernel_bpf", "lib", True), selected)
        with self.assertRaisesRegex(ValueError, "exactly one kernel_bpf"):
            runner.executable_from_cargo(cargo_output(*records[:-1]), "kernel_bpf", "lib", True)

    def test_software_collection_retains_each_fixed_exact_case_and_executable_hash(self):
        expected = [(gate, case, executable, test)
                    for gate, cases in runner.v05.SOFTWARE_CASES.items()
                    for case, (executable, test) in cases.items()]
        self.assertEqual(len(expected), sum(len(cases) for cases in runner.v05.SOFTWARE_CASES.values()))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for filename in runner.v05.SOFTWARE_EXECUTABLES.values():
                (output / filename).write_bytes(filename.encode())
            commands = []

            def recorded(command, stdout, stderr, *, env):
                commands.append(command)
                self.assertEqual(env, {"FIXTURE": "synthetic"})
                stdout.write_text(f"running 1 test\ntest {command[1]} ... ok\n"
                                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
                stderr.write_text("fixture stderr\n")
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(runner, "run_logged", side_effect=recorded):
                runner.collect_software(output, "source", "config", {"FIXTURE": "synthetic"})
            evidence = json.loads((output / "software.json").read_text())
            self.assertEqual(set(evidence), {"schema", "source_id", "acceptance_config_sha256", "executables", "cases"})
            self.assertEqual(evidence["schema"], "axiomos.v05.software.v1")
            self.assertEqual(evidence["source_id"], "source")
            self.assertEqual(evidence["acceptance_config_sha256"], "config")
            self.assertEqual(len(evidence["cases"]), len(expected))
            paths = []
            for row, (gate, case, executable, test), command in zip(evidence["cases"], expected, commands):
                self.assertEqual(command, [str(output / runner.v05.SOFTWARE_EXECUTABLES[executable]), test,
                                           "--exact", "--test-threads=1"])
                self.assertEqual((row["gate"], row["case"], row["executable"], row["test"], row["returncode"]),
                                 (gate, case, executable, test, 0))
                for stream in ("stdout", "stderr"):
                    paths.append(row[stream])
                    self.assertEqual(row[stream + "_sha256"], runner.v05.file_sha256(output / row[stream]))
            self.assertEqual(len(paths), len(set(paths)))
            for key, filename in runner.v05.SOFTWARE_EXECUTABLES.items():
                self.assertEqual(evidence["executables"][key],
                                 {"path": filename, "sha256": runner.v05.file_sha256(output / filename)})

    def test_failed_software_case_is_retained_before_collection_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for filename in runner.v05.SOFTWARE_EXECUTABLES.values():
                (output / filename).write_bytes(filename.encode())

            def failed(command, stdout, stderr, *, env):
                stdout.write_text("actual failed test output\n")
                stderr.write_text("actual failure details\n")
                return subprocess.CompletedProcess(command, 101)

            with mock.patch.object(runner, "run_logged", side_effect=failed) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    runner.collect_software(output, "source", "config", {})
            run.assert_called_once()
            evidence = json.loads((output / "software.json").read_text())
            self.assertEqual(len(evidence["cases"]), 1)
            row = evidence["cases"][0]
            self.assertEqual(row["returncode"], 101)
            self.assertEqual((output / row["stdout"]).read_text(), "actual failed test output\n")
            self.assertEqual((output / row["stderr"]).read_text(), "actual failure details\n")
            for stream in ("stdout", "stderr"):
                self.assertEqual(row[stream + "_sha256"], runner.v05.file_sha256(output / row[stream]))

    def test_missing_and_ambiguous_executable_artifacts_reject(self):
        for records in ((), ({"reason": "build-finished", "success": True},),
                        (cargo_artifact("first"), cargo_artifact("second")),
                        (cargo_artifact("same"), cargo_artifact("same")),
                        (cargo_artifact("", profile={"test": True}),)):
            with self.subTest(records=records), self.assertRaisesRegex(ValueError, "exactly one"):
                runner.executable_from_cargo(cargo_output(*records))

    def test_malformed_cargo_records_raise_a_retained_failure(self):
        for record in ([], None, True, {"reason": "compiler-artifact", "target": None},
                       cargo_artifact("test", profile=[]),
                       {**cargo_artifact("test"), "executable": ["not", "a", "path"]}):
            with self.subTest(record=record), self.assertRaises(ValueError):
                runner.executable_from_cargo(cargo_output(record))
        with self.assertRaises(ValueError):
            runner.executable_from_cargo('{"reason":"compiler-artifact","reason":"build-finished"}\n')

    def test_trace_extraction_preserves_exact_jsonl_and_ignores_test_noise(self):
        trace = '{"type":"header"}\n{"type":"cycle_release","seq":1}\n{"type":"terminal"}\n'
        stdout = "running 1 test\n" + "".join("V05_TRACE " + line for line in trace.splitlines(keepends=True)) + "test result: ok\n"
        self.assertEqual(runner.extract_trace(stdout), trace)

    def test_empty_truncated_or_malformed_producer_output_rejects(self):
        for stdout in ("", "test result: ok\n", "V05_TRACE\n", "V05_TRACE{}\n",
                       'V05_TRACE {"type":"header"}\n',
                       'V05_TRACE {"type":"header"}\nV05_TRACE {"type":"event"}\n',
                       'V05_TRACE {"type":"header"}\nV05_TRACE {"type":"event"}\nV05_TRACE {"type":"terminal"}',
                       'V05_TRACE {"type":"header"}\nV05_TRACE []\nV05_TRACE {"type":"terminal"}\n',
                       'V05_TRACE {"type":"header","type":"terminal"}\n',
                       'V05_TRACE {broken}\n'):
            with self.subTest(stdout=stdout), self.assertRaises(ValueError):
                runner.extract_trace(stdout)

    def test_retained_bundles_bind_every_trace_artifact_and_initial_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            bundles = {"a.bundle": b"signed controller A", "b.bundle": b"signed controller B"}
            digests = {name: hashlib.sha3_256(data).hexdigest() for name, data in bundles.items()}
            for name, data in bundles.items():
                (directory / name).write_bytes(data)
            rows = [{"type": "header", "artifact_id": digests["a.bundle"]},
                    {"type": "operation_request", "artifact_id": digests["b.bundle"]},
                    {"type": "terminal"}]
            self.assertEqual(runner.validate_artifacts(rows, directory), digests)
            with self.assertRaisesRegex(ValueError, "artifact identities"):
                runner.validate_artifacts([rows[1], rows[0], rows[2]], directory)
            with self.assertRaisesRegex(ValueError, "artifact identities"):
                runner.validate_artifacts([rows[0], rows[2]], directory)
            (directory / "b.bundle").write_bytes(b"modified controller B")
            with self.assertRaisesRegex(ValueError, "artifact identities"):
                runner.validate_artifacts(rows, directory)
            (directory / "b.bundle").unlink()
            with self.assertRaises(FileNotFoundError):
                runner.validate_artifacts(rows, directory)

    def test_timeout_retains_partial_stdout_and_stderr(self):
        command = ["fixture", "--exact"]
        environment = {"FIXTURE": "synthetic"}

        def timeout_after_output(actual, *, cwd, env, stdout, stderr, timeout):
            self.assertEqual(actual, command)
            self.assertEqual(cwd, runner.ROOT)
            self.assertEqual(env, environment)
            self.assertEqual(timeout, 3)
            stdout.write('V05_TRACE {"type":"header"}\nV05_TRACE {"type":')
            stderr.write("fixture stalled before terminal\n")
            raise subprocess.TimeoutExpired(actual, timeout)

        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "stdout.log", Path(directory) / "stderr.log"
            with mock.patch.object(runner.subprocess, "run", side_effect=timeout_after_output) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner.run_logged(command, out, err, env=environment, timeout=3)
            run.assert_called_once()
            self.assertEqual(out.read_text(), 'V05_TRACE {"type":"header"}\nV05_TRACE {"type":')
            self.assertEqual(err.read_text(), "fixture stalled before terminal\n")
            with self.assertRaises(ValueError):
                runner.extract_trace(out.read_text())

    def test_expectations_are_fixed_and_return_independent_nested_values(self):
        ledger = copy.deepcopy(runner.SCENARIOS)
        try:
            expected = runner.expectations("normal", "source", "artifact", "config")
            boot = expected["boots"]["normal"]
            self.assertEqual(boot["event_counts"]["operation_request"], 4)
            self.assertEqual(boot["release_cycles"], {"first": 1, "count": 16})
            boot["event_counts"]["operation_request"] = 0
            boot["release_cycles"]["count"] = 0
            boot["operation_outcomes"]["successful"] = 0
            fresh = runner.expectations("normal", "source", "artifact", "config")
            self.assertEqual(runner.SCENARIOS, ledger)
            self.assertEqual(fresh["boots"]["normal"], {"source_id": "source", "artifact_id": "artifact", **ledger["normal"]})
            stalled = runner.expectations("legacy-stall", "source", "artifact", "config")["boots"]["legacy-stall"]
            # Eight observed releases must not shrink the eleven expected releases.
            self.assertEqual(stalled["event_counts"]["cycle_release"], 8)
            self.assertEqual(stalled["release_cycles"]["count"], 11)
        finally:
            runner.SCENARIOS.clear()
            runner.SCENARIOS.update(ledger)

    def test_joined_export_must_match_kernel_bytes_and_explain_fresh_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            header = dict(type="header", slot_generation=3, session=1, session_established=True,
                          oldest=0, end=1, overwritten=0, dropped=0)
            record = dict(type="record", sequence=0, ticks=1, correlation=3, kind=2, payload_hex="a5" * 64)
            end = dict(type="end", cursor=1, records=1, gaps=0)
            raw = struct.pack("<QQQI4x64s", 0, 1, 3, 2, b"\xa5" * 64)
            (directory / "records.bin").write_bytes(raw)
            rows = [header, record, end]
            (directory / "audit.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            pairs = [(1, [0, 0]), (1, [1, 1]), (1, [2, 2]), (2, [0, 3]), (2, [1, 3]), (3, [0, 0]), (3, [1, 1])]
            events = [dict(decoded=dict(event="cycle", generation=generation, requested_pair=pair, handoff=False)) for generation, pair in pairs]
            events += [dict(decoded=dict(event="cycle", handoff=True, requested_pair=None)) for _ in range(3)]
            decoded = dict(qualification_evaluated=False, signature_reverified=False, payloads_decoded=True,
                           semantic_gaps=[], events=events, latest_stop_decoded={"event": "stop"})
            (directory / "decoded.json").write_text(json.dumps(decoded))
            self.assertEqual(runner.validate_audit(directory)["generation"], 3)
            (directory / "records.bin").write_bytes(raw[:-1])
            with self.assertRaisesRegex(ValueError, "actual kernel recorder"):
                runner.validate_audit(directory)
            (directory / "records.bin").write_bytes(raw)
            events[5]["decoded"]["requested_pair"] = [3, 3]
            (directory / "decoded.json").write_text(json.dumps(decoded))
            with self.assertRaisesRegex(ValueError, "fresh rollback"):
                runner.validate_audit(directory)
            (directory / "audit.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows[:-1]))
            with self.assertRaisesRegex(ValueError, "complete records"):
                runner.validate_audit(directory)


if __name__ == "__main__":
    unittest.main()
