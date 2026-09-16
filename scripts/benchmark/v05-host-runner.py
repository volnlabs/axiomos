#!/usr/bin/env python3
"""Retain and reduce the real kernel host lifecycle fixture with a modeled clock.

This is synthetic evidence, never hardware timing or a release qualification.
Run from a clean checkout; use a new output directory under target/ or outside
the checkout. Failed runs are retained. Re-run the printed reducer commands to
reproduce each verdict from the retained trace, expectations and acceptance file.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("analyze_v05", ROOT / "scripts/benchmark/analyze-v05.py")
v05 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v05)
TEST = "bpf::preparation::tests::trace::managed_host_benchmark_trace"

# Workload ledger, fixed independently of emitted events. Normal: A runs during
# two delayed worker releases; replace B, rollback A, reject stale generation,
# then time out a withheld acknowledgement. The negative scenario branches after
# rollback and skips three scheduled releases during a modeled legacy syscall.
SCENARIOS = {
    "normal": {
        "event_counts": {"operation_request": 4, "operation_accepted": 3,
                         "handoff_enter": 3, "sink_safe_ready": 2,
                         "operation_committed": 2, "operation_response": 4,
                         "cycle_release": 16, "behavior_enter": 5,
                         "behavior_exit": 5, "cycle_complete": 16},
        "operation_outcomes": {"successful": 2, "failed": 1, "rejected": 1, "canceled": 0},
        "release_cycles": {"first": 1, "count": 16},
    },
    "legacy-stall": {
        "event_counts": {"operation_request": 2, "operation_accepted": 2,
                         "handoff_enter": 2, "sink_safe_ready": 2,
                         "operation_committed": 2, "operation_response": 2,
                         "cycle_release": 8, "behavior_enter": 5,
                         "behavior_exit": 5, "cycle_complete": 8},
        "operation_outcomes": {"successful": 2, "failed": 0, "rejected": 0, "canceled": 0},
        # All scheduled releases, including the three the executor accounts lost.
        "release_cycles": {"first": 1, "count": 11},
    },
}


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def run_logged(command: list[str], stdout: Path, stderr: Path, *, env=None, timeout=60):
    # Stream to retained files so failures/timeouts cannot discard partial output.
    with stdout.open("w", encoding="utf-8") as out, stderr.open("w", encoding="utf-8") as err:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=timeout)
    return subprocess.CompletedProcess(command, result.returncode,
                                       stdout.read_text(encoding="utf-8"), stderr.read_text(encoding="utf-8"))


def clean_source() -> str:
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True)
    if status:
        raise ValueError("source must be clean; retain output under target/ or outside the checkout")
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def executable_from_cargo(output: str) -> Path:
    paths = []
    for line in output.splitlines():
        record = v05.parse_json(line)
        if not isinstance(record, dict):
            raise ValueError("malformed Cargo record")
        if record.get("reason") == "compiler-artifact" and (
                not isinstance(record.get("target"), dict)
                or not isinstance(record.get("profile"), dict)):
            raise ValueError("malformed Cargo artifact metadata")
        if (record.get("reason") == "compiler-artifact"
                and record.get("target", {}).get("name") == "kernel"
                and record.get("target", {}).get("kind") == ["lib"]
                and record.get("profile", {}).get("test") is True
                and record.get("executable")):
            if not isinstance(record["executable"], str):
                raise ValueError("malformed Cargo executable path")
            paths.append(Path(record["executable"]))
    if len(paths) != 1:
        raise ValueError("Cargo must identify exactly one kernel host test executable")
    return paths[0]


def extract_trace(output: str) -> str:
    lines = []
    for line in output.splitlines(keepends=True):
        if line.startswith("V05_TRACE"):
            if not line.startswith("V05_TRACE ") or not line.endswith("\n"):
                raise ValueError("truncated or malformed producer record")
            lines.append(line[len("V05_TRACE "):])
    text = "".join(lines)
    # Validate framing without inferring workload expectations from observations.
    rows = v05.parse_jsonl(text)
    if len(rows) < 3 or rows[0].get("type") != "header" or rows[-1].get("type") != "terminal":
        raise ValueError("producer omitted a complete trace")
    return text


def expectations(scenario: str, source: str, artifact: str, config: str) -> dict:
    return {"schema": v05.EXPECTATIONS_SCHEMA, "acceptance_config_sha256": config,
            "boots": {scenario: {"source_id": source, "artifact_id": artifact,
                                 **copy.deepcopy(SCENARIOS[scenario])}}}


def validate_artifacts(rows: list[dict], directory: Path) -> dict:
    # Match ProgramHash::compute; file checksums elsewhere remain SHA-256.
    digests = {name: hashlib.sha3_256((directory / name).read_bytes()).hexdigest()
               for name in ("a.bundle", "b.bundle")}
    observed = [row["artifact_id"] for row in rows if "artifact_id" in row]
    if (not rows or rows[0].get("artifact_id") != digests["a.bundle"]
            or any(not isinstance(value, str) for value in observed)
            or set(observed) != set(digests.values())):
        raise ValueError("trace artifact identities differ from retained bundles")
    return digests


def run(output: Path) -> None:
    source = clean_source()
    output.mkdir(parents=True, exist_ok=False)
    acceptance = output / "acceptance.json"
    shutil.copyfile(v05.DEFAULT_ACCEPTANCE, acceptance)
    config = v05.file_sha256(acceptance)
    env = os.environ.copy()
    env["EMBEDDED_DISK_PATH"] = "/dev/null"
    # The fixture owns its test signing key; no operator trust material is needed.
    env.pop("AXIOM_BPF_TRUSTED_KEY_PATH", None)
    command = ["cargo", "test", "--locked", "-p", "kernel", "--lib", "--features",
               "embedded-profile,managed-runtime", "--no-run", "--message-format=json"]
    manifest = {"schema": "axiomos.v05.host-run.v1", "source_id": source,
                "evidence_kind": "synthetic", "release_verdict": "blocked",
                "artifact_identity_algorithm": "sha3-256", "file_checksum_algorithm": "sha256",
                "scope": "host state-machine sequencing with modeled clock, acknowledgements and effect submission",
                "operation_id_domain": "benchmark attempts; accepted kernel operation IDs are checked inside the fixture",
                "timeout_cause_evidence": "fixture asserts HandoffError::TimedOut and ETIMEDEOUT; trace records generic failed outcome",
                "build_command": command, "test": TEST, "status": "incomplete",
                "build_environment": {key: env[key] for key in
                                      ("EMBEDDED_DISK_PATH", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_TARGET")
                                      if key in env},
                "acceptance_config_sha256": config, "runs": {}}
    dump(output / "manifest.json", manifest)
    try:
        build = run_logged(command, output / "build.jsonl", output / "build.stderr", env=env, timeout=600)
        build.check_returncode()
        executable = executable_from_cargo(build.stdout)
        retained = output / "host-test"
        shutil.copy2(executable, retained)
        manifest["test_executable_sha256"] = v05.file_sha256(retained)
        manifest["toolchain"] = subprocess.check_output(["rustc", "-Vv"], cwd=ROOT, env=env, text=True)
        manifest["cargo_lock_sha256"] = v05.file_sha256(ROOT / "Cargo.lock")
        if clean_source() != source or v05.file_sha256(v05.DEFAULT_ACCEPTANCE) != config:
            raise ValueError("source or acceptance changed during the build")
        reclamation = {"schema": "axiomos.v05.reclamation.v1", "source_id": source,
                       "acceptance_config_sha256": config,
                       "executable": {"path": "host-test", "sha256": manifest["test_executable_sha256"]},
                       "cases": []}
        for case, test in v05.RECLAMATION_CASES.items():
            directory = output / "reclamation" / case
            directory.mkdir(parents=True)
            stdout, stderr = directory / "stdout.log", directory / "stderr.log"
            test_command = [str(retained), test, "--exact", "--nocapture", "--test-threads=1"]
            result = run_logged(test_command, stdout, stderr,
                                env={**env, "AXIOM_V05_RESOURCE_EVIDENCE": "1"})
            reclamation["cases"].append({
                "case": case, "test": test, "returncode": result.returncode,
                "stdout": str(stdout.relative_to(output)), "stdout_sha256": v05.file_sha256(stdout),
                "stderr": str(stderr.relative_to(output)), "stderr_sha256": v05.file_sha256(stderr),
            })
            # Retain even a failed or incomplete campaign; never infer success
            # from a witness printed before the test process finishes.
            dump(output / "reclamation.json", reclamation)
            result.check_returncode()
        for scenario in SCENARIOS:
            directory = output / scenario
            directory.mkdir()
            artifacts = directory / "artifacts"
            artifacts.mkdir()
            env.update(AXIOM_V05_TRACE_SOURCE=source, AXIOM_V05_TRACE_CONFIG=config,
                       AXIOM_V05_TRACE_SCENARIO=scenario,
                       AXIOM_V05_TRACE_ARTIFACT_DIR=str(artifacts))
            test_command = [str(retained), TEST, "--exact", "--nocapture", "--test-threads=1", "--quiet"]
            result = run_logged(test_command, directory / "stdout.log", directory / "stderr.log", env=env)
            result.check_returncode()
            trace = extract_trace(result.stdout)
            (directory / "trace.jsonl").write_text(trace, encoding="utf-8")
            digests = validate_artifacts(v05.parse_jsonl(trace), artifacts)
            dump(directory / "expectations.json", expectations(scenario, source, digests["a.bundle"], config))
            reduce_command = [sys.executable, str(ROOT / "scripts/benchmark/analyze-v05.py"),
                              "--acceptance", str(acceptance), "--reclamation", str(output / "reclamation.json"), "--expectations",
                              str(directory / "expectations.json"), str(directory / "trace.jsonl")]
            reduced = run_logged(reduce_command, directory / "results.json", directory / "reducer.stderr")
            report = v05.parse_json(reduced.stdout)
            if not isinstance(report, dict):
                raise ValueError("malformed reducer result")
            if scenario == "normal":
                if (reduced.returncode != 0 or report.get("trace_verdict") != "pass"
                        or report.get("gate_results", {}).get("resource_reclamation") != "pass"):
                    raise ValueError("normal host trace did not pass reduction")
            elif (reduced.returncode != 1 or report.get("trace_verdict") != "fail"
                  or report.get("error") != "cycle release coverage does not match expectations"):
                raise ValueError("modeled legacy syscall did not fail release-coverage validation")
            if report.get("release_verdict") != "blocked":
                raise ValueError("synthetic host evidence must never qualify a release")
            manifest["runs"][scenario] = {
                "command": test_command, "reduction_command": reduce_command,
                "bundle_digests": digests,
                "trace_verdict": report["trace_verdict"],
                "files_sha256": {str(path.relative_to(directory)): v05.file_sha256(path)
                                 for path in sorted(directory.rglob("*")) if path.is_file()},
            }
        if (clean_source() != source or v05.file_sha256(v05.DEFAULT_ACCEPTANCE) != config
                or v05.file_sha256(retained) != manifest["test_executable_sha256"]):
            raise ValueError("source, acceptance or executable changed during collection")
        manifest["status"] = "pass"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        manifest["status"] = "fail"
        manifest["error"] = str(error)
        raise
    finally:
        dump(output / "manifest.json", manifest)
        # Standard tooling can check the retained inputs before rerunning reduction.
        paths = sorted(path for path in output.rglob("*") if path.is_file())
        (output / "SHA256SUMS").write_text("".join(
            f"{v05.file_sha256(path)}  {path.relative_to(output)}\n" for path in paths), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.output.resolve())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Host trace checks passed; release remains blocked. Evidence: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
