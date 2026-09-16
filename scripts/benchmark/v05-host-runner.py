#!/usr/bin/env python3
"""Retain host lifecycle evidence and export its recorder through the real CLI.

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
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("analyze_v05", ROOT / "scripts/benchmark/analyze-v05.py")
v05 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v05)
TEST = "bpf::preparation::tests::trace::managed_host_benchmark_trace"
WORKFLOW_TEST = "bpf::preparation::tests::workflow::framed_installer_upload_replace_fresh_rollback_and_stop_produce_one_joined_audit"

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


def executable_from_cargo(output: str, name="kernel", kind="lib", test=True) -> Path:
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
                and record.get("target", {}).get("name") == name
                and record.get("target", {}).get("kind") == [kind]
                and record.get("profile", {}).get("test") is test
                and record.get("executable")):
            if not isinstance(record["executable"], str):
                raise ValueError("malformed Cargo executable path")
            paths.append(Path(record["executable"]))
    if len(paths) != 1:
        raise ValueError(f"Cargo must identify exactly one {name} executable")
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


def validate_audit(directory: Path) -> dict:
    rows = v05.parse_jsonl((directory / "audit.jsonl").read_text(encoding="utf-8"))
    if len(rows) < 3 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("joined audit lacks complete records")
    header, terminal = rows[0], rows[-1]
    records = rows[1:-1]
    if (header.get("type") != "header" or terminal.get("type") != "end"
            or header.get("slot_generation") != 3 or header.get("oldest") != 0
            or header.get("session") != 1 or header.get("session_established") is not True
            or header.get("overwritten") != 0 or header.get("dropped") != 0
            or terminal.get("gaps") != 0 or terminal.get("records") != len(records)
            or terminal.get("cursor") != header.get("end")):
        raise ValueError("joined audit interval or final installation mismatch")
    try:
        if any(r["type"] != "record" or len(bytes.fromhex(r["payload_hex"])) != 64 for r in records):
            raise ValueError("joined audit contains invalid records")
        raw = b"".join(struct.pack("<QQQI4x64s", r["sequence"], r["ticks"], r["correlation"],
                                  r["kind"], bytes.fromhex(r["payload_hex"])) for r in records)
    except (KeyError, TypeError, struct.error) as error:
        raise ValueError("joined audit contains malformed records") from error
    if not raw or raw != (directory / "records.bin").read_bytes():
        raise ValueError("CLI export differs from actual kernel recorder bytes")
    decoded = v05.load_json(directory / "decoded.json")
    if (decoded.get("qualification_evaluated") is not False
            or decoded.get("signature_reverified") is not False
            or decoded.get("payloads_decoded") is not True
            or decoded.get("semantic_gaps") != []):
        raise ValueError("joined audit decode is incomplete or overclaims qualification")
    cycles = [r["decoded"] for r in decoded.get("events", []) if r.get("decoded", {}).get("event") == "cycle"]
    requests = [(r.get("generation"), r["requested_pair"]) for r in cycles if r.get("requested_pair") is not None]
    if (requests != [(1, [0, 0]), (1, [1, 1]), (1, [2, 2]), (2, [0, 3]), (2, [1, 3]), (3, [0, 0]), (3, [1, 1])]
            or sum(r.get("handoff") is True for r in cycles) != 3
            or decoded.get("latest_stop_decoded") is None):
        raise ValueError("decoded audit does not explain replacement, fresh rollback and stop")
    return {"records": len(records), "generation": header["slot_generation"],
            "scope": "real host recorder, installer and CLI export/decode; syscall copies and physical transport excluded"}


def export_workflow(output: Path, retained: Path, cli: Path, env: dict) -> dict:
    directory = output / "workflow"
    directory.mkdir()
    # A fresh PTY is the only serial character device opened by this campaign.
    # The Unix socket carries unchanged installer frames to the host kernel test.
    with tempfile.TemporaryDirectory(prefix="v05-audit-") as temporary:
        address = str(Path(temporary) / "installer.sock")
        master, slave = os.openpty()
        worker = client = None
        worker_command = [str(retained), WORKFLOW_TEST, "--exact", "--nocapture", "--test-threads=1"]
        client_command = [str(cli), "runtime", "--port", os.ttyname(slave), "audit-export",
                          "--output", str(directory / "audit.jsonl")]
        try:
            with (directory / "kernel.stdout").open("wb") as out, (directory / "kernel.stderr").open("wb") as err, \
                    (directory / "cli.stdout").open("wb") as cli_out, (directory / "cli.stderr").open("wb") as cli_err:
                worker = subprocess.Popen(worker_command, cwd=ROOT, stdout=out, stderr=err,
                                          env={**env, "AXIOM_V05_AUDIT_SOCKET": address,
                                               "AXIOM_V05_AUDIT_RECORDS": str(directory / "records.bin")})
                deadline = time.monotonic() + 30
                while not Path(address).exists():
                    if worker.poll() is not None or time.monotonic() >= deadline:
                        raise ValueError("kernel audit endpoint did not become ready")
                    time.sleep(0.01)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(1)
                    peer.connect(address)
                    os.set_blocking(master, False)
                    client = subprocess.Popen(client_command, cwd=ROOT, stdout=cli_out, stderr=cli_err)
                    while client.poll() is None:
                        if time.monotonic() >= deadline:
                            raise ValueError("joined audit export timed out")
                        readable, _, _ = select.select([master, peer], [], [], 0.05)
                        for source in readable:
                            data = os.read(master, 64) if source == master else peer.recv(64)
                            if not data:
                                raise ValueError("kernel audit endpoint ended before CLI export")
                            if source == master:
                                peer.sendall(data)
                            elif os.write(master, data) != len(data):
                                raise ValueError("PTY could not retain a complete reply fragment")
                    if client.wait() != 0:
                        raise ValueError("rk audit-export failed; see retained cli.stderr")
                    peer.shutdown(socket.SHUT_WR)
                if worker.wait(timeout=3) != 0:
                    raise ValueError("kernel audit workflow failed; see retained kernel.stdout")
                if time.monotonic() >= deadline:
                    raise ValueError("joined audit export completed after its deadline")
        finally:
            for process in (client, worker):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()
            os.close(master)
            os.close(slave)
    decode_command = [str(cli), "audit-decode", str(directory / "audit.jsonl"),
                      "--output", str(directory / "decoded.json")]
    decoded = run_logged(decode_command, directory / "decode.stdout", directory / "decode.stderr")
    decoded.check_returncode()
    result = validate_audit(directory)
    # A real CLI decode must refuse an interrupted export, not just unit fixtures.
    truncated = directory / "truncated.jsonl"
    truncated.write_bytes(b"".join((directory / "audit.jsonl").read_bytes().splitlines(keepends=True)[:-1]))
    rejected_output = directory / "truncated-decoded.json"
    negative_command = [str(cli), "audit-decode", str(truncated), "--output", str(rejected_output)]
    rejected = run_logged(negative_command, directory / "negative.stdout", directory / "negative.stderr")
    if rejected.returncode == 0 or rejected_output.exists():
        raise ValueError("CLI decoder accepted an interrupted export")
    result.update(kernel_command=worker_command, cli_command=client_command,
                  decode_command=decode_command, negative_command=negative_command,
                  truncated_export_rejected=True)
    return result


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
        cli_manifest = ROOT / "userspace/tools/rk_cli/Cargo.toml"
        cli_command = ["cargo", "build", "--locked", "--manifest-path", str(cli_manifest),
                       "--bin", "rk", "--message-format=json"]
        cli_build = run_logged(cli_command, output / "cli-build.jsonl", output / "cli-build.stderr", env=env, timeout=600)
        cli_build.check_returncode()
        cli = output / "rk"
        shutil.copy2(executable_from_cargo(cli_build.stdout, "rk", "bin", False), cli)
        manifest["cli"] = {"build_command": cli_command, "sha256": v05.file_sha256(cli),
                           "cargo_lock_sha256": v05.file_sha256(cli_manifest.with_name("Cargo.lock"))}
        manifest["workflow"] = export_workflow(output, retained, cli, env)
        if (clean_source() != source or v05.file_sha256(v05.DEFAULT_ACCEPTANCE) != config
                or v05.file_sha256(retained) != manifest["test_executable_sha256"]
                or v05.file_sha256(cli) != manifest["cli"]["sha256"]):
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
