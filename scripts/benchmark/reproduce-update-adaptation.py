#!/usr/bin/env python3
"""Build, retain, and analyze the deterministic adaptation replay."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
FEATURES = "kernel_bpf/embedded-profile,bpf-unsigned-development,bpf-update-diagnostics"
TARGET_DIR = "/home/utkarsh/Work/axiomOS/target"


def run(command, **kwargs):
    print("+ " + " ".join(map(str, command)), flush=True)
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = TARGET_DIR
    return subprocess.run(list(map(str, command)), cwd=ROOT, check=True, timeout=900,
                          env=environment, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new evidence directory; existing evidence is never overwritten")
    args = parser.parse_args()
    destination = args.output.resolve()
    if destination.exists():
        parser.error("output already exists; choose a new directory")

    spec = importlib.util.spec_from_file_location(
        "publication_runner", ROOT / "scripts/benchmark/update-transaction-runner.py")
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    source_digest = collector.source_manifest(destination)[3]
    command = [
        "cargo", "test", "--locked", "--release", "-p", "kernel",
        "--test", "bpf_update_adaptation", "--features", FEATURES,
        "--no-run", "--message-format=json",
    ]
    build = run(command, text=True, stdout=subprocess.PIPE)
    if collector.source_manifest(destination)[3] != source_digest:
        raise RuntimeError("source changed during compilation; no evidence collected")
    executable = None
    for line in build.stdout.splitlines():
        record = json.loads(line)
        if (record.get("reason") == "compiler-artifact"
                and record.get("target", {}).get("name") == "bpf_update_adaptation"
                and record.get("executable")):
            executable = record["executable"]
    if executable is None:
        raise RuntimeError("missing adaptation test executable")

    run([
        sys.executable, ROOT / "scripts/benchmark/update-transaction-runner.py",
        "--output", destination, "--marker", "UPDATE_ADAPT",
        "--measured-executable", executable,
        "--expected-source-digest", source_digest, "--timeout-seconds", "120",
        "--", executable, "--nocapture", "--test-threads=1",
    ])
    (destination / "build-command.json").write_text(json.dumps(command) + "\n")
    (destination / "build-artifacts.jsonl").write_text(build.stdout)
    run([
        sys.executable, ROOT / "scripts/benchmark/analyze-update-adaptation.py",
        destination / "adaptation-trace.jsonl", "--write-artifacts",
    ])
    print(f"Retained deterministic adaptation evidence in {destination}")


if __name__ == "__main__":
    main()
