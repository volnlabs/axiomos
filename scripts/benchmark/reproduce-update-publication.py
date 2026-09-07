#!/usr/bin/env python3
"""Build, retain, analyze and check the hosted publication evidence in one command."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
FEATURES = "kernel_bpf/embedded-profile,bpf-unsigned-development,bpf-update-diagnostics"


def run(command, **kwargs):
    print("+ " + " ".join(map(str, command)), flush=True)
    return subprocess.run(list(map(str, command)), cwd=ROOT, check=True, timeout=900, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new evidence directory; existing evidence is never overwritten")
    parser.add_argument("--dispatch-cpu", type=int, default=12)
    parser.add_argument("--update-cpu", type=int, default=14)
    parser.add_argument("--execute", nargs=2, metavar=("CAMPAIGN", "MEASUREMENTS"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.execute:
        campaign, measurements = args.execute
        run([campaign, "--nocapture", "--test-threads=1"])
        run([measurements, "--test-threads=1"])
        run([sys.executable, ROOT / "scripts/benchmark/update-cost-matrix.py",
             "--executable", measurements, "--dispatch-cpu", args.dispatch_cpu,
             "--update-cpu", args.update_cpu])
        return

    destination = args.output.resolve()
    if destination.exists():
        parser.error("output already exists; choose a new directory")
    adaptation = destination.with_name(destination.name + "-adaptation")
    if adaptation.exists():
        parser.error("paired adaptation output already exists; choose a new directory")
    spec = importlib.util.spec_from_file_location("publication_runner",
        ROOT / "scripts/benchmark/update-transaction-runner.py")
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    build_source_digest = collector.source_manifest(destination)[3]
    names = ("bpf_update_campaign", "bpf_update_measurements")
    command = ["cargo", "test", "--locked", "--release", "-p", "kernel",
               "--features", FEATURES, "--no-run", "--message-format=json"]
    for name in names:
        command += ["--test", name]
    build = run(command, text=True, stdout=subprocess.PIPE)
    if collector.source_manifest(destination)[3] != build_source_digest:
        raise RuntimeError("source changed during compilation; no evidence collected")
    executables = {}
    for line in build.stdout.splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-artifact" and record.get("executable"):
            executables[record["target"]["name"]] = record["executable"]
    assert set(names) <= executables.keys(), "missing measured test executable"
    runner = [sys.executable, ROOT / "scripts/benchmark/update-transaction-runner.py",
              "--output", destination, "--marker", "UPDATE_TXN", "--marker", "UPDATE_COST",
              "--expected-source-digest", build_source_digest, "--timeout-seconds", "600"]
    for name in names:
        runner += ["--measured-executable", executables[name]]
    runner += ["--", sys.executable, Path(__file__).resolve(), "--output", destination,
               "--dispatch-cpu", args.dispatch_cpu, "--update-cpu", args.update_cpu,
               "--execute", *(executables[name] for name in names)]
    run(runner)
    (destination / "build-command.json").write_text(json.dumps(command) + "\n")
    (destination / "build-artifacts.jsonl").write_text(build.stdout)
    run([sys.executable, ROOT / "scripts/benchmark/analyze-update-transaction.py",
         destination / "trace.jsonl", "--write-artifacts"])
    run([sys.executable, ROOT / "scripts/benchmark/analyze-update-cost.py",
         destination / "cost-trace.jsonl"])
    paper = ROOT / "papers/cl4fmagents2026"
    shutil.copyfile(destination / "result-table.tex", paper / "results.tex")
    shutil.copyfile(destination / "cost-table.tex", paper / "costs.tex")
    shutil.copyfile(destination / "cost-note.tex", paper / "cost-note.tex")
    run([sys.executable, ROOT / "scripts/benchmark/reproduce-update-adaptation.py",
         "--output", adaptation])
    shutil.copyfile(adaptation / "adaptation-table.tex", paper / "adaptation.tex")
    run(["make", "-C", paper], env={**os.environ, "UPDATE_PUBLICATION_EVIDENCE": str(destination),
                                        "UPDATE_ADAPTATION_EVIDENCE": str(adaptation)})
    run([sys.executable, paper / "verify.py"],
        env={**os.environ, "UPDATE_PUBLICATION_EVIDENCE": str(destination),
             "UPDATE_ADAPTATION_EVIDENCE": str(adaptation),
             "UPDATE_PUBLICATION_CHECK_BINARIES": "1"})


if __name__ == "__main__":
    main()
