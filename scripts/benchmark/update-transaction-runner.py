#!/usr/bin/env python3
"""Retain a real Rust publication campaign and its source/environment evidence."""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
import json
import os
import platform
import shlex
import signal
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKERS = {"UPDATE_TXN": "trace.jsonl", "UPDATE_COST": "cost-trace.jsonl"}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def read_host_file(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def source_manifest(destination: Path):
    revision = git("rev-parse", "HEAD").decode().strip()
    tracked = git("ls-files", "-z").decode().split("\0")
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    hashes = {}
    for name in sorted(set(tracked + untracked) - {""}):
        path = ROOT / name
        if path.is_file() and not path.is_symlink() and destination not in path.parents:
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps({"revision": revision, "sources": hashes},
                                      sort_keys=True).encode()).hexdigest()
    return revision, hashes, untracked, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--marker", action="append", choices=MARKERS)
    parser.add_argument("--measured-executable", action="append", type=Path, default=[])
    parser.add_argument("--expected-source-digest")
    parser.add_argument("--timeout-seconds", type=float, default=600)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("supply an explicit Rust test/campaign command after --")
    if args.timeout_seconds <= 0:
        parser.error("timeout must be positive")
    destination = args.output.resolve()
    revision, source_hashes, untracked, digest = source_manifest(destination)
    if args.expected_source_digest and args.expected_source_digest != digest:
        parser.error("source changed between build and evidence capture")
    markers = args.marker or ["UPDATE_TXN"]
    executable_hashes = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in args.measured_executable}
    destination.mkdir(parents=True, exist_ok=False)
    patch = git("diff", "--binary", "HEAD")
    (destination / "source.patch").write_bytes(patch)
    for name in source_hashes:
        if name in untracked:
            retained = destination / "untracked-source" / name
            retained.parent.mkdir(parents=True, exist_ok=True)
            retained.write_bytes((ROOT / name).read_bytes())
    manifest = {
        "schema": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "revision": revision,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "command": command,
        "cwd": str(ROOT),
        "platform": platform.uname()._asdict(),
        "python": sys.version,
        "source_sha256": source_hashes,
        "source_digest": digest,
        "build_source_digest": args.expected_source_digest,
        "executable_sha256": executable_hashes,
        "claim_boundary": "hosted manager and guard observations; no physical or privileged bytecode execution",
    }
    allowed = sorted(os.sched_getaffinity(0))
    manifest["host"] = {
        "allowed_cpus": allowed,
        "cpuinfo": read_host_file("/proc/cpuinfo"),
        "loadavg_start": read_host_file("/proc/loadavg"),
        "boost": read_host_file("/sys/devices/system/cpu/cpufreq/boost"),
        "cpu_topology": {str(cpu): {field: read_host_file(f"/sys/devices/system/cpu/cpu{cpu}/{path}")
            for field, path in (("core", "topology/core_id"),
                                ("package", "topology/physical_package_id"),
                                ("siblings", "topology/thread_siblings_list"),
                                ("governor", "cpufreq/scaling_governor"))}
            for cpu in allowed},
    }
    for tool, flags in (("rustc", ["-Vv"]), ("cargo", ["-V"])):
        result = subprocess.run([tool, *flags], cwd=ROOT, text=True, capture_output=True)
        manifest[tool] = {"exit_code": result.returncode, "output": result.stdout + result.stderr}
    (destination / "commands.txt").write_text(shlex.join(command) + "\n")
    with (destination / "test-output.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        timed_out = False

        def expire():
            nonlocal timed_out
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(args.timeout_seconds, expire)
        timer.start()
        assert process.stdout is not None
        try:
            for line in process.stdout:
                log.write(line)
                log.flush()
                print(line, end="", flush=True)
            code = process.wait()
        finally:
            timer.cancel()
    manifest["timed_out"] = timed_out
    if timed_out:
        code = 124
    manifest["exit_code"] = code
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["host"]["loadavg_end"] = read_host_file("/proc/loadavg")
    manifest["changed_sources_during_run"] = [name for name, digest in source_hashes.items()
        if not (ROOT / name).is_file() or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
    _, final_sources, _, final_digest = source_manifest(destination)
    manifest["changed_sources_during_run"] += sorted(set(final_sources) - set(source_hashes))
    manifest["finished_source_digest"] = final_digest
    records = {marker: [] for marker in markers}
    malformed = []
    for number, line in enumerate((destination / "test-output.log").read_text().splitlines(), 1):
        for marker in markers:
            prefix, found, payload = line.partition(marker + " ")
            # libtest may print the first marker after its unfinished test-name line.
            if found and (not prefix or (prefix.startswith("test ") and prefix.endswith(" ... "))):
                try:
                    records[marker].append(json.loads(payload))
                except json.JSONDecodeError as error:
                    malformed.append({"line": number, "marker": marker, "error": str(error)})
    manifest["malformed_records"] = malformed
    for marker, values in records.items():
        (destination / MARKERS[marker]).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in values))
    manifest["trace_records"] = {marker: len(values) for marker, values in records.items()}
    manifest["changed_executables_during_run"] = [name for name, digest in executable_hashes.items()
        if not Path(name).is_file() or hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest]
    (destination / "environment.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    checksums = []
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(destination)}\n")
    (destination / "SHA256SUMS").write_text("".join(checksums))
    if code:
        return code
    if malformed:
        print("FAIL: malformed marker records; original output retained", file=sys.stderr)
        return 1
    if (manifest["changed_sources_during_run"] or manifest["changed_executables_during_run"]
            or final_digest != manifest["source_digest"]):
        print("FAIL: source or measured executable changed while collecting evidence", file=sys.stderr)
        return 1
    if any(not values for values in records.values()):
        print("FAIL: command passed but a requested marker emitted no evidence", file=sys.stderr)
        return 1
    print(f"Retained {manifest['trace_records']} records in {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
