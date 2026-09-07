#!/usr/bin/env python3
"""Retain a real Rust publication campaign and its source/environment evidence."""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
import json
import platform
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKER = "UPDATE_TXN "


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("supply an explicit Rust test/campaign command after --")
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    revision = git("rev-parse", "HEAD").decode().strip()
    patch = git("diff", "--binary", "HEAD")
    (destination / "source.patch").write_bytes(patch)
    tracked = git("ls-files", "-z").decode().split("\0")
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    source_hashes = {}
    for name in sorted(set(tracked + untracked) - {""}):
        path = ROOT / name
        if not path.is_file() or path.is_symlink() or destination in path.parents:
            continue
        contents = path.read_bytes()
        source_hashes[name] = hashlib.sha256(contents).hexdigest()
        if name in untracked:
            retained = destination / "untracked-source" / name
            retained.parent.mkdir(parents=True, exist_ok=True)
            retained.write_bytes(contents)
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
        "claim_boundary": "software kernel executor; no physical or learning experiment",
    }
    for tool, flags in (("rustc", ["-Vv"]), ("cargo", ["-V"])):
        result = subprocess.run([tool, *flags], cwd=ROOT, text=True, capture_output=True)
        manifest[tool] = {"exit_code": result.returncode, "output": result.stdout + result.stderr}
    (destination / "commands.txt").write_text(shlex.join(command) + "\n")
    with (destination / "test-output.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            log.flush()
            print(line, end="", flush=True)
        code = process.wait()
    manifest["exit_code"] = code
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["changed_sources_during_run"] = [name for name, digest in source_hashes.items()
        if not (ROOT / name).is_file() or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
    records = []
    for line in (destination / "test-output.log").read_text().splitlines():
        prefix, marker, payload = line.partition(MARKER)
        # libtest may print the first marker after its unfinished test-name line.
        if marker and (not prefix or (prefix.startswith("test ") and prefix.endswith(" ... "))):
            records.append(json.loads(payload))
    (destination / "trace.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    manifest["trace_records"] = len(records)
    (destination / "environment.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    checksums = []
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(destination)}\n")
    (destination / "SHA256SUMS").write_text("".join(checksums))
    if code:
        return code
    if manifest["changed_sources_during_run"]:
        print("FAIL: source changed while collecting evidence", file=sys.stderr)
        return 1
    if not records:
        print("FAIL: command passed but emitted no UPDATE_TXN evidence", file=sys.stderr)
        return 1
    print(f"Retained {len(records)} records in {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
