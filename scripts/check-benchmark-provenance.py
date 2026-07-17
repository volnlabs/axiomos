#!/usr/bin/env python3
"""Validate tracked benchmark campaigns and their immutable source evidence."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "docs/performance/evidence"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(
        result.returncode == 0,
        f"cannot read {relative} from benchmark commit {commit}: "
        f"{result.stderr.decode('utf-8', errors='replace').strip()}",
    )
    return result.stdout


def validate_manifest(path: Path, current_doc: str) -> None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    required = (
        "schema_version",
        "campaign",
        "commit",
        "date",
        "command",
        "raw_log",
        "raw_log_sha256",
        "artifact_path",
        "artifact_sha256",
        "toolchain",
        "rustc",
        "host",
        "cpu",
        "required_markers",
        "inputs",
    )
    for field in required:
        require(field in data, f"{path.relative_to(ROOT)}: missing {field}")

    require(data["schema_version"] == 1, f"{path}: unsupported schema version")
    commit = data["commit"]
    require(isinstance(commit, str) and HEX_COMMIT.fullmatch(commit), f"{path}: invalid commit")
    require(commit.startswith(path.parent.name), f"{path}: directory does not identify commit")
    require(HEX_SHA256.fullmatch(data["raw_log_sha256"]), f"{path}: invalid raw-log hash")
    require(HEX_SHA256.fullmatch(data["artifact_sha256"]), f"{path}: invalid artifact hash")

    raw_relative = Path(data["raw_log"])
    raw_path = (ROOT / raw_relative).resolve()
    require(raw_path.is_relative_to(ROOT), f"{path}: raw log escapes repository")
    require(raw_path.is_file(), f"{path}: raw log is missing: {raw_relative}")
    raw = raw_path.read_bytes()
    require(sha256(raw) == data["raw_log_sha256"], f"{path}: raw-log hash mismatch")
    raw_text = raw.decode("utf-8")
    require(data["artifact_path"] in raw_text, f"{path}: Cargo artifact path absent from raw log")
    require("Finished `bench` profile" in raw_text, f"{path}: raw log lacks completed bench build")

    markers = data["required_markers"]
    require(isinstance(markers, list) and markers, f"{path}: required_markers must be non-empty")
    for marker in markers:
        require(marker in raw_text, f"{path}: raw log lacks result marker {marker!r}")

    inputs = data["inputs"]
    require(isinstance(inputs, dict) and inputs, f"{path}: inputs must be non-empty")
    for relative, expected in inputs.items():
        require(HEX_SHA256.fullmatch(expected), f"{path}: invalid input hash for {relative}")
        require(
            sha256(git_blob(commit, relative)) == expected,
            f"{path}: {relative} does not match recorded commit hash",
        )

    manifest_relative = str(path.relative_to(EVIDENCE_ROOT.parent))
    raw_doc_relative = str((ROOT / raw_relative).relative_to(EVIDENCE_ROOT.parent))
    require(manifest_relative in current_doc, f"docs/performance/current-results.md does not link {manifest_relative}")
    require(raw_doc_relative in current_doc, f"docs/performance/current-results.md does not link {raw_doc_relative}")


def main() -> int:
    try:
        manifests = sorted(EVIDENCE_ROOT.glob("*/manifest.toml"))
        require(manifests, "no benchmark evidence manifests found")
        current_doc = (ROOT / "docs/performance/current-results.md").read_text(encoding="utf-8")
        require(
            "historical benchmark record" in current_doc,
            "current benchmark authority must link the legacy record",
        )
        for manifest in manifests:
            validate_manifest(manifest, current_doc)
    except (AssertionError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"benchmark provenance check: FAIL: {error}", file=sys.stderr)
        return 1

    print(f"benchmark provenance check: PASS ({len(manifests)} campaign manifest(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
