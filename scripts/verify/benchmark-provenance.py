#!/usr/bin/env python3
"""Validate tracked benchmark campaigns and their immutable source evidence."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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


def validate_repo_file(relative: str, expected_hash: str, label: str) -> None:
    require(HEX_SHA256.fullmatch(expected_hash), f"{label}: invalid SHA-256")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT), f"{label}: path escapes repository")
    require(path.is_file(), f"{label}: file is missing: {relative}")
    require(sha256(path.read_bytes()) == expected_hash, f"{label}: hash mismatch")


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


def validate_provisional(path: Path, current_doc: str) -> None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    required = (
        "schema_version",
        "status",
        "campaign",
        "date",
        "reason",
        "toolchain",
        "rustc",
        "hardware",
        "reducer_command",
        "image",
        "capture",
    )
    for field in required:
        require(field in data, f"{path.relative_to(ROOT)}: missing {field}")

    require(data["schema_version"] == 1, f"{path}: unsupported provisional schema")
    require(data["status"] == "provisional", f"{path}: status must be provisional")
    require(bool(data["reason"].strip()), f"{path}: provisional reason is empty")

    images = data["image"]
    require(isinstance(images, list) and images, f"{path}: image must be non-empty")
    image_names = [image.get("name") for image in images]
    require(
        len(image_names) == len(set(image_names)),
        f"{path}: image names must be unique",
    )
    for image in images:
        label = f"{path.relative_to(ROOT)}: image {image.get('name')!r}"
        for field in (
            "name",
            "recorded_source_commit",
            "subsequent_commit",
            "recorded_worktree_dirty",
            "deployed_kernel8_sha256",
            "clean_rebuild_kernel8_sha256",
            "clean_rebuild_matches",
            "build_record",
            "build_record_sha256",
        ):
            require(field in image, f"{label}: missing {field}")
        require(
            HEX_COMMIT.fullmatch(image["recorded_source_commit"]),
            f"{label}: invalid recorded source commit",
        )
        require(
            HEX_COMMIT.fullmatch(image["subsequent_commit"]),
            f"{label}: invalid subsequent commit",
        )
        require(
            image["recorded_worktree_dirty"] is True,
            f"{label}: provisional image must retain dirty-worktree status",
        )
        require(
            HEX_SHA256.fullmatch(image["deployed_kernel8_sha256"]),
            f"{label}: invalid deployed image hash",
        )
        require(
            HEX_SHA256.fullmatch(image["clean_rebuild_kernel8_sha256"]),
            f"{label}: invalid clean-rebuild hash",
        )
        require(
            image["clean_rebuild_matches"]
            == (
                image["deployed_kernel8_sha256"]
                == image["clean_rebuild_kernel8_sha256"]
            ),
            f"{label}: clean-rebuild verdict contradicts the hashes",
        )
        validate_repo_file(
            image["build_record"],
            image["build_record_sha256"],
            f"{label}: build record",
        )

    captures = data["capture"]
    require(isinstance(captures, list) and captures, f"{path}: capture must be non-empty")
    capture_names = [capture.get("name") for capture in captures]
    require(
        len(capture_names) == len(set(capture_names)),
        f"{path}: capture names must be unique",
    )
    for capture in captures:
        label = f"{path.relative_to(ROOT)}: capture {capture.get('name')!r}"
        for field in ("name", "path", "sha256"):
            require(field in capture, f"{label}: missing {field}")
        validate_repo_file(capture["path"], capture["sha256"], label)

    doc_root = EVIDENCE_ROOT.parent
    manifest_relative = str(path.relative_to(doc_root))
    readme_relative = str((path.parent / "README.md").relative_to(doc_root))
    require(
        manifest_relative in current_doc,
        f"docs/performance/current-results.md does not link {manifest_relative}",
    )
    require(
        readme_relative in current_doc,
        f"docs/performance/current-results.md does not link {readme_relative}",
    )


def main() -> int:
    try:
        manifests = sorted(EVIDENCE_ROOT.glob("*/manifest.toml"))
        provisional = sorted(EVIDENCE_ROOT.glob("*/provisional.toml"))
        require(manifests, "no benchmark evidence manifests found")
        current_doc = (ROOT / "docs/performance/current-results.md").read_text(encoding="utf-8")
        require(
            "historical benchmark record" in current_doc,
            "current benchmark authority must link the legacy record",
        )
        for manifest in manifests:
            validate_manifest(manifest, current_doc)
        for evidence in provisional:
            validate_provisional(evidence, current_doc)
    except (AssertionError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"benchmark provenance check: FAIL: {error}", file=sys.stderr)
        return 1

    print(
        "benchmark provenance check: PASS "
        f"({len(manifests)} attributable campaign(s), "
        f"{len(provisional)} provisional evidence set(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
