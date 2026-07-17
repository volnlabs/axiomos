#!/usr/bin/env python3
"""Validate and optionally execute the repository quality campaigns."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = ROOT / "ci/components.toml"
QUALITY = ROOT / "ci/quality.toml"
GENERATED = ROOT / "docs/generated/quality.md"
ALLOWED_DISPOSITIONS = {
    "measured",
    "deferred-host",
    "target-qemu",
    "target-image",
    "fuzz-harness",
    "hardware-hil",
    "experimental-target",
    "formal-proof",
}


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def validate_mutation_evidence(row: dict, quality: dict) -> None:
    evidence_relative = row.get("evidence")
    if evidence_relative is None:
        return

    evidence = (ROOT / evidence_relative).resolve()
    if not evidence.is_relative_to(ROOT) or not evidence.is_file():
        raise ValueError(f"{row['name']}: mutation evidence is missing or escapes the repository")
    if sha256(evidence.read_bytes()) != row["evidence_sha256"]:
        raise ValueError(f"{row['name']}: mutation evidence hash mismatch")

    report = json.loads(evidence.read_text(encoding="utf-8"))
    if report.get("format_version") != 1 or report.get("campaign") != row["name"]:
        raise ValueError(f"{row['name']}: mutation evidence identity mismatch")
    commit = report.get("baseline_commit", "")
    if len(commit) != 40 or not commit.startswith(row["baseline_commit"]):
        raise ValueError(f"{row['name']}: mutation evidence commit mismatch")
    if report.get("cargo_mutants_version") != quality["cargo_mutants_version"]:
        raise ValueError(f"{row['name']}: mutation evidence tool version mismatch")

    command = report.get("command", [])
    if command[:4] != ["cargo", "mutants", "-p", row["package"]]:
        raise ValueError(f"{row['name']}: mutation evidence command/package mismatch")
    command_files = [command[index + 1] for index, arg in enumerate(command[:-1]) if arg == "-f"]
    if command_files != row["files"]:
        raise ValueError(f"{row['name']}: mutation evidence file scope mismatch")
    if ("--no-default-features" in command) != bool(row["no_default_features"]):
        raise ValueError(f"{row['name']}: mutation evidence default-feature mismatch")
    report_features = []
    if "--features" in command:
        report_features = command[command.index("--features") + 1].split(",")
    if report_features != row["features"]:
        raise ValueError(f"{row['name']}: mutation evidence feature mismatch")

    outcomes = report.get("outcomes", [])
    names = [outcome.get("mutant") for outcome in outcomes]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ValueError(f"{row['name']}: mutation evidence outcomes are not unique and sorted")
    counts = Counter(outcome.get("summary") for outcome in outcomes)
    expected_counts = {
        "CaughtMutant": int(row["baseline_caught"]),
        "MissedMutant": int(row["baseline_missed"]),
        "Timeout": int(row.get("baseline_timeout", 0)),
        "Unviable": int(row["baseline_unviable"]),
    }
    if counts != expected_counts or report.get("total_mutants") != len(outcomes):
        raise ValueError(f"{row['name']}: mutation evidence outcome totals mismatch")
    report_counts = report.get("counts", {})
    if report_counts != {
        "caught": expected_counts["CaughtMutant"],
        "missed": expected_counts["MissedMutant"],
        "timeout": expected_counts["Timeout"],
        "unviable": expected_counts["Unviable"],
    }:
        raise ValueError(f"{row['name']}: mutation evidence summary mismatch")
    score = mutation_score(
        expected_counts["CaughtMutant"],
        expected_counts["MissedMutant"],
        expected_counts["Timeout"],
    )
    if abs(float(report.get("score", -1.0)) - score) > 1e-9:
        raise ValueError(f"{row['name']}: mutation evidence score mismatch")

    inputs = report.get("inputs", {})
    source_inputs = {
        path.relative_to(ROOT).as_posix()
        for pattern in row["files"]
        for path in ROOT.glob(pattern)
    }
    required_inputs = source_inputs | {"Cargo.lock", "rust-toolchain.toml"}
    if set(inputs) != required_inputs:
        raise ValueError(f"{row['name']}: mutation evidence input set mismatch")
    for relative, expected_hash in inputs.items():
        if sha256(git_blob(commit, relative)) != expected_hash:
            raise ValueError(f"{row['name']}: historical input hash mismatch for {relative}")


def validate(components: dict, quality: dict) -> None:
    if quality.get("format_version") != 1:
        raise ValueError("ci/quality.toml must declare format_version = 1")

    component_paths = {row["path"] for row in components["component"]}
    dispositions = quality.get("disposition", {})
    disposition_paths = set(dispositions)
    if component_paths != disposition_paths:
        missing = sorted(component_paths - disposition_paths)
        stale = sorted(disposition_paths - component_paths)
        raise ValueError(
            f"quality denominator mismatch: missing={missing}, stale={stale}"
        )
    invalid = sorted(
        (path, value)
        for path, value in dispositions.items()
        if value not in ALLOWED_DISPOSITIONS
    )
    if invalid:
        raise ValueError(f"invalid quality dispositions: {invalid}")

    coverage = quality.get("coverage", [])
    coverage_components = [row["component"] for row in coverage]
    if len(coverage_components) != len(set(coverage_components)):
        raise ValueError("coverage campaigns contain duplicate components")
    measured = {path for path, value in dispositions.items() if value == "measured"}
    if measured != set(coverage_components):
        raise ValueError(
            "measured dispositions must exactly match coverage campaigns: "
            f"measured={sorted(measured)}, campaigns={sorted(coverage_components)}"
        )
    for row in coverage:
        if row["mode"] not in {"workspace", "standalone"}:
            raise ValueError(f"{row['name']}: unsupported coverage mode")
        for field in ("minimum_lines", "minimum_branches"):
            if not 0.0 <= float(row[field]) <= 100.0:
                raise ValueError(f"{row['name']}: {field} must be 0..100")
        if float(row["baseline_lines"]) < float(row["minimum_lines"]):
            raise ValueError(f"{row['name']}: line baseline is below minimum")
        if float(row["baseline_branches"]) < float(row["minimum_branches"]):
            raise ValueError(f"{row['name']}: branch baseline is below minimum")

    mutations = quality.get("mutation", [])
    if not mutations:
        raise ValueError("at least one mutation campaign is required")
    names = [row["name"] for row in mutations]
    if len(names) != len(set(names)):
        raise ValueError("mutation campaigns contain duplicate names")
    for row in mutations:
        caught = int(row["baseline_caught"])
        missed = int(row["baseline_missed"])
        timeout = int(row.get("baseline_timeout", 0))
        score = mutation_score(caught, missed, timeout)
        if score < float(row["minimum_score"]):
            raise ValueError(f"{row['name']}: mutation baseline is below minimum")
        validate_mutation_evidence(row, quality)


def mutation_score(caught: int, missed: int, timeout: int) -> float:
    denominator = caught + missed + timeout
    return 100.0 if denominator == 0 else 100.0 * caught / denominator


def render(components: dict, quality: dict) -> str:
    roles = {row["path"]: row["role"] for row in components["component"]}
    lines = [
        "<!-- Generated by `scripts/check-quality.py --write-docs`; do not edit. -->",
        "",
        "# Coverage and mutation quality boundary",
        "",
        "Coverage uses `cargo-llvm-cov --branch`; mutation scores are caught / (caught + missed + timeout), excluding mutants that do not compile. Percentages are evidence, not a quality score. Target-only, fuzz, formal, and hardware components retain explicit dispositions rather than fabricated host coverage.",
        "",
        "## Component denominator",
        "",
        "| Component | Role | Disposition |",
        "|---|---|---|",
    ]
    for path, disposition in sorted(quality["disposition"].items()):
        lines.append(f"| `{path}` | {roles[path]} | {disposition} |")

    lines.extend(
        [
            "",
            "## Coverage baselines",
            "",
            "| Campaign | Component | Lines | Branches | Minimum lines | Minimum branches | Commit |",
            "|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for row in quality["coverage"]:
        lines.append(
            f"| {row['name']} | `{row['component']}` | {row['baseline_lines']:.2f}% | "
            f"{row['baseline_branches']:.2f}% | {row['minimum_lines']:.2f}% | "
            f"{row['minimum_branches']:.2f}% | `{row['baseline_commit']}` |"
        )

    lines.extend(
        [
            "",
            "## Mutation baselines",
            "",
            "| Campaign | Caught | Missed | Timeout | Unviable | Score | Minimum | Commit | Evidence |",
            "|---|---:|---:|---:|---:|---:|---:|---|---|",
        ]
    )
    for row in quality["mutation"]:
        timeout = row.get("baseline_timeout", 0)
        score = mutation_score(row["baseline_caught"], row["baseline_missed"], timeout)
        evidence = f"[`report`](../{row['evidence'].removeprefix('docs/')})" if row.get("evidence") else "-"
        lines.append(
            f"| {row['name']} | {row['baseline_caught']} | {row['baseline_missed']} | "
            f"{timeout} | {row['baseline_unviable']} | {score:.2f}% | "
            f"{row['minimum_score']:.2f}% | `{row['baseline_commit']}` | {evidence} |"
        )
    lines.append("")
    return "\n".join(lines)


def command_version(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments, cwd=ROOT, check=True, text=True, capture_output=True
    )
    return result.stdout.strip() or result.stderr.strip()


def require_tool_versions(quality: dict, coverage: bool, mutation: bool) -> None:
    if coverage:
        actual = command_version(["cargo", "llvm-cov", "--version"])
        expected = quality["cargo_llvm_cov_version"]
        if expected not in actual:
            raise RuntimeError(f"cargo-llvm-cov {expected} required, got {actual}")
    if mutation:
        actual = command_version(["cargo", "mutants", "--version"])
        expected = quality["cargo_mutants_version"]
        if expected not in actual:
            raise RuntimeError(f"cargo-mutants {expected} required, got {actual}")


def run_coverage(quality: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    summaries = []
    for row in quality["coverage"]:
        report = output / f"{row['name']}.json"
        command = ["cargo", "llvm-cov", "--locked"]
        if row["mode"] == "workspace":
            command += ["-p", row["package"]]
        else:
            command += ["--manifest-path", row["component"]]
        if row["no_default_features"]:
            command.append("--no-default-features")
        if row["features"]:
            command += ["--features", ",".join(row["features"])]
        command += [
            "--branch",
            "--json",
            "--summary-only",
            "--output-path",
            str(report),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        totals = json.loads(report.read_text(encoding="utf-8"))["data"][0]["totals"]
        lines = float(totals["lines"]["percent"])
        branches = float(totals["branches"]["percent"])
        summaries.append({"name": row["name"], "lines": lines, "branches": branches})
        if lines < float(row["minimum_lines"]):
            raise RuntimeError(f"{row['name']}: line coverage {lines:.2f}% below minimum")
        if branches < float(row["minimum_branches"]):
            raise RuntimeError(
                f"{row['name']}: branch coverage {branches:.2f}% below minimum"
            )
    (output / "summary.json").write_text(
        json.dumps(summaries, indent=2) + "\n", encoding="utf-8"
    )


def run_mutations(quality: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    summaries = []
    for row in quality["mutation"]:
        campaign = output / row["name"]
        command = [
            "cargo",
            "mutants",
            "-p",
            row["package"],
            "--gitignore",
            "true",
            "--jobs",
            "4",
            "--timeout",
            "60",
            "--no-times",
            "--output",
            str(campaign),
        ]
        for file_name in row["files"]:
            command += ["-f", file_name]
        if row["no_default_features"]:
            command.append("--no-default-features")
        if row["features"]:
            command += ["--features", ",".join(row["features"])]
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode not in {0, 2, 3}:
            raise RuntimeError(f"{row['name']}: cargo-mutants exited {result.returncode}")
        outcomes_path = campaign / "mutants.out/outcomes.json"
        outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))["outcomes"]
        counts = {"CaughtMutant": 0, "MissedMutant": 0, "Unviable": 0, "Timeout": 0}
        for outcome in outcomes:
            summary = outcome["summary"]
            if summary in counts:
                counts[summary] += 1
        score = mutation_score(
            counts["CaughtMutant"], counts["MissedMutant"], counts["Timeout"]
        )
        summaries.append({"name": row["name"], **counts, "score": score})
        if score < float(row["minimum_score"]):
            raise RuntimeError(f"{row['name']}: mutation score {score:.2f}% below minimum")
    (output / "summary.json").write_text(
        json.dumps(summaries, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write-docs", action="store_true")
    parser.add_argument("--run-coverage", metavar="OUTPUT", type=Path)
    parser.add_argument("--run-mutation", metavar="OUTPUT", type=Path)
    args = parser.parse_args()
    if not any((args.check, args.write_docs, args.run_coverage, args.run_mutation)):
        parser.error("select --check, --write-docs, --run-coverage, or --run-mutation")

    components = load_toml(COMPONENTS)
    quality = load_toml(QUALITY)
    validate(components, quality)
    expected = render(components, quality)
    if args.check:
        actual = GENERATED.read_text(encoding="utf-8")
        if actual != expected:
            raise RuntimeError(
                "docs/generated/quality.md is stale; run scripts/check-quality.py --write-docs"
            )
    if args.write_docs:
        GENERATED.write_text(expected, encoding="utf-8")
    require_tool_versions(quality, args.run_coverage is not None, args.run_mutation is not None)
    if args.run_coverage is not None:
        run_coverage(quality, args.run_coverage)
    if args.run_mutation is not None:
        run_mutations(quality, args.run_mutation)
    print(f"quality boundary: PASS ({len(quality['disposition'])} components)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"quality boundary: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
