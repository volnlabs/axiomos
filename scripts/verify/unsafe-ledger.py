#!/usr/bin/env python3
"""Inventory and classify first-party Rust `unsafe` syntax.

The obligation catalog is intentionally maintained separately from source line
numbers. Each current source site inherits the metadata of the first matching
path rule, so line movement does not make the ledger stale.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import fnmatch
import hashlib
import re
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "docs/security/unsafe-code/ledger.toml"
LEDGER_PATH = ROOT / "docs/security/unsafe-code/ledger.md"
UNSAFE_TOKEN = re.compile(r"\bunsafe\b")
RAW_STRING_START = re.compile(r"(?:br|cr|r)(#{0,255})\"")


@dataclass(frozen=True)
class Obligation:
    id: str
    paths: tuple[str, ...]
    scope: str
    owner: str
    invariant: str
    callers: str
    tests: str
    priority: str
    reviewed: str


@dataclass(frozen=True)
class Site:
    path: str
    line: int
    column: int
    kind: str
    obligation: Obligation | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="verify coverage, baseline, and generated Markdown")
    action.add_argument("--write", action="store_true", help="regenerate the Markdown ledger")
    action.add_argument("--list", action="store_true", help="print the complete site-level ledger as TSV")
    return parser.parse_args()


def load_catalog() -> tuple[int, str, tuple[Obligation, ...]]:
    with CATALOG_PATH.open("rb") as catalog_file:
        catalog = tomllib.load(catalog_file)

    obligations = tuple(
        Obligation(
            id=item["id"],
            paths=tuple(item["paths"]),
            scope=item["scope"],
            owner=item["owner"],
            invariant=item["invariant"],
            callers=item["callers"],
            tests=item["tests"],
            priority=item["priority"],
            reviewed=item["reviewed"],
        )
        for item in catalog["obligation"]
    )
    ids = [item.id for item in obligations]
    if len(ids) != len(set(ids)):
        raise ValueError("unsafe obligation IDs must be unique")
    return catalog["baseline_sites"], catalog["baseline_fingerprint"], obligations


def rust_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard", "--", "*.rs"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths: list[Path] = []
    for relative in result.stdout.splitlines():
        path = Path(relative)
        if not (ROOT / path).is_file():
            continue
        parts = path.parts
        if "target" in parts or "generated" in parts:
            continue
        if "fuzz" in parts and ("corpus" in parts or "artifacts" in parts):
            continue
        paths.append(path)
    return sorted(set(paths))


def mask_comments_and_strings(source: str) -> str:
    """Replace comments and string contents with spaces, preserving offsets."""

    masked = list(source)
    length = len(source)
    index = 0
    block_depth = 0

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if masked[offset] != "\n":
                masked[offset] = " "

    while index < length:
        if block_depth:
            if source.startswith("/*", index):
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index, index + 2)
                block_depth -= 1
                index += 2
            else:
                blank(index, index + 1)
                index += 1
            continue

        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue

        if source.startswith("/*", index):
            blank(index, index + 2)
            block_depth = 1
            index += 2
            continue

        raw_match = RAW_STRING_START.match(source, index)
        if raw_match and (index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")):
            hashes = raw_match.group(1)
            terminator = '"' + hashes
            end = source.find(terminator, raw_match.end())
            end = length if end == -1 else end + len(terminator)
            blank(index, end)
            index = end
            continue

        if source[index] == '"':
            end = index + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                    continue
                end += 1
                if source[end - 1] == '"':
                    break
            blank(index, min(end, length))
            index = min(end, length)
            continue

        index += 1

    return "".join(masked)


def self_test_scanner() -> None:
    sample = '''
// unsafe { ignored(); }
/* unsafe fn ignored() { /* unsafe impl ignored */ } */
let normal = "unsafe { ignored(); }";
let raw = r#"unsafe fn ignored()"#;
let raw_bytes = br##"unsafe extern ignored"##;
#[unsafe(no_mangle)]
unsafe fn counted() { unsafe { counted_body(); } }
'''
    masked = mask_comments_and_strings(sample)
    matches = list(UNSAFE_TOKEN.finditer(masked))
    kinds = [site_kind(masked, match.start(), match.end()) for match in matches]
    if kinds != ["attribute", "function", "block"]:
        raise AssertionError(f"unsafe scanner self-test failed: {kinds}")


def site_kind(masked: str, start: int, end: int) -> str:
    line_start = masked.rfind("\n", 0, start) + 1
    prefix = masked[line_start:start]
    tail = masked[end : end + 80]
    if re.search(r"#\[\s*$", prefix):
        return "attribute"
    if re.match(r"\s+impl\b", tail):
        return "impl"
    if re.match(r"\s+trait\b", tail):
        return "trait"
    if re.match(r"\s+extern\b", tail):
        return "extern"
    if re.match(r"\s+fn\b", tail):
        return "function"
    if re.match(r"\s*\{", tail):
        return "block"
    return "type-or-macro"


def classify(path: str, obligations: tuple[Obligation, ...]) -> Obligation | None:
    for obligation in obligations:
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in obligation.paths):
            return obligation
    return None


def collect_sites(obligations: tuple[Obligation, ...]) -> list[Site]:
    sites: list[Site] = []
    for relative_path in rust_paths():
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        masked = mask_comments_and_strings(source)
        line_starts = [0]
        line_starts.extend(match.end() for match in re.finditer("\n", source))
        obligation = classify(relative_path.as_posix(), obligations)
        for match in UNSAFE_TOKEN.finditer(masked):
            line_index = bisect.bisect_right(line_starts, match.start()) - 1
            sites.append(
                Site(
                    path=relative_path.as_posix(),
                    line=line_index + 1,
                    column=match.start() - line_starts[line_index] + 1,
                    kind=site_kind(masked, match.start(), match.end()),
                    obligation=obligation,
                )
            )
    return sites


def site_fingerprint(sites: list[Site]) -> str:
    inventory = "\n".join(
        f"{site.path}:{site.line}:{site.column}:{site.kind}:{site.obligation.id if site.obligation else 'UNCLASSIFIED'}"
        for site in sites
    )
    return "sha256:" + hashlib.sha256(inventory.encode("utf-8")).hexdigest()


def markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(sites: list[Site], obligations: tuple[Obligation, ...]) -> str:
    counts = Counter(site.obligation.id for site in sites if site.obligation)
    kinds = Counter(site.kind for site in sites)
    file_count = len({site.path for site in sites})
    rows = []
    for obligation in obligations:
        count = counts[obligation.id]
        if count == 0:
            continue
        rows.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in (
                    obligation.id,
                    str(count),
                    obligation.scope,
                    obligation.owner,
                    obligation.priority,
                    obligation.invariant,
                    obligation.callers,
                    obligation.tests,
                    obligation.reviewed,
                )
            )
            + " |"
        )

    kind_summary = ", ".join(f"{kind} {count}" for kind, count in sorted(kinds.items()))
    fingerprint = site_fingerprint(sites)
    return f"""<!-- Generated by scripts/verify/unsafe-ledger.py; edit ledger.toml instead. -->
# Unsafe-code ledger

This ledger turns every first-party Rust `unsafe` syntax site into an owned review obligation. It covers tracked and untracked Rust source, including tests and fuzz targets, while excluding build output, generated source, fuzz corpora, and fuzz artifacts. Counts are syntactic source sites, not expanded macro instances or a proof of soundness.

Run `cargo xtask check unsafe` before review. Run `python3 scripts/verify/unsafe-ledger.py --list` for the site-level TSV containing location, construct, owner, invariant, callers, tests, priority, and review date. Update [ledger.toml](ledger.toml) when an invariant, owner, or baseline changes, then run `python3 scripts/verify/unsafe-ledger.py --write`.

Current snapshot: **{len(sites)} sites in {file_count} files** ({kind_summary}). Inventory fingerprint: `{fingerprint}`. All sites are classified by the obligations below.

| Obligation | Sites | Scope | Owner | Priority | Required invariant | Principal callers | Executable evidence | Reviewed |
|---|---:|---|---|---|---|---|---|---|
{chr(10).join(rows)}

## Review policy

- `P0` obligations gate release until their premises are enforced in code and exercised through a fault or concurrency path. `P1` requires targeted tests before the owning subsystem is considered complete. `P2` is platform or ABI glue with documented external premises. `P3` is test/tooling-only syntax.
- The path rule is the durable owner of an obligation; `--list` resolves it onto every current source location. A new path containing `unsafe` fails `--check` until explicitly classified.
- Count drift fails `--check`. Reducing the count still requires catalog review because removing one site can move the same obligation into a larger unsafe helper.
- “Boot smoke” is integration evidence, not a substitute for provenance, aliasing, lifetime, mapping, interrupt, DMA, or MMIO tests. Rows that explicitly say coverage is missing remain open audit debt.
"""


def write_site_tsv(sites: list[Site]) -> None:
    output = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    output.writerow(
        ("site", "kind", "obligation", "scope", "owner", "priority", "invariant", "callers", "tests", "reviewed")
    )
    for site in sites:
        obligation = site.obligation
        if obligation is None:
            output.writerow((f"{site.path}:{site.line}:{site.column}", site.kind, "UNCLASSIFIED"))
            continue
        output.writerow(
            (
                f"{site.path}:{site.line}:{site.column}",
                site.kind,
                obligation.id,
                obligation.scope,
                obligation.owner,
                obligation.priority,
                obligation.invariant,
                obligation.callers,
                obligation.tests,
                obligation.reviewed,
            )
        )


def validate(
    sites: list[Site], baseline: int, baseline_fingerprint: str, obligations: tuple[Obligation, ...]
) -> list[str]:
    errors = []
    unclassified = [site for site in sites if site.obligation is None]
    if unclassified:
        rendered = ", ".join(f"{site.path}:{site.line}" for site in unclassified[:20])
        suffix = " ..." if len(unclassified) > 20 else ""
        errors.append(f"{len(unclassified)} unsafe sites are unclassified: {rendered}{suffix}")
    if len(sites) != baseline:
        errors.append(f"unsafe site count changed: catalog baseline {baseline}, source {len(sites)}")
    fingerprint = site_fingerprint(sites)
    if fingerprint != baseline_fingerprint:
        errors.append(
            f"unsafe site inventory changed: catalog {baseline_fingerprint}, source {fingerprint}"
        )

    generated = render_markdown(sites, obligations)
    if not LEDGER_PATH.exists() or LEDGER_PATH.read_text(encoding="utf-8") != generated:
        errors.append(
            f"{LEDGER_PATH.relative_to(ROOT)} is stale; "
            "run scripts/verify/unsafe-ledger.py --write"
        )
    return errors


def main() -> int:
    args = parse_args()
    self_test_scanner()
    baseline, baseline_fingerprint, obligations = load_catalog()
    sites = collect_sites(obligations)

    if args.list:
        write_site_tsv(sites)
        return int(any(site.obligation is None for site in sites))

    if args.write:
        LEDGER_PATH.write_text(render_markdown(sites, obligations), encoding="utf-8")
        print(f"wrote {LEDGER_PATH.relative_to(ROOT)} with {len(sites)} sites")
        return 0

    errors = validate(sites, baseline, baseline_fingerprint, obligations)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"unsafe ledger clean: {len(sites)} sites, {len({site.path for site in sites})} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
