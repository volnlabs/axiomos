#!/usr/bin/env python3
"""Build the deterministic anonymous-review artifact for the publication study."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ARTIFACT = "artifact-r1"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644
DIR_MODE = 0o755

RAW_FILES = {
    "docs/performance/evidence/update-transaction-v2/trace.jsonl":
        "raw/publication/trace.jsonl",
    "docs/performance/evidence/update-transaction-v2/cost-trace.jsonl":
        "raw/publication/cost-trace.jsonl",
    "docs/performance/evidence/update-transaction-v2/cost-runs.csv":
        "raw/publication/cost-runs.csv",
    "docs/performance/evidence/update-adaptation-v1/adaptation-trace.jsonl":
        "raw/adaptation/adaptation-trace.jsonl",
}
SCRIPT_FILES = {
    "scripts/benchmark/analyze-update-transaction.py":
        "scripts/analyze-publication.py",
    "scripts/benchmark/analyze-update-cost.py": "scripts/analyze-cost.py",
    "scripts/benchmark/analyze-update-adaptation.py":
        "scripts/analyze-adaptation.py",
    "papers/cl4fmagents2026/render_tables.py": "scripts/render_tables.py",
}
HOST_TESTS = {
    "kernel/tests/bpf_update_transaction.rs":
        "source/host-tests/publication_transaction.rs",
    "kernel/tests/bpf_update_campaign.rs":
        "source/host-tests/publication_campaign.rs",
    "kernel/tests/bpf_update_measurements.rs":
        "source/host-tests/publication_measurements.rs",
    "kernel/tests/bpf_update_adaptation.rs":
        "source/host-tests/publication_adaptation.rs",
}
PATCH_PATHS = {
    "kernel/crates/kernel_bpf/Cargo.toml": "source/runtime-core/Cargo.toml",
    "kernel/crates/kernel_bpf/src/concurrency/exclusive_slot.rs":
        "source/runtime-core/src/concurrency/exclusive_slot.rs",
    "kernel/crates/kernel_bpf/tests/concurrency_model.rs":
        "source/runtime-core/tests/concurrency_model.rs",
    "kernel/src/bpf/mod.rs": "source/manager/bpf/mod.rs",
    "kernel/tests/bpf_update_campaign.rs":
        "source/host-tests/publication_campaign.rs",
    "kernel/tests/bpf_update_transaction.rs":
        "source/host-tests/publication_transaction.rs",
}

REPLACEMENTS = (
    ("AXIOMOS", "ANONYMOUS_RUNTIME"),
    ("AxiomOS", "Anonymous Runtime"),
    ("axiomos", "anonymous_runtime"),
    ("VOLNLABS", "ANONYMOUS_RESEARCH_GROUP"),
    ("VolnLabs", "Anonymous Research Group"),
    ("volnlabs", "anonymous_research_group"),
    ("AXIOM_", "REVIEW_"),
    ("kernel_bpf", "anonymous_runtime_core"),
    ("kernel_abi", "anonymous_runtime_abi"),
    ("use kernel::", "use anonymous_runtime::"),
    ("`kernel` crate", "`anonymous_runtime` crate"),
)
TRACKER_IDS = re.compile(
    r"#(?:20|43|48|65|67|83|84|85|86|87|88|89|102|104|105|114|116|121|122|123|181)\b"
)
FORBIDDEN = (
    ("project identity", re.compile(r"axiomos|volnlabs", re.I)),
    ("first-party crate identity", re.compile(r"\b(?:kernel_bpf|kernel_abi)\b")),
    ("user path", re.compile(r"/(?:home|Users|tmp)/")),
    ("email", re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")),
    ("repository URL", re.compile(r"https?://|(?:github|gitlab|bitbucket)\.com", re.I)),
    ("VCS metadata", re.compile(r"(?:^|[/ ])\.git(?:[/ ]|$)|\b(?:commit|revision)\s+[0-9a-f]{7,40}\b", re.I | re.M)),
    ("Git object id", re.compile(r"\b[0-9a-f]{40}\b", re.I)),
    ("tracker reference", re.compile(
        r"\b(?:issue|pull request|merge request)\s*#?\d+\b|" + TRACKER_IDS.pattern,
        re.I,
    )),
    ("CI reference", re.compile(r"\bCI\b|continuous integration|\.github/|\bworkflows?\b", re.I)),
    ("author metadata", re.compile(r"\b(?:authors?|maintainers?)\s*[:=]", re.I)),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitized(text: str) -> str:
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    text = re.sub(r"\bissue\s+" + TRACKER_IDS.pattern, "a prior tracked defect", text,
                  flags=re.I)
    text = TRACKER_IDS.sub("a prior tracked change", text)
    text = text.replace("audit-gate", "validation").replace("audit gate", "validation")
    return text


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def copy_text(source: Path, destination: Path, export_root: Path, mapping: list[dict]) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"source must be a regular file: {source}")
    original = source.read_bytes()
    exported = sanitized(original.decode("utf-8")).encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(exported)
    mapping.append({
        "source": str(source),
        "export": str(destination.relative_to(export_root)),
        "source_sha256": sha256(original),
        "export_sha256": sha256(exported),
    })


def copy_tree(source: Path, destination: Path, export_root: Path,
              mapping: list[dict]) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink excluded from source snapshot: {path}")
        if path.is_file():
            copy_text(path, destination / path.relative_to(source), export_root, mapping)


def export_patch(source: Path) -> str:
    sections: dict[str, list[str]] = {}
    current = None
    for line in source.read_text(encoding="utf-8").splitlines(keepends=True):
        if line.startswith("diff --git "):
            parts = line.split()
            original = parts[2][2:] if len(parts) >= 4 and parts[2].startswith("c/") else None
            current = [] if original in PATCH_PATHS else None
            if current is not None:
                sections[original] = current
            continue
        if current is not None:
            current.append(line)

    output = [
        "# Anonymous source delta\n",
        "# Actual publication-runtime delta with export-only identity substitutions.\n",
        "# Version-control object identifiers and repository metadata are intentionally omitted.\n",
    ]
    for original, anonymous in PATCH_PATHS.items():
        lines = sections.get(original)
        if lines is None:
            raise ValueError(f"missing patch section: {original}")
        output.extend((f"--- before/{anonymous}\n", f"+++ after/{anonymous}\n"))
        for line in lines:
            if line.startswith(("index ", "new file mode ", "deleted file mode ",
                                "old mode ", "new mode ", "--- ", "+++ ")):
                continue
            output.append(line)
    return sanitized("".join(output))


REPRODUCE = '''#!/usr/bin/env python3
"""Recompute all derived review material from the retained raw traces."""
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
publication = root / "derived" / "publication"
adaptation = root / "derived" / "adaptation"
publication.mkdir(parents=True, exist_ok=True)
adaptation.mkdir(parents=True, exist_ok=True)
commands = (
    (root / "scripts/analyze-publication.py", root / "raw/publication/trace.jsonl",
     "--output-dir", publication),
    (root / "scripts/analyze-cost.py", root / "raw/publication/cost-trace.jsonl",
     "--output-dir", publication),
    (root / "scripts/analyze-adaptation.py", root / "raw/adaptation/adaptation-trace.jsonl",
     "--output-dir", adaptation),
)
for command in commands:
    subprocess.run((sys.executable, *map(str, command)), check=True)
for checksum in (publication / "SHA256SUMS", adaptation / "SHA256SUMS"):
    checksum.unlink(missing_ok=True)
subprocess.run((sys.executable, str(root / "scripts/render_tables.py"),
                "--publication", str(publication), "--adaptation", str(adaptation),
                "--output-dir", str(root / "derived/review-tables")), check=True)
'''

CORE_MANIFEST = '''[package]
name = "anonymous_runtime_core"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
anonymous_runtime_abi = { path = "../runtime-abi" }
ed25519-dalek = { version = "2.2", default-features = false }
sha2 = { version = "0.10", default-features = false, features = ["force-soft"] }
spin = "0.10"
zerocopy = { version = "0.9.0-alpha.0", default-features = false, features = ["derive"] }
loom = { version = "0.7", optional = true }

[features]
default = []
cloud-profile = []
embedded-profile = []
experimental-aarch64-jit = []
loom-model = ["dep:loom"]
host-update-diagnostics = []
'''

ABI_MANIFEST = '''[package]
name = "anonymous_runtime_abi"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
bitflags = "2.10"
zerocopy = { version = "0.9.0-alpha.0", default-features = false, features = ["derive"] }
'''

SOURCE_WORKSPACE = '''[workspace]
members = ["runtime-abi", "runtime-core"]
resolver = "2"
'''

THIRD_PARTY = '''# Dependency notice

No third-party source or binary is bundled. The buildable core names its direct
dependencies and versions in `runtime-core/Cargo.toml`: ed25519-dalek, sha2,
spin, zerocopy, bitflags, and the optional Loom model checker. Those packages and their
transitive dependencies are fetched separately and remain under their upstream
licenses and attribution requirements. No legal notice present in the selected
source files was removed.
'''

README = '''# Anonymous publication artifact

Local artifact revision: `artifact-r1`.

This bundle contains the runtime publication source needed to inspect the
reported mechanism, the four hosted campaign sources, retained raw traces, the
three independent analyzers, and presentation-only table rendering. Numeric
measurements and installation identities are unchanged.

Run `python3 scripts/reproduce.py` from any directory to recompute `derived/`
from `raw/`. Run `cargo test --manifest-path source/runtime-core/Cargo.toml
--features loom-model,cloud-profile --test concurrency_model` to exercise the
same publication and reclamation implementation under the model checker.

`source/runtime-core` and `source/runtime-abi` form an independently buildable
subset. `source/manager/bpf` and `source/host-tests` preserve the actual manager
integration and campaign implementations for inspection, but the broad kernel,
platform, boot, and device modules they import are deliberately omitted. The
artifact therefore reproduces all retained analyses and the core concurrency
model; it does not reproduce campaign capture or a complete kernel build.

`patch.diff` is the actual publication-runtime delta after the same export-only
identity substitutions used in `source/`. It contains no version-control object
identifiers. `MANIFEST.sha256` hashes the anonymized artifact files and excludes
itself. Dependency resolution is intentionally not locked here because the
private workspace lock contains repository locations and source checksums.
'''


def reproduce(artifact: Path) -> str:
    result = subprocess.run(
        (sys.executable, str(artifact / "scripts/reproduce.py")),
        check=True, cwd=artifact, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return result.stdout


def normalize(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            raise ValueError(f"symlink in artifact: {path}")
        os.chmod(path, DIR_MODE if path.is_dir() else FILE_MODE)
        os.utime(path, (315532800, 315532800), follow_symlinks=False)
    os.chmod(root, DIR_MODE)
    os.utime(root, (315532800, 315532800), follow_symlinks=False)


def write_manifest(root: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.sha256":
            lines.append(f"{sha256(path.read_bytes())}  {path.relative_to(root)}\n")
    write_text(root / "MANIFEST.sha256", "".join(lines))


def scan_text(label: str, text: str) -> None:
    for kind, pattern in FORBIDDEN:
        match = pattern.search(text)
        if match:
            excerpt = match.group(0).replace("\n", " ")[:80]
            raise ValueError(f"{label}: forbidden {kind}: {excerpt!r}")


def scan_tree(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        scan_text(f"path {relative}", relative)
        if path.is_symlink():
            raise ValueError(f"symlink in artifact: {relative}")
        if path.is_file():
            scan_text(relative, path.read_text(encoding="utf-8"))
            if stat.S_IMODE(path.stat().st_mode) != FILE_MODE:
                raise ValueError(f"unsafe file mode: {relative}")


def make_zip(root: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for path in [root, *sorted(root.rglob("*"))]:
            relative = Path(ARTIFACT) / path.relative_to(root)
            name = relative.as_posix() + ("/" if path.is_dir() else "")
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ((stat.S_IFDIR | DIR_MODE) if path.is_dir()
                                  else (stat.S_IFREG | FILE_MODE)) << 16
            archive.writestr(info, b"" if path.is_dir() else path.read_bytes())


def scan_zip(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        if archive.comment:
            raise ValueError("ZIP comment is not permitted")
        for info in archive.infolist():
            scan_text(f"ZIP path {info.filename}", info.filename)
            if info.date_time != ZIP_TIME or info.extra or info.comment:
                raise ValueError(f"non-neutral ZIP metadata: {info.filename}")
            mode = (info.external_attr >> 16) & 0o177777
            wanted = stat.S_IFDIR | DIR_MODE if info.is_dir() else stat.S_IFREG | FILE_MODE
            if mode != wanted:
                raise ValueError(f"unsafe ZIP mode: {info.filename}")
            if not info.is_dir():
                scan_text(f"ZIP content {info.filename}", archive.read(info).decode("utf-8"))


def build(repo: Path, output_root: Path) -> tuple[Path, Path, Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".anonymous-publication-", dir=output_root))
    artifact = staging / ARTIFACT
    mapping: list[dict] = []
    try:
        copy_tree(repo / "kernel/crates/kernel_bpf/src",
                  artifact / "source/runtime-core/src", artifact, mapping)
        copy_text(repo / "kernel/crates/kernel_bpf/tests/concurrency_model.rs",
                  artifact / "source/runtime-core/tests/concurrency_model.rs", artifact, mapping)
        copy_tree(repo / "kernel/crates/kernel_abi/src",
                  artifact / "source/runtime-abi/src", artifact, mapping)
        copy_tree(repo / "kernel/src/bpf", artifact / "source/manager/bpf", artifact, mapping)
        for source, destination in HOST_TESTS.items():
            copy_text(repo / source, artifact / destination, artifact, mapping)
        for source, destination in SCRIPT_FILES.items():
            copy_text(repo / source, artifact / destination, artifact, mapping)
        for source, destination in RAW_FILES.items():
            copy_text(repo / source, artifact / destination, artifact, mapping)

        write_text(artifact / "source/runtime-core/Cargo.toml", CORE_MANIFEST)
        write_text(artifact / "source/runtime-abi/Cargo.toml", ABI_MANIFEST)
        write_text(artifact / "source/Cargo.toml", SOURCE_WORKSPACE)
        write_text(artifact / "source/DEPENDENCIES.md", THIRD_PARTY)
        write_text(artifact / "scripts/reproduce.py", REPRODUCE)
        write_text(artifact / "README.md", README)
        write_text(artifact / "patch.diff", export_patch(
            repo / "docs/performance/evidence/update-transaction-v2/source.patch"))
        write_text(artifact / "derived/reproduction.log", reproduce(artifact))

        normalize(artifact)
        write_manifest(artifact)
        normalize(artifact)
        scan_tree(artifact)
        archive = staging / f"{ARTIFACT}.zip"
        make_zip(artifact, archive)
        scan_zip(archive)

        final_artifact = output_root / ARTIFACT
        final_archive = output_root / f"{ARTIFACT}.zip"
        private_map = output_root / f"{ARTIFACT}.private-map.json"
        if final_artifact.exists():
            shutil.rmtree(final_artifact)
        final_archive.unlink(missing_ok=True)
        final_artifact.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(artifact), final_artifact)
        shutil.move(str(archive), final_archive)
        revision = subprocess.run(("git", "rev-parse", "HEAD"), cwd=repo,
                                  check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
        private_map.write_text(json.dumps({
            "artifact": ARTIFACT,
            "source_revision": revision,
            "files": mapping,
        }, indent=2, sort_keys=True) + "\n")
        return final_artifact, final_archive, private_map
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    default_target = Path(os.environ.get("CARGO_TARGET_DIR", repo / "target"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path,
                        default=default_target / "anonymous-publication")
    args = parser.parse_args()
    artifact, archive, private_map = build(repo, args.output_root.resolve())
    print(f"PASS: built {artifact.name} ({len(artifact.joinpath('MANIFEST.sha256').read_text().splitlines())} files)")
    print(f"PASS: deterministic archive {archive.name}; private source map {private_map.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
