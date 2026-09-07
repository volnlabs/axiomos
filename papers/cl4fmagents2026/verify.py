#!/usr/bin/env python3
"""Check the review PDF and its table against the retained publication trace."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def output(*args):
    return subprocess.check_output(args, text=True)


pdf = HERE / "who-guards-the-update.pdf"
text = output("pdftotext", "-layout", str(pdf), "-")
pages = [page for page in text.split("\f") if page.strip()]
reference_pages = [i for i, page in enumerate(pages)
                   if re.search(r"^\s*\d*\s*References\s*$", page, re.M)]
assert reference_pages, "Missing references section"
assert 1 <= reference_pages[0] <= 4, f"Content exceeds four pages: {reference_pages[0]}"
assert "case study is" not in pages[0].lower(), "Case study displaced the page-1 problem"

metadata = output("pdfinfo", str(pdf))
assert re.search(r"^Author:\s*$", metadata, re.M), "Author metadata is not blank"
assert "Transactional Publication Semantics" in metadata, "Stale PDF title"
for identity in ("utkarsh", "maurya", "axiomos", "kernex", "/home/", "2ef74f0"):
    assert identity not in (text + metadata).lower(), f"Identifying material: {identity}"
assert "Anonymous Author(s)" in pages[0]
assert not re.search(r"\b(?:TODO|TBD)\b|\?\?", text)
assert "pending validation" not in text.lower(), "Experiment is not ready for submission"

log = (HERE / "build/main.log").read_text()
assert not re.search(r"Overfull|undefined|Citation .* undefined|Rerun to get", log)
source = (HERE / "main.tex").read_text()
assert r"\usepackage[dblblindworkshop]{neurips_2026}" in source
evidence = Path(os.environ.get("UPDATE_PUBLICATION_EVIDENCE",
                ROOT / "docs/performance/evidence/update-transaction-v2"))
checksums = {}
for line in (evidence / "SHA256SUMS").read_text().splitlines():
    digest, separator, name = line.partition("  ")
    relative = Path(name)
    assert separator and re.fullmatch(r"[0-9a-f]{64}", digest), "Malformed checksum"
    assert name and not relative.is_absolute() and ".." not in relative.parts
    assert relative.as_posix() == name and name not in checksums, "Duplicate/aliased checksum path"
    path = evidence / relative
    assert not path.is_symlink() and path.is_file(), f"Missing/linked evidence: {name}"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, f"Corrupt evidence: {name}"
    checksums[name] = digest
assert set(checksums) == {str(p.relative_to(evidence)) for p in evidence.rglob("*")
                          if p.is_file() and p.name != "SHA256SUMS"}, "Incomplete checksums"
manifest = json.loads((evidence / "environment.json").read_text())
assert manifest["exit_code"] == 0 and not manifest["timed_out"], "Capture failed"
assert not manifest["malformed_records"], "Malformed raw evidence"
assert not manifest["changed_sources_during_run"] and not manifest["changed_executables_during_run"]
source_digest = hashlib.sha256(json.dumps({"revision": manifest["revision"],
    "sources": manifest["source_sha256"]}, sort_keys=True).encode()).hexdigest()
assert source_digest == manifest["source_digest"] == manifest["build_source_digest"] == manifest["finished_source_digest"]
assert manifest["patch_sha256"] == checksums["source.patch"]
for name, digest in manifest["source_sha256"].items():
    retained = "untracked-source/" + name
    if retained in checksums:
        assert checksums[retained] == digest, f"Source copy disagrees with manifest: {name}"
for marker, trace in (("UPDATE_TXN", "trace.jsonl"), ("UPDATE_COST", "cost-trace.jsonl")):
    assert manifest["trace_records"][marker] == sum(1 for line in (evidence / trace).open() if line.strip())
build_command = json.loads((evidence / "build-command.json").read_text())
assert "--locked" in build_command and "--release" in build_command
assert "kernel_bpf/embedded-profile" in build_command[build_command.index("--features") + 1]
targets = {}
for line in (evidence / "build-artifacts.jsonl").read_text().splitlines():
    record = json.loads(line)
    if record.get("reason") == "compiler-artifact" and record.get("executable"):
        targets[record["target"]["name"]] = record["executable"]
assert {"bpf_update_campaign", "bpf_update_measurements"} <= targets.keys()
assert {targets[name] for name in ("bpf_update_campaign", "bpf_update_measurements")} == set(manifest["executable_sha256"])
if os.environ.get("UPDATE_PUBLICATION_CHECK_BINARIES") == "1":
    for name, digest in manifest["executable_sha256"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, f"Measured binary changed: {name}"
# Verification must never rewrite the retained evidence being checked.
with tempfile.TemporaryDirectory(prefix="publication-paper-check-") as directory:
    regenerated = Path(directory)
    for trace, analyzer in (("trace.jsonl", "analyze-update-transaction.py"),
                            ("cost-trace.jsonl", "analyze-update-cost.py")):
        command = ["python3", str(ROOT / "scripts/benchmark" / analyzer), str(evidence / trace),
                   "--output-dir", str(regenerated)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    for name in ("analysis.json", "cost-analysis.json", "result-table.tex", "cost-table.tex", "cost-note.tex"):
        assert (evidence / name).read_bytes() == (regenerated / name).read_bytes(), name
records = [json.loads(line) for line in (evidence / "trace.jsonl").read_text().splitlines()]
spec = importlib.util.spec_from_file_location(
    "update_analysis", ROOT / "scripts/benchmark/analyze-update-transaction.py")
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)
reported = json.loads((evidence / "analysis.json").read_text())
assert analysis.analyze(records) == {**reported["paired_summary"], **reported["supporting_summary"]}
for local, retained in (("results.tex", "result-table.tex"), ("costs.tex", "cost-table.tex"),
                        ("cost-note.tex", "cost-note.tex")):
    assert (HERE / local).read_bytes() == (evidence / retained).read_bytes()
    assert f"\\input{{{local}}}" in source, f"PDF does not include {local}"
    for row in (HERE / local).read_text().splitlines():
        if " & " not in row or row.startswith(("Observation &", "Fault &", "Hold ")):
            continue
        cells = row.removesuffix(r" \\").split(" & ")
        cells = [re.sub(r"\\(?:textsc|textbf|texttt)\{([^{}]*)\}", r"\1", cell) for cell in cells]
        pattern = r"\s+".join((r"(?:--|–|—)" if cell == "--" else re.escape(cell)) for cell in cells)
        assert re.search(pattern, text, re.I), f"Generated table row absent from PDF: {cells}"
assert "qin2026governed" in source and "lim2026lithe" in source
prose = re.sub(r"^\s*\d+\s{2,}", "", text, flags=re.M)
normalize = lambda value: re.sub(r"[^a-z0-9]", "", value.lower())
note = (HERE / "cost-note.tex").read_text().replace(r"\mu", "")
assert normalize(note) in normalize(prose), "Generated cost prose absent from PDF"

print("PASS: at most four content pages; anonymous PDF; resolved build; verified provenance and trace-derived tables/prose.")
