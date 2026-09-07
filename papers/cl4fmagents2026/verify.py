#!/usr/bin/env python3
"""Check the review PDF and its table against the retained publication trace."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def output(*args):
    return subprocess.check_output(args, text=True)


def check_capture(evidence, markers, names):
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
    for marker, trace in markers:
        assert manifest["trace_records"][marker] == sum(1 for line in (evidence / trace).open() if line.strip())
    build_command = json.loads((evidence / "build-command.json").read_text())
    assert "--locked" in build_command and "--release" in build_command
    assert "kernel_bpf/embedded-profile" in build_command[build_command.index("--features") + 1]
    targets = {}
    for line in (evidence / "build-artifacts.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-artifact" and record.get("executable"):
            targets[record["target"]["name"]] = record["executable"]
    assert set(names) <= targets.keys()
    assert {targets[name] for name in names} == set(manifest["executable_sha256"])
    if os.environ.get("UPDATE_PUBLICATION_CHECK_BINARIES") == "1":
        for name, digest in manifest["executable_sha256"].items():
            assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, f"Measured binary changed: {name}"


pdf = HERE / "who-guards-the-update.pdf"
build_inputs = {}
for line in (HERE / "build/inputs.sha256").read_text().splitlines():
    digest, name = line.split("  ", 1)
    assert name not in build_inputs and Path(name).name == name
    assert hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest, f"Stale build: {name}"
    build_inputs[name] = digest
assert set(build_inputs) == {"Makefile", "render_tables.py", pdf.name} | {
    p.name for pattern in ("*.tex", "*.bib", "*.sty") for p in HERE.glob(pattern)
}, "Build input inventory changed; rebuild the paper"
text = output("pdftotext", "-layout", str(pdf), "-")
pages = [page for page in text.split("\f") if page.strip()]
reference_pages = [i for i, page in enumerate(pages)
                   if re.search(r"^\s*\d*\s*References\s*$", page, re.M)]
assert reference_pages, "Missing references section"
assert 1 <= reference_pages[0] <= 4, f"Content exceeds four pages: {reference_pages[0]}"
appendix_pages = [i for i, page in enumerate(pages)
                  if re.search(r"^\s*\d*\s*A\s+Protocol API and state machine\s*$", page, re.M)]
assert len(appendix_pages) == 1 and appendix_pages[0] > reference_pages[0], "Appendix must follow references"
assert 3 <= len(pages) - appendix_pages[0] <= 5, "Appendix must occupy three to five pages"
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
assert source.index(r"\bibliography{references}") < source.index(r"\appendix")
assert r"\input{appendix.tex}" in source
source += "\n" + (HERE / "appendix.tex").read_text()
assert r"\usepackage[dblblindworkshop]{neurips_2026}" in source
assert "Workshop:" in pages[0] and "Foundation Models and Embodied Agents" in pages[0]
assert "Short systems paper" in metadata and "CreationDate:" not in metadata
assert r"\texttt{Reset}" not in source and r"\textsc{" not in source
assert "Our contributions" in pages[0] or "We contribute" in pages[0], "Contributions moved off page one"
for table in re.findall(r"\\begin\{table\}.*?\\end\{table\}", source, re.S):
    body = re.search(r"\\(?:input\{|begin\{tabular\})", table)
    assert body and table.index(r"\caption{") < body.start(), "Caption must precede table"
assert r"\resizebox" not in source
evidence = Path(os.environ.get("UPDATE_PUBLICATION_EVIDENCE",
                ROOT / "docs/performance/evidence/update-transaction-v2"))
check_capture(evidence, (("UPDATE_TXN", "trace.jsonl"), ("UPDATE_COST", "cost-trace.jsonl")),
              ("bpf_update_campaign", "bpf_update_measurements"))
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
adaptation = Path(os.environ.get("UPDATE_ADAPTATION_EVIDENCE",
                  ROOT / "docs/performance/evidence/update-adaptation-v1"))
check_capture(adaptation, (("UPDATE_ADAPT", "adaptation-trace.jsonl"),), ("bpf_update_adaptation",))
with tempfile.TemporaryDirectory(prefix="adaptation-paper-check-") as directory:
    regenerated = Path(directory)
    subprocess.run(["python3", str(ROOT / "scripts/benchmark/analyze-update-adaptation.py"),
                    str(adaptation / "adaptation-trace.jsonl"), "--output-dir", str(regenerated)],
                   check=True, capture_output=True, text=True, timeout=120)
    for name in ("analysis.json", "adaptation-table.tex"):
        assert (adaptation / name).read_bytes() == (regenerated / name).read_bytes(), name
spec = importlib.util.spec_from_file_location("review_tables", HERE / "render_tables.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
subprocess.run([sys.executable, HERE / "test_render_tables.py"], check=True, capture_output=True, text=True)
with tempfile.TemporaryDirectory(prefix="review-table-check-") as directory:
    regenerated = Path(directory)
    rows = renderer.render(evidence, adaptation, regenerated)
    for local in (*rows, "cost-note.tex"):
        assert (HERE / local).read_bytes() == (regenerated / local).read_bytes(), local
        assert f"\\input{{{local}}}" in source
    for local in ("appendix-analysis.json", "appendix-requests.csv", "appendix-runs.csv", "appendix-summary.csv", "appendix-latency-runs.csv"):
        assert (HERE / local).read_bytes() == (regenerated / local).read_bytes(), local
    for local, table_rows in rows.items():
        for row in table_rows:
            # Wrapped label cells may straddle numeric rows in pdftotext.
            # Source/PDF build hashes bind the full table; check numeric cells too.
            values = row[1:]
            if not all(re.fullmatch(r"[0-9./]+|--|AP|GR", value) for value in values):
                continue
            pattern = r"\s+".join(r"(?:--|–|—)" if value == "--" else re.escape(value) for value in values)
            assert re.search(pattern, text), f"Generated values absent from PDF: {values}"
assert "qin2026governed" in source and "lim2026lithe" in source
prose = re.sub(r"^\s*\d+\s{2,}", "", text, flags=re.M)
normalize = lambda value: re.sub(r"[^a-z0-9]", "", value.lower())
note = (HERE / "cost-note.tex").read_text().replace(r"\mu", "")
note = re.sub(r"\\texttt\{([^{}]*)\}", r"\1", note)
assert normalize(note) in normalize(prose), "Generated cost prose absent from PDF"

print("PASS: four-page body limit; three-to-five-page appendix after references; anonymous PDF; verified provenance and trace-derived tables/prose.")
