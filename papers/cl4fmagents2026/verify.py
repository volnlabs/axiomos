#!/usr/bin/env python3
"""Check the review PDF and its table against the retained publication trace."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess

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
evidence = ROOT / "docs/performance/evidence/update-transaction"
subprocess.run(["python3", str(ROOT / "scripts/benchmark/analyze-update-transaction.py"),
                str(evidence / "trace.jsonl")], check=True, capture_output=True, text=True)
records = [json.loads(line) for line in (evidence / "trace.jsonl").read_text().splitlines()]
spec = importlib.util.spec_from_file_location(
    "update_analysis", ROOT / "scripts/benchmark/analyze-update-transaction.py")
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)
assert analysis.analyze(records) == json.loads((evidence / "analysis.json").read_text())["summary"]
assert (HERE / "results.tex").read_bytes() == (evidence / "result-table.tex").read_bytes()
assert r"\input{results.tex}" in source, "PDF does not include the generated result table"
for row in (HERE / "results.tex").read_text().splitlines():
    if " & " in row and not row.startswith("Observation &"):
        cells = row.removesuffix(r" \\").split(" & ")
        pattern = r"\s+".join((r"(?:--|–|—)" if cell == "--" else re.escape(cell)) for cell in cells)
        assert re.search(pattern, text), f"Generated table row absent from PDF: {cells}"
assert "qin2026governed" in source and "lim2026lithe" in source

print("PASS: at most four content pages; anonymous text/metadata; resolved build; trace-derived table.")
