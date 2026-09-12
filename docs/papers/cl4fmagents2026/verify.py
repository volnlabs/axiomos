#!/usr/bin/env python3
"""Check the actual review PDF, its build log, and its retained numeric source."""
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def output(*args):
    return subprocess.check_output(args, text=True)


pdf = HERE / "who-guards-the-update.pdf"
text = output("pdftotext", "-layout", str(pdf), "-")
pages = [page for page in text.split("\f") if page.strip()]
assert len(pages) == 5, f"Expected 4 content pages + references, got {len(pages)}"
assert re.search(r"^\s*\d*\s*References\s*$", pages[4], re.M)
assert all(not re.search(r"^\s*\d*\s*References\s*$", p, re.M) for p in pages[:4])
assert "case study is" not in pages[0].lower(), "Case study displaced the page-1 problem"

metadata = output("pdfinfo", str(pdf))
assert re.search(r"^Author:\s*$", metadata, re.M), "Author metadata is not blank"
for identity in ("utkarsh", "maurya", "axiomos", "kernex", "/home/", "2ef74f0"):
    assert identity not in (text + metadata).lower(), f"Identifying material: {identity}"
assert "Anonymous Author(s)" in pages[0]
assert not re.search(r"\b(?:TODO|TBD)\b|\?\?", text)

log = (HERE / "build/main.log").read_text()
assert not re.search(r"Overfull|undefined|Citation .* undefined|Rerun to get", log)
source = (HERE / "main.tex").read_text()
assert r"\usepackage[dblblindworkshop]{neurips_2026}" in source
raw = (ROOT / "docs/performance/evidence/2ef74f0/verifier-host.log").read_text()
for size, low, high in ((10, "3.1151", "3.1216"), (100, "31.437", "31.465"),
                        (1000, "376.43", "379.28")):
    section = raw.split(f"verifier/scaling/instructions/{size}\n", 1)[1]
    interval = re.search(r"time:\s*\[([^]]+)\]", section).group(1)
    numbers = re.findall(r"\d+\.\d+", interval)
    assert (numbers[0], numbers[-1]) == (low, high)
    assert re.search(re.escape(low) + r"\s*[-–]\s*" + re.escape(high), text)

print("PASS: 4 content pages + references; anonymous text/metadata; resolved build; exact retained intervals.")
