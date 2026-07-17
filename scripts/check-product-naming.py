#!/usr/bin/env python3
"""Enforce the canonical axiomos product name outside historical records."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
URL = re.compile(r"https?://[^\s)>]+")
LEGACY_NAME = re.compile(
    r"\bAx" r"iom\b|\b(?:Ax" r"iomOS|ax" r"iomOS)\b|\bax" r"iom-[a-z0-9]"
)


def governed_files() -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(
        ROOT / entry.decode("utf-8", errors="surrogateescape")
        for entry in result.stdout.split(b"\0")
        if entry
    )


def historical(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return (
        relative == Path("ENGINEERING_AUDIT.md")
        or relative.parts[:1] == ("artifacts",)
        or relative.parts[:2] == ("docs", "archive")
        or relative.parts[:2] == (".superpowers", "sdd")
        or relative.suffix == ".log"
    )


def main() -> int:
    failures: list[str] = []
    checked = 0
    for path in governed_files():
        if historical(path) or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        checked += 1
        for line_number, line in enumerate(text.splitlines(), start=1):
            # Repository slugs are external identities and are not renamed.
            match = LEGACY_NAME.search(URL.sub("", line))
            if match:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: "
                    f"legacy product name {match.group(0)!r}"
                )

    if failures:
        print("product naming check: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"product naming check: PASS ({checked} governed text files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
