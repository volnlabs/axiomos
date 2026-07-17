#!/usr/bin/env python3
"""Reject broken repository-local links in Markdown documentation."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")
INLINE_CODE = re.compile(r"`[^`]*`")
EXTERNAL_SCHEMES = {
    "data",
    "ftp",
    "http",
    "https",
    "irc",
    "mailto",
    "tel",
}


def markdown_files() -> list[Path]:
    """Return tracked and not-ignored untracked Markdown files."""
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.md",
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


def destination(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        return raw[1 : raw.index(">")]
    return raw.split(maxsplit=1)[0]


def local_target(source: Path, raw: str) -> Path | None:
    target = unquote(destination(raw)).replace("\\ ", " ")
    if not target or target.startswith("#"):
        return None

    parsed = urlsplit(target)
    if parsed.scheme.lower() in EXTERNAL_SCHEMES or parsed.netloc:
        return None

    path = parsed.path
    if not path:
        return None
    if path.startswith("/"):
        return ROOT / path.lstrip("/")
    return source.parent / path


def links(path: Path) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    fence: str | None = None
    for line_number, original in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = original.lstrip()
        fence_match = re.match(r"(```+|~~~+)", stripped)
        if fence_match:
            marker = fence_match.group(1)[0]
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            continue
        if fence is not None:
            continue

        line = INLINE_CODE.sub("", original)
        for match in INLINE_LINK.finditer(line):
            found.append((line_number, match.group(1)))
        reference = REFERENCE_LINK.match(line)
        if reference:
            found.append((line_number, reference.group(1)))
    return found


def main() -> int:
    failures: list[str] = []
    checked_links = 0
    files = markdown_files()
    for source in files:
        for line_number, raw in links(source):
            target = local_target(source, raw)
            if target is None:
                continue
            checked_links += 1
            if not target.exists():
                relative = source.relative_to(ROOT)
                failures.append(
                    f"{relative}:{line_number}: missing local link target {destination(raw)!r}"
                )

    if failures:
        print("documentation link check: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"documentation link check: PASS ({len(files)} Markdown files, "
        f"{checked_links} local links)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
