#!/usr/bin/env python3
"""Run the documented, bounded developer command surface without a shell."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "ci/manifests/commands.toml"
ALLOWED_ARGV = {
    ("cargo", "xtask", "--help"),
    ("cargo", "xtask", "inventory", "--check"),
    ("cargo", "xtask", "boundary", "--check"),
    ("cargo", "xtask", "docs", "--check"),
    ("scripts/verify/engineering-audit.sh", "--help"),
    ("scripts/debug/qemu-triage.sh", "--help"),
    ("scripts/benchmark/analyze-v03.py", "--self-test"),
    ("scripts/benchmark/verifier-cost.py", "--help"),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def safe_argv(argv: list[str]) -> bool:
    return tuple(argv) in ALLOWED_ARGV


def main() -> int:
    try:
        data = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
        require(data.get("schema_version") == 1, "unsupported command manifest schema")
        commands = data.get("command")
        require(isinstance(commands, list) and commands, "command manifest is empty")

        names: set[str] = set()
        environment = os.environ.copy()
        environment.update(CARGO_TERM_COLOR="never", PYTHONDONTWRITEBYTECODE="1")
        for command in commands:
            name = command.get("name")
            display = command.get("display")
            argv = command.get("argv")
            docs = command.get("docs")
            expect = command.get("expect")
            require(isinstance(name, str) and name, "command name is missing")
            require(name not in names, f"duplicate command name: {name}")
            names.add(name)
            require(isinstance(display, str) and display, f"{name}: display is missing")
            require(
                isinstance(argv, list) and all(isinstance(arg, str) and arg for arg in argv),
                f"{name}: argv must be a non-empty string array",
            )
            require(safe_argv(argv), f"{name}: command is outside the bounded allowlist")
            require(isinstance(docs, list) and docs, f"{name}: docs must be non-empty")
            for relative in docs:
                path = (ROOT / relative).resolve()
                require(path.is_relative_to(ROOT), f"{name}: documentation escapes repository")
                require(path.is_file(), f"{name}: documentation is missing: {relative}")
                require(
                    display in path.read_text(encoding="utf-8"),
                    f"{name}: {relative} does not contain {display!r}",
                )

            result = subprocess.run(
                argv,
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            require(result.returncode == 0, f"{name}: exited {result.returncode}\n{result.stdout}")
            if expect is not None:
                require(isinstance(expect, str) and expect, f"{name}: expect must be a string")
                require(expect in result.stdout, f"{name}: missing output marker {expect!r}")
    except (AssertionError, subprocess.TimeoutExpired, tomllib.TOMLDecodeError) as error:
        print(f"command smoke check: FAIL: {error}", file=sys.stderr)
        return 1

    print(f"command smoke check: PASS ({len(commands)} documented commands)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
