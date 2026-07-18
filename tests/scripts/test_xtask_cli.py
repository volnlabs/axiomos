#!/usr/bin/env python3
"""End-to-end contracts for the repository command surface."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
XTASK = ROOT / "target/debug/xtask"
REPORTER = ROOT / "scripts/verify/reporters/summary.py"


class XtaskCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["cargo", "build", "--locked", "-p", "xtask"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def run_xtask(
        self,
        *arguments: str,
        cwd: Path = ROOT,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(XTASK), *arguments],
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_help_is_successful(self) -> None:
        result = self.run_xtask("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage: cargo xtask", result.stdout)

    def test_invalid_invocations_use_exit_two(self) -> None:
        for arguments in (("unknown",), ("build",), ("build", "unknown")):
            with self.subTest(arguments=arguments):
                result = self.run_xtask(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_dependency_uses_exit_three(self) -> None:
        environment = os.environ.copy()
        environment["PATH"] = ""
        result = self.run_xtask("build", "x86_64", env=environment)
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_dry_run_works_outside_root_with_spaces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="axiomos tooling ") as directory:
            result = self.run_xtask(
                "debug", "qemu", "--dry-run", cwd=Path(directory)
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(ROOT / "scripts/debug/qemu-triage.sh"), result.stdout)

    def test_summary_reporter_emits_stable_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="axiomos summary ") as directory:
            output = Path(directory)
            results = output / "results.tsv"
            manifest = output / "manifest.txt"
            summary = output / "summary.json"
            results.write_text(
                "step\tstatus\tduration_seconds\tlog\tcommand\n"
                "inventory\tPASS\t2\tinventory.log\tcargo xtask inventory --check\n",
                encoding="utf-8",
            )
            manifest.write_text(
                "status=PASS\nmode=quick\ncommit=abc123\n"
                "started_at=2026-07-17T00:00:00Z\n"
                "finished_at=2026-07-17T00:00:02Z\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["python3", str(REPORTER), str(results), str(manifest), str(summary)],
                cwd=output,
                check=True,
            )
            payload = json.loads(summary.read_text(encoding="utf-8"))

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["profile"], "quick")
        self.assertEqual(payload["duration_ms"], 2000)
        self.assertEqual(payload["checks"][0]["name"], "inventory")


if __name__ == "__main__":
    unittest.main()
