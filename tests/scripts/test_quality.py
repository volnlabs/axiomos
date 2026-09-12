#!/usr/bin/env python3
"""Regression checks for historical mutation evidence provenance."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
QUALITY_PATH = ROOT / "scripts/verify/quality.py"
spec = importlib.util.spec_from_file_location("quality", QUALITY_PATH)
quality = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(quality)


class QualityEvidenceTests(unittest.TestCase):
    def test_historical_scope_excludes_new_file_and_rejects_missing_entry(self) -> None:
        commit = "2cd870d8f5087ee17adba86f073559cc9a1414fe"
        pattern = "kernel/crates/shrike_link/src/*.rs"
        inputs = quality.historical_source_inputs(commit, [pattern])

        self.assertNotIn("kernel/crates/shrike_link/src/tx.rs", inputs)
        self.assertIn("kernel/crates/shrike_link/src/lib.rs", inputs)

        row = next(
            row
            for row in quality.load_toml(ROOT / "ci/manifests/quality.toml")["mutation"]
            if row["name"] == "shrike-link-protocol"
        )
        report = json.loads(
            (ROOT / row["evidence"]).read_text(encoding="utf-8")
        )
        report["inputs"].pop("kernel/crates/shrike_link/src/lib.rs")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            evidence = Path(directory) / "evidence.json"
            evidence.write_text(json.dumps(report), encoding="utf-8")
            test_row = {
                **row,
                "evidence": evidence.relative_to(ROOT).as_posix(),
                "evidence_sha256": quality.sha256(evidence.read_bytes()),
            }
            with self.assertRaisesRegex(ValueError, "input set mismatch"):
                quality.validate_mutation_evidence(
                    test_row, quality.load_toml(ROOT / "ci/manifests/quality.toml")
                )

    def test_historical_scope_is_root_anchored(self) -> None:
        result = quality.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b"kernel/crates/shrike_link/src/lib.rs\0"
                b"nested/kernel/crates/shrike_link/src/extra.rs\0"
            ),
        )
        with patch.object(quality.subprocess, "run", return_value=result):
            self.assertEqual(
                quality.historical_source_inputs(
                    "baseline", ["kernel/crates/shrike_link/src/*.rs"]
                ),
                {"kernel/crates/shrike_link/src/lib.rs"},
            )


if __name__ == "__main__":
    unittest.main()
