#!/usr/bin/env python3
"""Synthetic checks of capture failures; these are not benchmark evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CaptureTest(unittest.TestCase):
    def test_capture_status_and_provenance_fail_closed(self):
        runner = Path(__file__).with_name("update-transaction-runner.py")
        cases = (
            ("success", 'print("UPDATE_TXN {}")', [], 0),
            ("missing", 'print("no marker")', [], 1),
            ("malformed", 'print("UPDATE_TXN {")', [], 1),
            ("timeout", "import time; time.sleep(10)", ["--timeout-seconds", "0.1"], 124),
            ("stale_source", 'print("UPDATE_TXN {}")', ["--expected-source-digest", "wrong"], 2),
        )
        with tempfile.TemporaryDirectory(prefix="publication-runner-check-",
                                          dir=os.environ.get("CARGO_TARGET_DIR")) as temporary:
            for name, program, extra, expected in cases:
                with self.subTest(name=name):
                    destination = Path(temporary) / name
                    result = subprocess.run([sys.executable, str(runner), "--output", str(destination),
                                             *extra, "--", sys.executable, "-c", program],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if name in ("timeout", "malformed"):
                        manifest = json.loads((destination / "environment.json").read_text())
                        self.assertTrue(manifest["timed_out" if name == "timeout" else "malformed_records"])


if __name__ == "__main__":
    unittest.main()
