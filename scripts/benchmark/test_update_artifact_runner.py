#!/usr/bin/env python3
"""Synthetic checks of capture failures; these are not benchmark evidence."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CaptureTest(unittest.TestCase):
    def test_streamed_markers_preserve_records_and_bad_line_numbers(self):
        spec = importlib.util.spec_from_file_location(
            "capture", Path(__file__).with_name("update-transaction-runner.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=os.environ.get("CARGO_TARGET_DIR")) as temporary:
            root = Path(temporary)
            log = root / "test-output.log"
            log.write_text('test check ... UPDATE_TXN {"b":2,"a":1}\n'
                           'noise UPDATE_TXN {}\nUPDATE_ADAPT {"run":0}\n'
                           'UPDATE_ADAPT {\nUPDATE_TXN {}\n')
            counts, malformed = module.extract_records(log, root, ["UPDATE_TXN", "UPDATE_ADAPT"])
            self.assertEqual(counts, {"UPDATE_TXN": 2, "UPDATE_ADAPT": 1})
            self.assertEqual((root / "trace.jsonl").read_text(), '{"a": 1, "b": 2}\n{}\n')
            self.assertEqual(json.loads((root / "adaptation-trace.jsonl").read_text()), {"run": 0})
            self.assertEqual([(r["line"], r["marker"]) for r in malformed], [(4, "UPDATE_ADAPT")])

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
