#!/usr/bin/env python3
"""Integration contract for the GPIO23 probe's human-action prompt."""

from __future__ import annotations

import os
from pathlib import Path
import pty
import signal
import stat
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "scripts/hil/gpio23-probe.sh"


MOCK_SIGROK = """#!/usr/bin/env python3
import os
import pathlib
import sys
import time

mode = os.environ.get("SIGROK_MODE", "data")
if "-i" in sys.argv:
    raise SystemExit(0)
output = pathlib.Path(sys.argv[sys.argv.index("-o") + 1])
output.write_bytes(b"mock capture\\n")
if mode == "fail":
    print("analyzer failed", file=sys.stderr)
    raise SystemExit(1)
if mode == "data":
    print("Received SR_DF_LOGIC", flush=True)
    time.sleep(2)
else:
    print("Received SR_DF_HEADER", flush=True)
    time.sleep(0.1)
"""


class Gpio23ProbePromptTests(unittest.TestCase):
    def run_probe(self, mode: str, uart: bytes = b"", timeout: float = 3.0) -> str:
        with tempfile.TemporaryDirectory(prefix="gpio23-probe-test-") as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            sigrok = bin_dir / "sigrok-cli"
            sigrok.write_text(MOCK_SIGROK, encoding="utf-8")
            sigrok.chmod(sigrok.stat().st_mode | stat.S_IXUSR)
            run_dir = root / "run"
            master, slave = pty.openpty()
            try:
                environment = os.environ.copy()
                environment.update(
                    {
                        "PATH": f"{bin_dir}:{environment['PATH']}",
                        "PI_UART": os.ttyname(slave),
                        "RUN_DIR": str(run_dir),
                        "SIGROK_MODE": mode,
                        "READY_TIMEOUT": "1",
                        "ANALYZER_READY_TIMEOUT": "1",
                        "UART_SECONDS": "10",
                        "SAMPLES": "1",
                    }
                )
                slave_name = os.ttyname(slave)
                os.close(slave)
                slave = -1
                environment["PI_UART"] = slave_name
                process = subprocess.Popen(
                    [str(PROBE)],
                    cwd=ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                )
                time.sleep(0.25)
                if uart:
                    os.write(master, uart)
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                output = process.communicate()[0]
                return output
            finally:
                os.close(master)
                if slave >= 0:
                    os.close(slave)

    def test_prompt_requires_both_uart_markers_and_live_logic_data(self) -> None:
        missing = self.run_probe("data")
        self.assertNotRegex(missing, r">>> TOUCH NOW|touch the resistor lead")

        boot_only = self.run_probe("data", b"PI5_BENCH_READY\n")
        self.assertNotRegex(boot_only, r">>> TOUCH NOW|touch the resistor lead")

        failed = self.run_probe(
            "fail", b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\n"
        )
        self.assertNotRegex(failed, r">>> TOUCH NOW|touch the resistor lead")

        no_data = self.run_probe(
            "no-data", b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\n"
        )
        self.assertNotRegex(no_data, r">>> TOUCH NOW|touch the resistor lead")

        panic = self.run_probe(
            "data", b"PI5_BENCH_READY\npanic: uart failure\nSIGNED_BPF_LOAD_OK\n"
        )
        self.assertNotRegex(panic, r">>> TOUCH NOW|touch the resistor lead")

        ready = self.run_probe("data", b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\n")
        self.assertIn("TOUCH NOW", ready)
        self.assertNotIn("touch the resistor lead", ready)


if __name__ == "__main__":
    unittest.main()
