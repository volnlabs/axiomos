#!/usr/bin/env python3
"""Contract tests for the Shrike GPIO23 pulse harness."""

from __future__ import annotations

import os
from pathlib import Path
import pty
import signal
import stat
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts/hil/shrike-gpio23-pulse.sh"


MOCK_SIGROK = r'''#!/usr/bin/env python3
import os
import pathlib
import sys
import time

event_log = pathlib.Path(os.environ["EVENT_LOG"])
mode = os.environ.get("SIGROK_MODE", "data")
if "-i" in sys.argv:
    print("; mock csv", flush=True)
    print("0,0,0", flush=True)
    raise SystemExit(0)
output = pathlib.Path(sys.argv[sys.argv.index("-o") + 1])
output.write_bytes(b"mock capture\n")
if mode == "fail":
    print("analyzer failed", file=sys.stderr, flush=True)
    raise SystemExit(1)
if mode == "header":
    print("Received SR_DF_HEADER", flush=True)
else:
    print("Received SR_DF_LOGIC", flush=True)
with event_log.open("a", encoding="utf-8") as stream:
    stream.write("SIGROK_" + ("HEADER" if mode == "header" else "LOGIC") + "\n")
    stream.flush()
time.sleep(4)
'''


MOCK_MPREMOTE = r'''#!/usr/bin/env python3
import os
import pathlib
import sys

log = pathlib.Path(os.environ["MPREMOTE_LOG"])
event_log = pathlib.Path(os.environ["EVENT_LOG"])
code = sys.argv[sys.argv.index("exec") + 1] if "exec" in sys.argv else ""
with log.open("a", encoding="utf-8") as stream:
    stream.write(code.replace("\n", "\\n") + "\n")
    stream.flush()
with event_log.open("a", encoding="utf-8") as stream:
    stream.write("MPREMOTE_" + ("PULSE" if "MULTIPULSE_START" in code else "SETUP") + "\n")
    stream.flush()
'''


MOCK_SLEEP = "#!/bin/sh\nexit 0\n"


class ShrikeGpio23PulseTests(unittest.TestCase):
    def run_harness(self, mode: str, uart: bytes, timeout: float = 12.0) -> tuple[str, str, str]:
        with tempfile.TemporaryDirectory(prefix="shrike-gpio23-test-") as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name, source in (("sigrok-cli", MOCK_SIGROK), ("mpremote", MOCK_MPREMOTE), ("sleep", MOCK_SLEEP)):
                path = bin_dir / name
                path.write_text(source, encoding="utf-8")
                path.chmod(path.stat().st_mode | stat.S_IXUSR)
            run_dir = root / "run"
            event_log = root / "events.log"
            mpremote_log = root / "mpremote.log"
            master, slave = pty.openpty()
            slave_name = os.ttyname(slave)
            os.close(slave)
            shrike_path = root / "shrike-uart"
            shrike_path.write_bytes(b"")

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_dir}:{environment['PATH']}",
                    "MPREMOTE": str(bin_dir / "mpremote"),
                    "PI_UART": slave_name,
                    "SHRIKE_UART": str(shrike_path),
                    "RUN_DIR": str(run_dir),
                    "EVENT_LOG": str(event_log),
                    "MPREMOTE_LOG": str(mpremote_log),
                    "SIGROK_MODE": mode,
                    "LOGIC_CONN": "fx2lafw",
                    "READY_TIMEOUT": "1",
                    "ANALYZER_READY_TIMEOUT": "1",
                    "UART_SECONDS": "10",
                    "PULSE_COUNT": "2",
                    "PULSE_HIGH_MS": "20",
                    "PULSE_LOW_MS": "20",
                    "ACTUATORS_MOTORS_DISCONNECTED": "YES",
                }
            )
            process = subprocess.Popen(
                [str(HARNESS)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )

            def feed_uart() -> None:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not list(run_dir.glob("*uart.log")):
                    time.sleep(0.01)
                os.write(master, uart)

            feeder = threading.Thread(target=feed_uart, daemon=True)
            feeder.start()
            try:
                output, _ = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
            finally:
                os.close(master)
            return (
                output,
                mpremote_log.read_text(encoding="utf-8") if mpremote_log.exists() else "",
                event_log.read_text(encoding="utf-8") if event_log.exists() else "",
            )

    def test_missing_signed_marker_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "data", b"PI5_BENCH_READY\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n"
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_panic_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "data",
            b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\npanic: boot failure\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_analyzer_failure_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "fail",
            b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_header_only_analyzer_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "header",
            b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_pulses_follow_live_data_and_cleanup_drives_both_low(self) -> None:
        _, commands, events = self.run_harness(
            "data",
            b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertIn("MULTIPULSE_START", commands)
        self.assertIn("MULTIPULSE_DONE", commands)
        self.assertLess(events.index("SIGROK_LOGIC"), events.index("MPREMOTE_PULSE"))
        cleanup = [line for line in commands.splitlines() if "GPIO_SAFE" in line]
        self.assertTrue(cleanup)
        self.assertIn("Pin(22, Pin.OUT, value=0)", cleanup[-1])
        self.assertIn("Pin(21, Pin.OUT, value=0)", cleanup[-1])


if __name__ == "__main__":
    unittest.main()
