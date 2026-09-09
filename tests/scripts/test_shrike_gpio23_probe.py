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

CONTAINMENT_UART = (
    b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\nPI5_BENCH_LOG_MODE deferred=true\n"
    b"PI5_PWM_READY carrier_request_hz=10000 requested_duty_percent=50 auto_rearm=false\n"
    b"PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false gpio12_ctrl=0x0000c080 gpio12_pad=0x00000000\n"
    b"PI5_PWM_CONTAINMENT_READY requested=4294967295 clamp_percent=90 reject_channel=3\n"
    b"PI5_GPIO_IRQ_PROVEN\nPI5_MA sample_id=1 monitor_ns=10\n"
    b"PI5_MC sample_id=1 ns=20 kind=pwm ch=1 val=90\n"
    b"PI5_PWM_REQUEST sample_id=1 chip=0 channel=1 requested=4294967295 code=0 range=5000 duty=4500\n"
    b"PI5_PWM_REQUEST sample_id=2 chip=0 channel=3 requested=4294967295 code=-1 range=5000 duty=4500\n"
)


def corpus_uart(count=5):
    prefix = CONTAINMENT_UART.split(b"PI5_GPIO_IRQ_PROVEN", 1)[0]
    text = prefix.decode() + "PI5_PWM_CORPUS_READY cases=5 requests_per_pulse=2\nPI5_GPIO_IRQ_PROVEN\n"
    for j in range(count):
        duty = (91, 100, 255, 65535, 4294967295)[j % 5]
        channel = (0, 3, 257, 65537, 4294967295)[j % 5]
        text += f"PI5_MA sample_id={2*j+1} monitor_ns=10\nPI5_MC sample_id={2*j+1} ns=20 kind=pwm ch=1 val=90\n"
        text += f"PI5_PWM_REQUEST sample_id={2*j+1} chip=0 channel=1 requested={duty} code=0 range=5000 duty=4500\n"
        text += f"PI5_PWM_REQUEST sample_id={2*j+2} chip=0 channel={channel} requested=4294967295 code=-1 range=5000 duty=4500\n"
    return (text + f"V04_ESTOP event_id=1 source=operator stage=assert ts_ns=300\nPI5_MB sample_id={2*count+1} ns=20\n").encode()


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
assert "-t" not in sys.argv
assert sys.argv[sys.argv.index("-l") + 1] == "4"
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
assert "resume" in sys.argv
code = sys.argv[sys.argv.index("exec") + 1] if "exec" in sys.argv else ""
compile(code, "stimulus", "exec")
with log.open("a", encoding="utf-8") as stream:
    stream.write(code.replace("\n", "\\n") + "\n")
    stream.flush()
with event_log.open("a", encoding="utf-8") as stream:
    stream.write("MPREMOTE_" + ("PULSE" if "MULTIPULSE_START" in code else "SETUP") + "\n")
    stream.flush()
if "MULTIPULSE_START" in code:
    print("MULTIPULSE_START\nMULTIPULSE_DONE 0 0")
elif "GPIO_SAFE" in code:
    print("GPIO_SAFE 0 0")
else:
    print("GPIO_READY 0 1")
'''


class ShrikeGpio23PulseTests(unittest.TestCase):
    def run_harness(self, mode: str, uart: bytes, output_mode: str = "gpio", pulse_count: str = "2", timeout: float = 12.0, high_ms: str = "100", low_ms: str = "100", samplerate: str = "24m", uart_seconds: str = "60") -> tuple[str, str, str]:
        with tempfile.TemporaryDirectory(prefix="shrike-gpio23-test-") as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name, source in (("sigrok-cli", MOCK_SIGROK), ("mpremote", MOCK_MPREMOTE)):
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
                    "OUTPUT_MODE": output_mode,
                    "LOGIC_CONN": "fx2lafw",
                    "READY_TIMEOUT": "1",
                    "ANALYZER_READY_TIMEOUT": "1",
                    "UART_SECONDS": uart_seconds,
                    "PULSE_COUNT": pulse_count,
                    "PULSE_HIGH_MS": high_ms,
                    "PULSE_LOW_MS": low_ms,
                    "SAMPLERATE": samplerate,
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
                    if process.poll() is not None:
                        return
                    time.sleep(0.01)
                if output_mode in ("pwm", "pwm-containment", "pwm-corpus") and b"PI5_GPIO_IRQ_PROVEN" in uart:
                    prefix, tail = uart.split(b"PI5_GPIO_IRQ_PROVEN", 1)
                    os.write(master, prefix)
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            return
                        if event_log.exists() and "MPREMOTE_PULSE" in event_log.read_text(encoding="utf-8"):
                            break
                        time.sleep(0.01)
                    os.write(master, b"PI5_GPIO_IRQ_PROVEN" + tail)
                else:
                    os.write(master, uart)

            feeder = threading.Thread(target=feed_uart, daemon=True)
            feeder.start()
            try:
                output, _ = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
            finally:
                feeder.join(timeout=4)
                os.close(master)
            return (
                f"RETURN_CODE={process.returncode}\n" + output,
                mpremote_log.read_text(encoding="utf-8") if mpremote_log.exists() else "",
                event_log.read_text(encoding="utf-8") if event_log.exists() else "",
            )

    def test_missing_signed_marker_never_dispatches_pulses(self) -> None:
        output, commands, _ = self.run_harness(
            "data", b"PI5_BENCH_READY\nPI5_BENCH_LOG_MODE deferred=true\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n"
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_panic_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "data",
            b"PI5_BENCH_READY\nPI5_BENCH_LOG_MODE deferred=true\nSIGNED_BPF_LOAD_OK\npanic: boot failure\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_analyzer_failure_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "fail",
            b"PI5_BENCH_READY\nPI5_BENCH_LOG_MODE deferred=true\nSIGNED_BPF_LOAD_OK\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_header_only_analyzer_never_dispatches_pulses(self) -> None:
        _, commands, _ = self.run_harness(
            "header",
            b"PI5_BENCH_READY\nPI5_BENCH_LOG_MODE deferred=true\nSIGNED_BPF_LOAD_OK\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_pulses_follow_live_data_and_cleanup_drives_both_low(self) -> None:
        _, commands, events = self.run_harness(
            "data",
            b"PI5_BENCH_READY\nPI5_BENCH_LOG_MODE deferred=true\nSIGNED_BPF_LOAD_OK\nPI5_V03B_READY output=gpio sample_ids=true auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n",
        )
        self.assertIn("MULTIPULSE_START", commands)
        self.assertIn("MULTIPULSE_DONE", commands)
        self.assertLess(events.index("SIGROK_LOGIC"), events.index("MPREMOTE_PULSE"))
        cleanup = [line for line in commands.splitlines() if "GPIO_SAFE" in line]
        self.assertTrue(cleanup)
        self.assertIn("Pin(22, Pin.OUT, value=0)", cleanup[-1])
        self.assertIn("Pin(21, Pin.OUT, value=0)", cleanup[-1])

    def test_pwm_requires_one_pulse_and_correlates_one_pair_without_rearm(self) -> None:
        output, commands, _ = self.run_harness(
            "data",
            b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\nPI5_BENCH_LOG_MODE deferred=true\n"
            b"PI5_PWM_READY carrier_request_hz=10000 requested_duty_percent=50 auto_rearm=false\n"
            b"PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false\n"
            b"PI5_GPIO_IRQ_PROVEN\nPI5_MA sample_id=7 monitor_ns=10\nPI5_MC sample_id=7 ns=20 kind=pwm ch=1 val=0\n",
            output_mode="pwm",
            pulse_count="1",
        )
        self.assertIn("MULTIPULSE_START", commands)
        self.assertIn("RETURN_CODE=0", output)
        self.assertIn("CAPTURE COMPLETE: PWM smoke software correlation only", output)
        self.assertNotIn("PI5_REFLEX_REARM", commands)

    def test_pwm_rejects_extra_response_or_rearm(self) -> None:
        base = (
            b"PI5_BENCH_READY\nSIGNED_BPF_LOAD_OK\nPI5_BENCH_LOG_MODE deferred=true\n"
            b"PI5_PWM_READY carrier_request_hz=10000 requested_duty_percent=50 auto_rearm=false\n"
            b"PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false\n"
            b"PI5_GPIO_IRQ_PROVEN\nPI5_MA sample_id=7 monitor_ns=10\nPI5_MC sample_id=7 ns=20 kind=pwm ch=1 val=0\n"
        )
        for extra in (
            b"PI5_MC sample_id=8 ns=20 kind=gpio ch=12 val=0\n",
            b"PI5_ESTOP_REARM sample_id=7 mode=pwm code=0\n",
        ):
            with self.subTest(extra=extra):
                output, _, _ = self.run_harness("data", base + extra, output_mode="pwm", pulse_count="1")
                self.assertIn("RETURN_CODE=1", output)
                self.assertIn("PWM software correlation failed", output)

    def test_pwm_rejects_multi_pulse_request(self) -> None:
        output, commands, _ = self.run_harness(
            "data", b"", output_mode="pwm", pulse_count="2"
        )
        self.assertIn("PULSE_COUNT=1", output)
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_containment_correlates_clamp_and_rejection_without_claiming_physical_pass(self) -> None:
        output, commands, events = self.run_harness(
            "data", CONTAINMENT_UART, output_mode="pwm-containment", pulse_count="1"
        )
        self.assertIn("RETURN_CODE=0", output)
        self.assertIn("containment software checks complete", output)
        self.assertIn("waveform review required", output)
        self.assertNotIn("PASS", output)
        self.assertLess(events.index("SIGROK_LOGIC"), events.index("MPREMOTE_PULSE"))
        self.assertIn("for _ in range(1)", commands)
        self.assertIn("GPIO_SAFE", commands)

    def test_containment_wrong_image_never_dispatches(self) -> None:
        marker = b"PI5_PWM_CONTAINMENT_READY requested=4294967295 clamp_percent=90 reject_channel=3\n"
        for uart in (
            CONTAINMENT_UART.replace(marker, b""),
            CONTAINMENT_UART.replace(b"clamp_percent=90", b"clamp_percent=50"),
            CONTAINMENT_UART.replace(b"reject_channel=3", b"reject_channel=30"),
            CONTAINMENT_UART.replace(b"gpio12_ctrl=0x0000c080", b"gpio12_ctrl=0x00000000"),
        ):
            with self.subTest(uart=uart):
                output, commands, _ = self.run_harness("data", uart, output_mode="pwm-containment", pulse_count="1")
                self.assertIn("RETURN_CODE=1", output)
                self.assertNotIn("MULTIPULSE_START", commands)
                self.assertIn("GPIO_SAFE", commands)

    def test_pwm_rejects_containment_image_before_dispatch(self) -> None:
        output, commands, _ = self.run_harness("data", CONTAINMENT_UART, output_mode="pwm", pulse_count="1")
        self.assertIn("RETURN_CODE=1", output)
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_containment_requires_bounded_timing_capture(self) -> None:
        for settings in ({"pulse_count": "2"}, {"samplerate": "1m"}, {"high_ms": "99"}, {"low_ms": "99"}):
            with self.subTest(settings=settings):
                options = {"pulse_count": "1", **settings}
                output, commands, _ = self.run_harness("data", b"", output_mode="pwm-containment", **options)
                self.assertIn("RETURN_CODE=1", output)
                self.assertEqual(commands, "")

    def test_containment_rejects_wrong_results_and_extra_or_mismatched_samples(self) -> None:
        for uart in (
            CONTAINMENT_UART.replace(b"code=-1 range", b"code=0 range"),
            CONTAINMENT_UART.replace(b"duty=4500", b"duty=4999"),
            CONTAINMENT_UART.replace(b"PI5_PWM_REQUEST sample_id=2", b"PI5_PWM_REQUEST sample_id=3"),
            CONTAINMENT_UART.replace(b"kind=pwm ch=1 val=90", b"kind=pwm ch=1 val=0"),
            CONTAINMENT_UART.replace(b"PI5_MA sample_id=1", b"PI5_MA sample_id=2"),
            CONTAINMENT_UART + b"PI5_PWM_REQUEST sample_id=3 chip=0 channel=1 requested=4294967295 code=0 range=5000 duty=4500\n",
            CONTAINMENT_UART + b"PI5_MA sample_id=2 monitor_ns=30\n",
            CONTAINMENT_UART + b"PI5_MC sample_id=2 ns=30 kind=pwm ch=1 val=90\n",
            CONTAINMENT_UART + b"PI5_GPIO_IRQ_PROVEN\n",
            CONTAINMENT_UART + b"PI5_ESTOP_REARM sample_id=1 mode=pwm code=0\n",
        ):
            with self.subTest(uart=uart):
                output, commands, _ = self.run_harness("data", uart, output_mode="pwm-containment", pulse_count="1")
                self.assertIn("MULTIPULSE_START", commands)
                self.assertIn("RETURN_CODE=1", output)
                self.assertIn("containment software correlation failed", output)

    def test_corpus_correlates_all_requests_and_rejects_missing_request(self):
        uart = corpus_uart()
        output, commands, _ = self.run_harness("data", uart, output_mode="pwm-corpus", pulse_count="5")
        self.assertIn("RETURN_CODE=0", output)
        self.assertIn("waveform review required", output)
        self.assertIn("for _ in range(5)", commands)
        bad = b"\n".join(line for line in uart.split(b"\n") if not line.startswith(b"PI5_PWM_REQUEST sample_id=8 "))
        output, _, _ = self.run_harness("data", bad, output_mode="pwm-corpus", pulse_count="5")
        self.assertIn("RETURN_CODE=1", output)
        self.assertIn("corpus software correlation failed", output)

    def test_corpus_requires_matching_image_and_bounded_count_before_stimulus(self):
        for uart, count in ((CONTAINMENT_UART, "5"), (corpus_uart(), "1"), (corpus_uart(), "505")):
            output, commands, _ = self.run_harness("data", uart, output_mode="pwm-corpus", pulse_count=count)
            self.assertIn("RETURN_CODE=1", output)
            self.assertNotIn("MULTIPULSE_START", commands)
        output, commands, _ = self.run_harness("data", corpus_uart(), output_mode="pwm-containment", pulse_count="1")
        self.assertIn("RETURN_CODE=1", output)
        self.assertNotIn("MULTIPULSE_START", commands)

    def test_single_boot_thousand_requests_at_six_mhz(self):
        output, commands, _ = self.run_harness(
            "data", corpus_uart(500), output_mode="pwm-corpus", pulse_count="500",
            samplerate="6m", high_ms="100", low_ms="400", uart_seconds="600")
        self.assertIn("RETURN_CODE=0", output)
        self.assertIn("for _ in range(500)", commands)
        self.assertIn("waveform review required", output)

    def test_long_run_rejects_short_uart_window_before_stimulus(self):
        output, commands, _ = self.run_harness(
            "data", b"", output_mode="pwm-corpus", pulse_count="500",
            samplerate="6m", high_ms="100", low_ms="400", uart_seconds="60")
        self.assertIn("UART_SECONDS must cover", output)
        self.assertNotIn("MULTIPULSE_START", commands)


if __name__ == "__main__":
    unittest.main()
