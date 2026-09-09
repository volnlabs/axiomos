#!/usr/bin/env python3
"""Offline, unloaded PWM containment check: D0=GPIO23, D1=GPIO12, 24 MHz.

Requires one sensor pulse: 50% baseline -> UINT_MAX clamped to 90% -> invalid
channel rejected with 90% retained -> final LOW. The 1 ms settling allowance
is functional, not a latency gate. D0 does not capture the e-stop input;
this reducer cannot measure physical e-stop latency or establish WCET.
The matching analyzer log must confirm acquisition completion (SR_DF_END).
"""
import argparse
import json
from pathlib import Path
import re
import runpy
import zipfile

_CAPTURE = runpy.run_path(str(Path(__file__).with_name("v03d-reduce.py")))
Edges = _CAPTURE["Edges"]
RATE = _CAPTURE["SAMPLE_RATE_HZ"]
PERIOD_MIN, PERIOD_MAX = 2280, 2520  # 95..105 us at nominal 24 MHz.
SETTLE = RATE // 1000  # Functional allowance, never a latency/WCET claim.
RETAIN = RATE // 100  # At least 10 ms after the rejected request.
FINAL_LOW = RATE // 10
TOLERANCE = 2  # Logic-analyzer sample quantization, not a calibrated clock.


def read_capture(path):
    edges = _CAPTURE["read_capture"](str(path))
    # Reuse the validated capture layout; Edges does not retain total length.
    with zipfile.ZipFile(path) as archive:
        metadata = _CAPTURE["_srzip_metadata"](archive.read("metadata").decode())
        base = metadata["capturefile"]
        samples = sum(info.file_size for info in archive.infolist()
                      if info.filename == base or
                      (info.filename.startswith(base + "-") and
                       info.filename[len(base) + 1:].isdigit()))
    return edges, samples


def validate_uart(text):
    errors = []
    if text.count("PI5_GPIO_IRQ_PROVEN") != 1:
        errors.append("UART needs exactly one GPIO IRQ route proof")
    expected = [
        "sample_id=1 chip=0 channel=1 requested=4294967295 code=0 range=5000 duty=4500",
        "sample_id=2 chip=0 channel=3 requested=4294967295 code=-1 range=5000 duty=4500",
    ]
    records = re.findall(r"PI5_PWM_REQUEST\b([^\r\n]*)", text)
    if [record.strip() for record in records] != expected:
        errors.append("UART needs exactly sample 1 clamp and sample 2 invalid-channel rejection requests")
    ma = re.findall(r"PI5_MA\b([^\r\n]*)", text)
    if len(ma) != 1 or not re.fullmatch(r" sample_id=1 monitor_ns=\d+", ma[0]):
        errors.append("UART needs exactly one M-A record for sample 1")
    mc = re.findall(r"PI5_MC\b([^\r\n]*)", text)
    if len(mc) != 1 or not re.fullmatch(r" sample_id=1 ns=\d+ kind=pwm ch=1 val=90", mc[0]):
        errors.append("UART needs exactly one M-C record for sample 1, PWM ch=1 val=90")
    ready = "PI5_PWM_CONTAINMENT_READY requested=4294967295 clamp_percent=90 reject_channel=3"
    arm = "PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false"
    if (text.count("PI5_PWM_CONTAINMENT_READY") != 1 or ready not in text or
            text.count("PI5_OUT_ARM") != 1 or arm not in text):
        errors.append("UART needs containment readiness and exactly one successful initial PWM arm")
    if re.search(r"PI5_(?:REFLEX_REARM|ESTOP_REARM|BENCH_FAIL|BENCH_LOG_LOSS)|"
                 r"panic|fatal|watchdog|SIGNED_BPF_(?:INPUT_MISSING|INPUT_INVALID|LOAD_REJECTED)",
                 text, re.I):
        errors.append("UART contains re-arm, kernel failure, or log-loss marker")
    if records and (text.find(arm) > text.find("PI5_PWM_REQUEST") or
                    text.find(ready) > text.find("PI5_PWM_REQUEST")):
        errors.append("UART requests precede initial arm/readiness")
    estop = re.findall(r"V04_ESTOP event_id=\d+ source=operator stage=assert ts_ns=\d+", text)
    mb = re.findall(r"PI5_MB\b([^\r\n]*)", text)
    if len(estop) != 1 or len(mb) != 1 or not re.fullmatch(r" sample_id=3 ns=\d+", mb[0]):
        errors.append("UART needs one final operator e-stop assertion and M-B sample 3")
    elif records and not text.rfind("PI5_PWM_REQUEST") < text.find(estop[0]) < text.find("PI5_MB"):
        errors.append("UART final operator stop must follow both PWM requests")
    if "PI5_PWM_REQUEST" in text and re.search(r"V04_ESTOP.*stage=release", text[text.find("PI5_PWM_REQUEST"):]):
        errors.append("UART e-stop released after PWM requests")
    return errors


def validate_waveform(edges, samples):
    errors = []
    summary = {"sample_rate_hz_nominal": RATE, "samples": samples}
    if edges.initial not in ((0, 0), (0, 1)) or edges.final != (0, 0):
        errors.append("D0 must begin/end LOW and D1 must end LOW")
    if len(edges.d0_rises) != 1 or len(edges.d0_falls) != 1:
        errors.append("D0 must have exactly one rise and one fall (GPIO23 sensor probe)")
        return summary, errors
    rise, fall = edges.d0_rises[0], edges.d0_falls[0]
    if not 0 < rise < fall < samples:
        errors.append("D0 sensor pulse is out of order or outside capture")
        return summary, errors
    events = sorted([(sample, 1) for sample in edges.d1_rises] +
                    [(sample, 0) for sample in edges.d1_falls])
    if not events or edges.initial is None:
        errors.append("D1 carrier is missing")
        return summary, errors
    level = edges.initial[1]
    previous = 0
    for sample, new_level in events:
        if not previous < sample < samples or new_level == level:
            errors.append("D1 edges must alternate strictly within capture")
            return summary, errors
        previous, level = sample, new_level
    if level != 0 or edges.final != (0, 0):
        errors.append("D1 final state is not LOW")
        return summary, errors
    # Each complete cycle is rise -> fall -> rise. The final high pulse may
    # be shortened by the stop, but cannot exceed the preceding 90% envelope.
    cycles = [(events[i][0], events[i + 1][0], events[i + 2][0])
              for i in range(len(events) - 2) if events[i][1] == 1]
    baseline = [cycle for cycle in cycles if cycle[2] <= rise]
    clamped = [cycle for cycle in cycles if cycle[0] >= rise + SETTLE and cycle[2] <= fall]
    retained = [cycle for cycle in cycles if cycle[0] >= fall]
    if len(baseline) < 10:
        errors.append("need >=10 complete 50% carrier cycles before D0 rises")
    if len(clamped) < 10:
        errors.append("need >=10 complete 90% carrier cycles after settling and before D0 falls")
    if not retained or retained[-1][2] - retained[0][0] < RETAIN:
        errors.append("rejected request must retain 90% carrier for >=10 ms")
    for start, high_end, end in cycles:
        period, high = end - start, high_end - start
        if not PERIOD_MIN <= period <= PERIOD_MAX:
            errors.append(f"carrier period outside 95..105 us at sample {start}")
            break
        if high * 10 > period * 9 + TOLERANCE * 10:
            errors.append(f"PWM exceeds 90% envelope at sample {start}")
            break
        expected = 50 if end <= rise else 90 if start >= rise + SETTLE else None
        if expected is not None and abs(high * 100 - period * expected) > TOLERANCE * 100:
            errors.append(f"PWM must be {expected}% at sample {start}")
            break
    # Locate the first cycle of the final uninterrupted 90% run. A cycle
    # beginning after the allowance cannot rescue a delayed response.
    steady_start = None
    for start, high_end, end in reversed(cycles):
        if abs((high_end - start) * 100 - (end - start) * 90) > TOLERANCE * 100:
            break
        steady_start = start
    if steady_start is None or steady_start > rise + SETTLE:
        errors.append("90% carrier not established within the 1 ms functional settling allowance")
    stop = events[-1][0]
    final_low = samples - stop
    if final_low < FINAL_LOW:
        errors.append("final D1 LOW must last >=100 ms")
    if stop <= fall + RETAIN:
        errors.append("final stop occurred before >=10 ms rejection retention")
    if baseline and events[0][0] > (baseline[0][2] - baseline[0][0]) / 2 + TOLERANCE:
        errors.append("initial carrier is absent or initial partial pulse exceeds 50%")
    if cycles and len(events) >= 2:
        last_high = stop - events[-2][0]
        last_period = cycles[-1][2] - cycles[-1][0]
        if last_high * 10 > last_period * 9 + TOLERANCE * 10:
            errors.append("final high pulse exceeds 90% envelope")
    summary.update(baseline_cycles=len(baseline), clamped_cycles=len(clamped),
                   retained_cycles=len(retained), final_low_ms=final_low * 1000 / RATE,
                   sensor_rise_sample=rise, sensor_fall_sample=fall,
                   final_output_fall_sample=stop,
                   functional_settling_allowance_ms=1)
    return summary, errors


def self_test():
    """Synthetic edges only: these tests do not constitute physical evidence."""
    import copy
    import subprocess
    import sys
    import tempfile

    uart = "\n".join([
        "PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false",
        "PI5_PWM_CONTAINMENT_READY requested=4294967295 clamp_percent=90 reject_channel=3",
        "PI5_GPIO_IRQ_PROVEN pin=23 pending_before=0x00000001 pending_after=0x00000000",
        "PI5_MA sample_id=1 monitor_ns=40",
        "PI5_MC sample_id=1 ns=100 kind=pwm ch=1 val=90",
        "PI5_PWM_REQUEST sample_id=1 chip=0 channel=1 requested=4294967295 code=0 range=5000 duty=4500",
        "PI5_PWM_REQUEST sample_id=2 chip=0 channel=3 requested=4294967295 code=-1 range=5000 duty=4500",
        "V04_ESTOP event_id=1 source=operator stage=assert ts_ns=1000000",
        "PI5_MB sample_id=3 ns=200",
    ]) + "\n"
    period = 2400
    rise, fall = 30 * period, 100 * period
    def fixture(change=30, reject_duty=2160):
        starts = [120 + i * period for i in range(240)]
        falls = [start + (1200 if i < change else 2160 if start < fall else reject_duty)
                 for i, start in enumerate(starts)]
        return Edges([fall], [rise], falls, starts, (0, 0), (0, 0))
    valid = fixture()
    samples = valid.d1_falls[-1] + FINAL_LOW
    assert not validate_uart(uart), validate_uart(uart)
    assert not validate_waveform(valid, samples)[1], validate_waveform(valid, samples)
    cases = {}
    cases["missing carrier"] = Edges([fall], [rise], [], [], (0, 0), (0, 0))
    cases["wrong D0 probe"] = Edges([fall], [], valid.d1_falls, valid.d1_rises, (1, 0), (0, 0))
    cases["near 100% duty"] = fixture(reject_duty=period - 1)
    cases["100% duty"] = copy.deepcopy(valid)
    cases["100% duty"].d1_rises = valid.d1_rises[:101]
    cases["100% duty"].d1_falls = valid.d1_falls[:100] + [valid.d1_falls[-1]]
    cases["transition exceeds envelope"] = copy.deepcopy(valid)
    cases["transition exceeds envelope"].d1_falls[31] += 10
    cases["rejection changes output"] = fixture(reject_duty=1200)
    cases["delayed response"] = fixture(change=45)
    cases["just outside settling allowance"] = fixture(change=40)
    cases["final high"] = copy.deepcopy(valid)
    cases["final high"].final = (0, 1)
    cases["missing pulse"] = copy.deepcopy(valid)
    del cases["missing pulse"].d1_rises[150]
    del cases["missing pulse"].d1_falls[150]
    cases["extra D0 edge"] = copy.deepcopy(valid)
    cases["extra D0 edge"].d0_rises.append(fall + period)
    for label, edges in cases.items():
        assert validate_waveform(edges, samples)[1], f"accepted {label}"
    assert validate_waveform(valid, samples - 1)[1], "accepted short final LOW"
    shortened = copy.deepcopy(valid)
    shortened.d1_falls[-1] -= 100
    assert not validate_waveform(shortened, samples)[1], "rejected safe shortened final pulse"
    quantized = copy.deepcopy(valid)
    quantized.d1_falls = [sample + TOLERANCE for sample in quantized.d1_falls]
    assert not validate_waveform(quantized, samples + TOLERANCE)[1], "rejected 2-sample tolerance"
    for corrupt in (uart + uart, uart.replace("channel=3", "channel=2"),
                    uart.replace("code=-1", "code=0"), uart.replace("val=90", "val=0"),
                    uart + "PI5_BENCH_LOG_LOSS\n", uart + "PI5_REFLEX_REARM\n",
                    uart.replace("sample_id=1 monitor", "sample_id=2 monitor"),
                    uart.replace("PI5_GPIO_IRQ_PROVEN", "MISSING_ROUTE_PROOF"),
                    uart + "PI5_GPIO_IRQ_PROVEN\n",
                    uart.replace("PI5_MB sample_id=3", "PI5_MB sample_id=4"),
                    uart.replace("source=operator stage=assert", "source=operator stage=release")):
        assert validate_uart(corrupt), "accepted invalid UART"
    # Exercise the reused srzip reader and total-length accounting across chunks.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "capture.sr"
        raw = bytearray(samples)
        for start, end in zip(valid.d1_rises, valid.d1_falls):
            raw[start:end] = b"\x02" * (end - start)
        raw[rise:fall] = bytes(value | 1 for value in raw[rise:fall])
        _CAPTURE["_write_test_srzip"](str(path), b"", numbered_chunks=(bytes(raw[:rise]), bytes(raw[rise:])))
        parsed, count = read_capture(path)
        assert count == samples and not validate_waveform(parsed, count)[1]
        uart_path, analyzer_path = Path(tmp) / "uart.log", Path(tmp) / "analyzer.log"
        uart_path.write_text(uart)
        analyzer_path.write_text("Received SR_DF_LOGIC\nReceived SR_DF_END\n")
        command = [sys.executable, "-B", __file__, "--uart", str(uart_path),
                   "--analyzer", str(analyzer_path), "--json", str(path)]
        complete = subprocess.run(command, text=True, capture_output=True)
        assert complete.returncode == 0, complete.stdout + complete.stderr
        assert json.loads(complete.stdout)["verdict"] == "PASS"
        analyzer_path.write_text("Received SR_DF_LOGIC\n")
        incomplete = subprocess.run(command, text=True, capture_output=True)
        assert incomplete.returncode == 1, "accepted capture without SR_DF_END"
        assert any("SR_DF_END" in error for error in json.loads(incomplete.stdout)["errors"])
        _CAPTURE["_write_test_srzip"](str(path), bytes(raw), probes=("D1", "D0"))
        try:
            read_capture(path)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted swapped metadata probes")
    print("PASS: synthetic waveform, UART, and srzip containment self-tests")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="?", help="24 MHz sigrok .sr capture")
    parser.add_argument("--uart", type=Path, help="matching complete UART log")
    parser.add_argument("--analyzer", type=Path, help="matching analyzer log with Received SR_DF_END")
    parser.add_argument("--json", action="store_true", help="emit machine-readable result")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.capture or not args.uart or not args.analyzer:
        parser.error("capture.sr, --uart, and --analyzer are required")
    result = {"scope": "offline unloaded PWM functional containment; no WCET or physical e-stop latency"}
    try:
        edges, samples = read_capture(args.capture)
        summary, errors = validate_waveform(edges, samples)
        errors += validate_uart(args.uart.read_text(encoding="utf-8", errors="replace"))
        complete = "Received SR_DF_END" in args.analyzer.read_text(encoding="utf-8", errors="replace")
        if not complete:
            errors.append("analyzer log lacks Received SR_DF_END acquisition completion")
        result.update(summary, acquisition_complete=complete)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        errors = [str(exc)]
    result.update(verdict="FAIL" if errors else "PASS", errors=errors)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"VERDICT: {result['verdict']} ({result['scope']})")
        for error in errors:
            print(f"  {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
