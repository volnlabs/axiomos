#!/usr/bin/env python3
"""Offline, unloaded PWM containment check: D0=GPIO23, D1=GPIO12, 24 MHz by default.

By default, requires one sensor pulse: 50% baseline -> UINT_MAX clamped to 90% -> invalid
channel rejected with 90% retained -> final LOW. The 1 ms settling allowance
is functional, not a latency gate. D0 does not capture the e-stop input;
this reducer cannot measure physical e-stop latency or establish WCET.
The matching analyzer log must confirm acquisition completion (SR_DF_END).
--corpus --count N repeats all five deterministic request cases (N=5..500,
a multiple of five), retaining 90% through every subsequent sensor pulse.
--samplerate 6m reduces transport bandwidth for long functional corpus captures.
"""
import argparse
from bisect import bisect_left, bisect_right
import json
from pathlib import Path
import re
import runpy
import zipfile

_CAPTURE = runpy.run_path(str(Path(__file__).with_name("v03d-reduce.py")))
Edges = _CAPTURE["Edges"]
RATE = _CAPTURE["SAMPLE_RATE_HZ"]
RETAIN = RATE // 100  # At least 10 ms after the rejected request.
FINAL_LOW = RATE // 10
TOLERANCE = 2  # Logic-analyzer sample quantization, not a calibrated clock.
DUTIES = (91, 100, 255, 65535, 4294967295)
CHANNELS = (0, 3, 257, 65537, 4294967295)


def read_capture(path, rate_hz=RATE):
    edges = _CAPTURE["read_capture"](str(path), rate_hz)
    # Reuse the validated capture layout; Edges does not retain total length.
    with zipfile.ZipFile(path) as archive:
        metadata = _CAPTURE["_srzip_metadata"](archive.read("metadata").decode())
        base = metadata["capturefile"]
        samples = sum(info.file_size for info in archive.infolist()
                      if info.filename == base or
                      (info.filename.startswith(base + "-") and
                       info.filename[len(base) + 1:].isdigit()))
    return edges, samples


def validate_uart(text, count=1, corpus=False):
    if (corpus and not (0 < count <= 500 and count % 5 == 0)) or (not corpus and count != 1):
        return ["count must be 1 normally, or a positive multiple of 5 <=500 for corpus"]
    errors = []
    if text.count("PI5_GPIO_IRQ_PROVEN") != 1:
        errors.append("UART needs exactly one GPIO IRQ route proof")
    expected = []
    for j in range(count):
        duty = DUTIES[j % 5] if corpus else 4294967295
        channel = CHANNELS[j % 5] if corpus else 3
        expected.extend([
            f"sample_id={2*j+1} chip=0 channel=1 requested={duty} code=0 range=5000 duty=4500",
            f"sample_id={2*j+2} chip=0 channel={channel} requested=4294967295 code=-1 range=5000 duty=4500",
        ])
    records = re.findall(r"PI5_PWM_REQUEST\b([^\r\n]*)", text)
    if [record.strip() for record in records] != expected:
        errors.append(f"UART needs exactly {2*count} ordered requests matching the expected clamp/rejection cases")
    ma = re.findall(r"PI5_MA\b([^\r\n]*)", text)
    if len(ma) != count or any(not re.fullmatch(fr" sample_id={2*j+1} monitor_ns=\d+", record)
                                               for j, record in enumerate(ma)):
        errors.append(f"UART needs exactly {count} M-A records with ordered odd sample IDs")
    mc = re.findall(r"PI5_MC\b([^\r\n]*)", text)
    if len(mc) != count or any(not re.fullmatch(fr" sample_id={2*j+1} ns=\d+ kind=pwm ch=1 val=90", record)
                                               for j, record in enumerate(mc)):
        errors.append(f"UART needs exactly {count} M-C records with ordered odd sample IDs, PWM ch=1 val=90")
    corpus_ready = "PI5_PWM_CORPUS_READY cases=5 requests_per_pulse=2"
    if corpus:
        if text.count("PI5_PWM_CORPUS_READY") != 1 or corpus_ready not in text:
            errors.append("UART needs exactly one five-case PWM corpus readiness marker")
        elif records and text.find(corpus_ready) > text.find("PI5_PWM_REQUEST"):
            errors.append("UART requests precede corpus readiness")
    elif "PI5_PWM_CORPUS_READY" in text:
        errors.append("corpus UART requires --corpus")
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
    if len(estop) != 1 or len(mb) != 1 or not re.fullmatch(fr" sample_id={2*count+1} ns=\d+", mb[0]):
        errors.append(f"UART needs one final operator e-stop assertion and M-B sample {2*count+1}")
    elif records and not text.rfind("PI5_PWM_REQUEST") < text.find(estop[0]) < text.find("PI5_MB"):
        errors.append("UART final operator stop must follow both PWM requests")
    if "PI5_PWM_REQUEST" in text and re.search(r"V04_ESTOP.*stage=release", text[text.find("PI5_PWM_REQUEST"):]):
        errors.append("UART e-stop released after PWM requests")
    return errors


def validate_waveform(edges, samples, count=1, rate_hz=RATE):
    if rate_hz not in (6_000_000, RATE):
        return {}, ["unsupported sample rate"]
    period_min, period_max = rate_hz * 95 // 1_000_000, rate_hz * 105 // 1_000_000
    settle, retain, final_low_min = rate_hz // 1000, rate_hz // 100, rate_hz // 10
    errors = []
    summary = {"sample_rate_hz_nominal": rate_hz, "samples": samples}
    if edges.initial not in ((0, 0), (0, 1)) or edges.final != (0, 0):
        errors.append("D0 must begin/end LOW and D1 must end LOW")
    if len(edges.d0_rises) != count or len(edges.d0_falls) != count:
        errors.append(f"D0 must have exactly {count} rises and {count} falls (GPIO23 sensor probe)")
        return summary, errors
    previous = 0
    for rise, fall in zip(edges.d0_rises, edges.d0_falls):
        if not previous < rise < fall < samples:
            errors.append("D0 sensor pulses must alternate strictly within capture")
            return summary, errors
        previous = fall
    rise, fall = edges.d0_rises[0], edges.d0_falls[0]
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
    clamped = [cycle for cycle in cycles if cycle[0] >= rise + settle and cycle[2] <= fall]
    retained_counts, retention_ms = [], []
    boundaries = edges.d0_rises[1:] + [events[-1][0]]
    for j, (rejected, boundary) in enumerate(zip(edges.d0_falls, boundaries)):
        first = bisect_left(cycles, rejected, key=lambda cycle: cycle[0])
        last = bisect_right(cycles, boundary, key=lambda cycle: cycle[2]) - 1
        duration = cycles[last][2] - cycles[first][0] if first <= last else 0
        retained_counts.append(max(0, last - first + 1))
        retention_ms.append(duration * 1000 / rate_hz)
        if duration < retain:
            errors.append(f"pulse {j+1}: rejected request must retain 90% carrier for >=10 ms before next rise/stop")
    if len(baseline) < 10:
        errors.append("need >=10 complete 50% carrier cycles before D0 rises")
    if len(clamped) < 10:
        errors.append("need >=10 complete 90% carrier cycles after settling and before D0 falls")
    for start, high_end, end in cycles:
        period, high = end - start, high_end - start
        if not period_min <= period <= period_max:
            errors.append(f"carrier period outside 95..105 us at sample {start}")
            break
        if high * 10 > period * 9 + TOLERANCE * 10:
            errors.append(f"PWM exceeds 90% envelope at sample {start}")
            break
        expected = 50 if end <= rise else 90 if start >= rise + settle else None
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
    if steady_start is None or steady_start > rise + settle:
        errors.append("90% carrier not established within the 1 ms functional settling allowance")
    stop = events[-1][0]
    final_low = samples - stop
    if final_low < final_low_min:
        errors.append("final D1 LOW must last >=100 ms")
    if stop <= edges.d0_falls[-1] + retain:
        errors.append("final stop occurred before >=10 ms rejection retention")
    if baseline and events[0][0] > (baseline[0][2] - baseline[0][0]) / 2 + TOLERANCE:
        errors.append("initial carrier is absent or initial partial pulse exceeds 50%")
    if cycles and len(events) >= 2:
        last_high = stop - events[-2][0]
        last_period = cycles[-1][2] - cycles[-1][0]
        if last_high * 10 > last_period * 9 + TOLERANCE * 10:
            errors.append("final high pulse exceeds 90% envelope")
    summary.update(baseline_cycles=len(baseline), clamped_cycles=len(clamped),
                   retained_cycles=sum(retained_counts), retention_ms_per_pulse=retention_ms,
                   pulses=count, final_low_ms=final_low * 1000 / rate_hz,
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
    # Corpus fixtures spell out the five cases independently of validator constants.
    count = 5
    corpus_uart = uart.split("PI5_MA")[0] + "PI5_PWM_CORPUS_READY cases=5 requests_per_pulse=2\n"
    for j, (duty, channel) in enumerate(zip((91, 100, 255, 65535, 4294967295),
                                           (0, 3, 257, 65537, 4294967295))):
        corpus_uart += (f"PI5_MA sample_id={2*j+1} monitor_ns=40\n"
                       f"PI5_MC sample_id={2*j+1} ns=100 kind=pwm ch=1 val=90\n"
                       f"PI5_PWM_REQUEST sample_id={2*j+1} chip=0 channel=1 requested={duty} code=0 range=5000 duty=4500\n"
                       f"PI5_PWM_REQUEST sample_id={2*j+2} chip=0 channel={channel} requested=4294967295 code=-1 range=5000 duty=4500\n")
    corpus_uart += "V04_ESTOP event_id=1 source=operator stage=assert ts_ns=1000000\nPI5_MB sample_id=11 ns=200\n"
    assert not validate_uart(corpus_uart, count, True), validate_uart(corpus_uart, count, True)
    prefix, body = corpus_uart.split("PI5_MA", 1)
    body, ending = ("PI5_MA" + body).split("V04_ESTOP", 1)
    repeated_uart = (prefix + body + re.sub(r"sample_id=(\d+)",
                     lambda match: f"sample_id={int(match[1]) + 10}", body) +
                     "V04_ESTOP" + ending.replace("sample_id=11", "sample_id=21"))
    assert not validate_uart(repeated_uart, 10, True), "rejected repeated five-case matrix"
    for corrupt in (corpus_uart.replace("sample_id=6", "sample_id=4"),
                    corpus_uart.replace("channel=257", "channel=3"),
                    corpus_uart.replace("requested=91 ", "requested=100 "),
                    corpus_uart.replace("PI5_MA sample_id=5 monitor_ns=40\n", ""),
                    corpus_uart.replace("PI5_PWM_CORPUS_READY", "MISSING_CORPUS_MARKER"),
                    corpus_uart + "PI5_PWM_REQUEST sample_id=10 chip=0 channel=4294967295 requested=4294967295 code=-1 range=5000 duty=4500\n"):
        assert validate_uart(corrupt, count, True), "accepted corrupted corpus IDs/cases"
    for bad_count in (0, 1, 6, 505):
        assert validate_uart(corpus_uart, bad_count, True), "accepted invalid corpus count"
    assert validate_uart(corpus_uart), "accepted corpus as ordinary smoke"
    corpus = fixture()
    corpus.d0_rises = [(30 + j * 210) * period for j in range(count)]
    corpus.d0_falls = [(100 + j * 210) * period for j in range(count)]
    corpus.d1_rises = [120 + i * period for i in range(count * 210 + 30)]
    corpus.d1_falls = [start + (1200 if i < 30 else 2160) for i, start in enumerate(corpus.d1_rises)]
    corpus_samples = corpus.d1_falls[-1] + FINAL_LOW
    assert not validate_waveform(corpus, corpus_samples, count)[1], validate_waveform(corpus, corpus_samples, count)
    for mode in ("missing pulse", "duplicate pulse", "short retention", "rejection drop", "discontinuity", "100% duty"):
        broken = copy.deepcopy(corpus)
        if mode == "missing pulse":
            broken.d0_rises.pop()
            broken.d0_falls.pop()
        elif mode == "duplicate pulse":
            broken.d0_rises[2] = broken.d0_rises[1]
            broken.d0_falls[2] = broken.d0_falls[1]
        elif mode == "short retention":
            broken.d0_falls[1] = broken.d0_rises[2] - RETAIN // 2
        elif mode == "rejection drop":
            broken.d1_falls[350] = broken.d1_rises[350] + 1200
        elif mode == "discontinuity":
            del broken.d1_rises[350]
            del broken.d1_falls[350]
        else:
            del broken.d1_rises[350:390]
            del broken.d1_falls[349:389]
        assert validate_waveform(broken, corpus_samples, count)[1], f"accepted corpus {mode}"
    # A 6 MHz capture has 600 samples/carrier cycle: the same physical checks
    # still reject a 91% output, despite the two-sample quantization allowance.
    six = copy.deepcopy(corpus)
    for field in ("d0_rises", "d0_falls", "d1_rises", "d1_falls"):
        setattr(six, field, [value // 4 for value in getattr(six, field)])
    assert not validate_waveform(six, corpus_samples // 4, 5, rate_hz=6_000_000)[1]
    unsafe = copy.deepcopy(six)
    unsafe.d1_falls[350] = unsafe.d1_rises[350] + 546  # 91% of 600
    assert validate_waveform(unsafe, corpus_samples // 4, 5, rate_hz=6_000_000)[1]
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
        # Exercise corpus CLI/count validation through an actual generated capture.
        raw = bytearray(corpus_samples)
        for start, end in zip(corpus.d1_rises, corpus.d1_falls):
            raw[start:end] = b"\x02" * (end - start)
        for start, end in zip(corpus.d0_rises, corpus.d0_falls):
            raw[start:end] = bytes(value | 1 for value in raw[start:end])
        _CAPTURE["_write_test_srzip"](str(path), bytes(raw))
        uart_path.write_text(corpus_uart)
        analyzer_path.write_text("Received SR_DF_END\n")
        complete = subprocess.run(command + ["--corpus", "--count", "5"], text=True, capture_output=True)
        assert complete.returncode == 0, complete.stdout + complete.stderr
        assert json.loads(complete.stdout)["requests"] == 10
        _CAPTURE["_write_test_srzip"](str(path), bytes(raw[::4]), samplerate="6 MHz")
        parsed_six, samples_six = read_capture(path, 6_000_000)
        assert not validate_waveform(parsed_six, samples_six, 5, 6_000_000)[1]
        try:
            _CAPTURE["read_capture"](str(path))
        except RuntimeError as error:
            assert "24 MHz" in str(error)
        else:
            raise AssertionError("e-stop decoder silently accepted 6 MHz")
        six_cli = subprocess.run(command + ["--corpus", "--count", "5", "--samplerate", "6m"],
                                 text=True, capture_output=True)
        assert six_cli.returncode == 0, six_cli.stdout + six_cli.stderr
        assert json.loads(six_cli.stdout)["sample_rate_hz_nominal"] == 6_000_000
        wrong_rate = subprocess.run(command + ["--corpus", "--count", "5"], capture_output=True)
        assert wrong_rate.returncode == 1, "silently interpreted 6 MHz as 24 MHz"
        _CAPTURE["_write_test_srzip"](str(path), bytes(raw))
        for arguments in (["--count", "5"], ["--corpus", "--count", "6"], ["--corpus", "--count", "505"]):
            assert subprocess.run(command + arguments, capture_output=True).returncode == 2
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
    parser.add_argument("capture", nargs="?", help="sigrok .sr capture at the declared --samplerate")
    parser.add_argument("--uart", type=Path, help="matching complete UART log")
    parser.add_argument("--analyzer", type=Path, help="matching analyzer log with Received SR_DF_END")
    parser.add_argument("--samplerate", choices=("24m", "6m"), default="24m", help="expected capture rate (6m is functional corpus only)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable result")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--corpus", action="store_true", help="validate all five deterministic cases repeatedly")
    parser.add_argument("--count", type=int, default=1, help="pulse count: 1 normally; corpus multiple of 5, <=500")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if (args.corpus and not (0 < args.count <= 500 and args.count % 5 == 0)) or (not args.corpus and args.count != 1):
        parser.error("--count must be 1 normally, or a positive multiple of 5 <=500 with --corpus")
    if args.samplerate == "6m" and not args.corpus:
        parser.error("6m is supported only for --corpus")
    if not args.capture or not args.uart or not args.analyzer:
        parser.error("capture.sr, --uart, and --analyzer are required")
    result = {"scope": "offline unloaded PWM functional containment; no WCET or physical e-stop latency"}
    try:
        rate_hz = 6_000_000 if args.samplerate == "6m" else RATE
        edges, samples = read_capture(args.capture, rate_hz)
        summary, errors = validate_waveform(edges, samples, args.count, rate_hz)
        errors += validate_uart(args.uart.read_text(encoding="utf-8", errors="replace"), args.count, args.corpus)
        complete = "Received SR_DF_END" in args.analyzer.read_text(encoding="utf-8", errors="replace")
        if not complete:
            errors.append("analyzer log lacks Received SR_DF_END acquisition completion")
        result.update(summary, acquisition_complete=complete, corpus=args.corpus, requests=2*args.count)
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
