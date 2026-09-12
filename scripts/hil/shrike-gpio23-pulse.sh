#!/usr/bin/env bash
# Unloaded GPIO reflex capture; physical waveform review is still required.
# Shrike GP22 -> 220 ohm -> Pi pin16/GPIO23, analyzer D0 (input1).
# Shrike GP21 -> 220 ohm -> Pi pin18/GPIO24 (active-low e-stop).
# Analyzer D1 (input2) -> Pi pin32/GPIO12. All grounds common.
# No motors/drivers/actuators or static GPIO24-to-3.3V jumper permitted.
# GPIO requires bench-reflex-rearm; PWM requires bench-pwm (or bench-pwm-containment).
# GP21 is released before boot for initial arming,
# then asserted in the pulse program's finally block and host cleanup.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$REPO/artifacts/runs/axiomos-hil-20260720T134903Z/03-gpio}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
SHRIKE_UART="${SHRIKE_UART:-/dev/serial/by-id/usb-SHRIKE_Board_in_Micropython_Mode_de65143857942625-if00}"
MPREMOTE="${MPREMOTE:-mpremote}"
OUTPUT_MODE="${OUTPUT_MODE:-gpio}"
LOGIC_CONN="${LOGIC_CONN:-fx2lafw}"
SAMPLERATE="${SAMPLERATE:-24m}"
UART_SECONDS="${UART_SECONDS:-600}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
ANALYZER_READY_TIMEOUT="${ANALYZER_READY_TIMEOUT:-10}"
PULSE_COUNT="${PULSE_COUNT:-5}"
PULSE_HIGH_MS="${PULSE_HIGH_MS:-800}"
PULSE_LOW_MS="${PULSE_LOW_MS:-800}"
CAPTURE_MARGIN_MS=5000

die() { echo "ABORT: $*" >&2; exit 1; }
[ "${ACTUATORS_MOTORS_DISCONNECTED:-}" = YES ] || die "disconnect motors, drivers and actuators; set ACTUATORS_MOTORS_DISCONNECTED=YES"
for value in "$PULSE_COUNT" "$PULSE_HIGH_MS" "$PULSE_LOW_MS" "$UART_SECONDS" "$READY_TIMEOUT" "$ANALYZER_READY_TIMEOUT"; do
    [[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] || die "counts and durations must be positive decimal integers <= 99999"
done
case "$SAMPLERATE" in
    1m) SAMPLES_PER_MS=1000 ;;
    24m) SAMPLES_PER_MS=24000 ;;
    6m) [ "$OUTPUT_MODE" = pwm-corpus ] || die "6m is supported only for PWM corpus"; SAMPLES_PER_MS=6000 ;;
    *) die "supported capture rates: 1m, 24m, or 6m (PWM corpus only)" ;;
esac
case "$OUTPUT_MODE" in
    gpio) ;;
    pwm) [ "$PULSE_COUNT" -eq 1 ] || die "OUTPUT_MODE=pwm requires PULSE_COUNT=1" ;;
    pwm-containment|pwm-corpus)
        if [ "$OUTPUT_MODE" = pwm-containment ]; then
            [ "$PULSE_COUNT" -eq 1 ] || die "OUTPUT_MODE=pwm-containment requires PULSE_COUNT=1"
        else
            [ "$PULSE_COUNT" -le 500 ] && [ "$((PULSE_COUNT % 5))" -eq 0 ] || die "PWM corpus requires PULSE_COUNT to be a multiple of 5 <=500"
        fi
        [[ "$SAMPLERATE" = 24m || ( "$OUTPUT_MODE" = pwm-corpus && "$SAMPLERATE" = 6m ) ]] || die "PWM containment requires 24m, or 6m for corpus"
        [ "$PULSE_HIGH_MS" -ge 100 ] && [ "$PULSE_LOW_MS" -ge 100 ] || die "PWM containment requires high and low durations >= 100ms"
        ;;
    *) die "OUTPUT_MODE must be gpio, pwm, pwm-containment or pwm-corpus" ;;
esac
CAPTURE_MS=$((PULSE_COUNT * (PULSE_HIGH_MS + PULSE_LOW_MS) + CAPTURE_MARGIN_MS))
CAPTURE_SAMPLES=$((CAPTURE_MS * SAMPLES_PER_MS))
CAPTURE_SECONDS=$(((CAPTURE_MS + 999) / 1000 + 10))
if [ "$OUTPUT_MODE" = pwm-corpus ]; then
    [ "$UART_SECONDS" -ge "$((READY_TIMEOUT + (CAPTURE_MS + 999) / 1000 + 30))" ] || die "UART_SECONDS must cover readiness, capture and 30s margin"
fi
for command in "$MPREMOTE" sigrok-cli fuser rg timeout python3; do
    command -v "$command" >/dev/null || die "missing command: $command"
done
for port in "$PI_UART" "$SHRIKE_UART"; do
    [ -r "$port" ] && [ -w "$port" ] || die "no read/write access to $port; run with sudo"
    ! fuser "$port" >/dev/null 2>&1 || die "port already open: $port; stop the other reader first"
done
mkdir -p "$RUN_DIR" || exit 1
idx=0
for file in "$RUN_DIR"/shrike-gpio23-pulse-*; do
    number=${file##*/shrike-gpio23-pulse-}; number=${number%%[-.]*}
    [[ "$number" =~ ^[0-9]+$ ]] || continue
    [ "$((10#$number))" -le "$idx" ] || idx=$((10#$number))
done
PREFIX="$RUN_DIR/shrike-gpio23-pulse-$(printf '%02d' "$((idx + 1))")"
UART_LOG="$PREFIX-uart.log"
LOGIC_LOG="$PREFIX.sr"
RAW_LOG="$PREFIX.bin"
CONVERT_LOG="$PREFIX-convert.log"
ANALYZER_LOG="$PREFIX-analyzer.log"
SHRIKE_LOG="$PREFIX-shrike.log"
printf 'rate=%s samples=%s count=%s high_ms=%s low_ms=%s output_mode=%s\n' \
    "$SAMPLERATE" "$CAPTURE_SAMPLES" "$PULSE_COUNT" "$PULSE_HIGH_MS" "$PULSE_LOW_MS" "$OUTPUT_MODE" > "$PREFIX-config.txt" || die "could not retain capture configuration"
UART_PID=""; LOGIC_PID=""; PULSE_PID=""; SHRIKE_TOUCHED=0
set_safe() {
    timeout --signal=TERM --kill-after=2s 12s "$MPREMOTE" connect "$SHRIKE_UART" resume exec \
        "from machine import Pin; p=Pin(22, Pin.OUT, value=0); e=Pin(21, Pin.OUT, value=0); print('GPIO_SAFE', p.value(), e.value())" >> "$SHRIKE_LOG" 2>&1
}
cleanup() {
    local status=$?
    for pid in "$PULSE_PID" "$LOGIC_PID" "$UART_PID"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    if [ "$SHRIKE_TOUCHED" -eq 1 ] && ! set_safe; then
        echo "ABORT: could not set Shrike outputs LOW; power off the Pi." >&2
        status=1
    fi
    return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SHRIKE_TOUCHED=1
timeout --signal=TERM --kill-after=2s 12s "$MPREMOTE" connect "$SHRIKE_UART" resume exec \
    "from machine import Pin; p=Pin(22, Pin.OUT, value=0); e=Pin(21, Pin.OUT, value=1); print('GPIO_READY', p.value(), e.value())" > "$SHRIKE_LOG" 2>&1 || die "Shrike initialization failed"
stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo || die "UART setup failed"
timeout --signal=TERM --kill-after=2s "${UART_SECONDS}s" cat "$PI_UART" > "$UART_LOG" &
UART_PID=$!
echo "UART RECORDING — POWER ON THE PI NOW. Do not touch the stimulus."
echo "Recording to $PREFIX; $PULSE_COUNT pulses will be automatic."
check_uart() {
    kill -0 "$UART_PID" 2>/dev/null || die "UART capture ended early"
    ! rg -aiq 'PI5_BENCH_FAIL|PI5_BENCH_LOG_LOSS|panic|fatal|watchdog|SIGNED_BPF_(INPUT_MISSING|INPUT_INVALID|LOAD_REJECTED)' "$UART_LOG" || die "kernel failure marker"
    if [ "$OUTPUT_MODE" = pwm ]; then
        ! rg -aq 'PI5_PWM_CONTAINMENT_READY' "$UART_LOG" || die "wrong image: containment image requires OUTPUT_MODE=pwm-containment"
    elif [ "$OUTPUT_MODE" = pwm-containment ]; then
        ! rg -aq 'PI5_PWM_CORPUS_READY' "$UART_LOG" || die "wrong image: corpus image requires OUTPUT_MODE=pwm-corpus"
    fi
}
waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" && rg -aq 'SIGNED_BPF_LOAD_OK' "$UART_LOG"; do
    check_uart
    [ "$waited" -lt "$((READY_TIMEOUT * 10))" ] || die "boot readiness timeout"
    sleep 0.1; waited=$((waited + 1))
done
check_uart
rg -aq 'PI5_BENCH_LOG_MODE deferred=true' "$UART_LOG" || die "wrong image: deferred bench logging required"
if [ "$OUTPUT_MODE" = gpio ]; then
    rg -aq 'PI5_V03B_READY output=gpio sample_ids=true auto_rearm=true' "$UART_LOG" || die "wrong image: bench-reflex-rearm required"
    rg -aq 'PI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false' "$UART_LOG" || die "initial output arm denied; check e-stop wiring"
else
    rg -aq 'PI5_PWM_READY carrier_request_hz=10000 requested_duty_percent=50 auto_rearm=false' "$UART_LOG" || die "wrong image: PWM smoke build required"
    rg -aq 'PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false' "$UART_LOG" || die "initial PWM arm denied; check e-stop wiring"
    if [[ "$OUTPUT_MODE" = pwm-containment || "$OUTPUT_MODE" = pwm-corpus ]]; then
        rg -aqx 'PI5_PWM_CONTAINMENT_READY requested=4294967295 clamp_percent=90 reject_channel=3\r?' "$UART_LOG" &&
            [ "$(rg -ac 'PI5_PWM_CONTAINMENT_READY' "$UART_LOG")" -eq 1 ] || die "wrong image: PWM containment marker required"
        rg -aqx 'PI5_OUT_ARM mode=pwm gpio=12 code=0 estop_asserted=false gpio12_ctrl=0x0000c080 gpio12_pad=0x[0-9a-f]{8}\r?' "$UART_LOG" || die "PWM containment GPIO12 mux readback mismatch"
    fi
fi
if [ "$OUTPUT_MODE" = pwm-corpus ]; then
    rg -aqx 'PI5_PWM_CORPUS_READY cases=5 requests_per_pulse=2\r?' "$UART_LOG" &&
        [ "$(rg -ac 'PI5_PWM_CORPUS_READY' "$UART_LOG")" -eq 1 ] || die "wrong image: five-case PWM corpus marker required"
fi
! rg -aq 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG" || die "unexpected sensor edge before capture; cold boot required"

# Continuous capture includes idle baseline, every pulse and the final stop.
# libsigrok 0.5.2 rewrites srzip for every USB packet. Its growing archive work
# can starve acquisition. Stream raw bytes here; package after capture stops.
# Do not trigger on an edge that we have not yet authorized Shrike to generate.
timeout --signal=TERM --kill-after=2s "${CAPTURE_SECONDS}s" \
    sigrok-cli -l 4 -d "$LOGIC_CONN" -c "samplerate=$SAMPLERATE" -C D0,D1 \
    --samples "$CAPTURE_SAMPLES" -O binary -o "$RAW_LOG" > "$ANALYZER_LOG" 2>&1 &
LOGIC_PID=$!
waited=0
until rg -q 'Received SR_DF_LOGIC' "$ANALYZER_LOG"; do
    check_uart
    kill -0 "$LOGIC_PID" 2>/dev/null || die "analyzer exited before delivering data"
    [ "$waited" -lt "$((ANALYZER_READY_TIMEOUT * 10))" ] || die "analyzer data timeout"
    sleep 0.1; waited=$((waited + 1))
done
check_uart
kill -0 "$LOGIC_PID" 2>/dev/null || die "analyzer ended before pulses"
! rg -aq 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG" || die "unexpected edge before pulses"
echo "CAPTURE ACTIVE — sending $PULSE_COUNT pulses automatically. Keep hands off."
timeout --signal=TERM --kill-after=2s "${CAPTURE_SECONDS}s" \
    "$MPREMOTE" connect "$SHRIKE_UART" resume exec \
    "from machine import Pin; import time
p=Pin(22, Pin.OUT, value=0); e=Pin(21, Pin.OUT)
try:
    print('MULTIPULSE_START')
    for _ in range($PULSE_COUNT):
        p.value(1); time.sleep_ms($PULSE_HIGH_MS)
        p.value(0); time.sleep_ms($PULSE_LOW_MS)
finally:
    p.value(0); e.value(0)
print('MULTIPULSE_DONE', p.value(), e.value())" >> "$SHRIKE_LOG" 2>&1 &
PULSE_PID=$!
while kill -0 "$PULSE_PID" 2>/dev/null; do
    check_uart
    kill -0 "$LOGIC_PID" 2>/dev/null || die "capture ended before pulses completed"
    sleep 0.1
done
wait "$PULSE_PID" || die "Shrike pulse command failed"
PULSE_PID=""
rg -q 'MULTIPULSE_DONE 0 0' "$SHRIKE_LOG" || die "Shrike did not confirm pulse completion and final LOW state"
while kill -0 "$LOGIC_PID" 2>/dev/null; do check_uart; sleep 0.1; done
wait "$LOGIC_PID" || die "analyzer failed"
LOGIC_PID=""
check_uart
set_safe || die "could not assert final e-stop; power off Pi"
SHRIKE_TOUCHED=0
kill "$UART_PID" 2>/dev/null || true
wait "$UART_PID" 2>/dev/null || true
UART_PID=""
# FX2 D0/D1 use one raw byte per sample. A short stream must never pass merely
# because sigrok exited zero. Keep the original binary even if packaging fails.
python3 - "$RAW_LOG" "$CAPTURE_SAMPLES" <<'PY' || die "raw sample count mismatch; retain capture for diagnosis"
from pathlib import Path
import sys
actual = Path(sys.argv[1]).stat().st_size
expected = int(sys.argv[2])
if actual != expected:
    raise SystemExit(f"raw sample count {actual} != {expected}")
PY
echo "ACQUISITION COMPLETE — packaging saved samples; Pi may be powered off."
sigrok-cli -i "$RAW_LOG" -I "binary:numchannels=8:samplerate=$((SAMPLES_PER_MS * 1000))" \
    -C 0=D0,1=D1 -O srzip -o "$LOGIC_LOG" > "$CONVERT_LOG" 2>&1 || die "capture packaging failed; raw samples retained"
[ -s "$LOGIC_LOG" ] || die "capture packaging failed; raw samples retained"
sha256sum "$UART_LOG" "$LOGIC_LOG" "$RAW_LOG" "$ANALYZER_LOG" "$CONVERT_LOG" "$SHRIKE_LOG" "$PREFIX-config.txt" | tee "$PREFIX.sha256" || die "could not hash capture artifacts"
rg -a 'PI5_OUT_ARM|PI5_GPIO_IRQ_PROVEN|PI5_REFLEX_REARM|PI5_ESTOP_REARM|PI5_MC|PI5_MA sample_id=|PI5_PWM_REQUEST' "$UART_LOG" || true
if [ "$OUTPUT_MODE" != gpio ]; then
    python3 - "$UART_LOG" "$OUTPUT_MODE" "$PULSE_COUNT" "$REPO/scripts/hil/pwm-containment-reduce.py" <<'PY' || die "PWM${OUTPUT_MODE#pwm} software correlation failed; retain capture for diagnosis"
import re, runpy, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
if sys.argv[2] == "pwm-corpus":
    errors = runpy.run_path(sys.argv[4])["validate_uart"](text, int(sys.argv[3]), True)
    if errors:
        raise SystemExit("; ".join(errors))
    raise SystemExit(0)
if sys.argv[2] == "pwm-containment":
    expected = {
        "PI5_PWM_CONTAINMENT_READY": r" requested=4294967295 clamp_percent=90 reject_channel=3",
        "PI5_PWM_REQUEST": r" sample_id=([12]) chip=0 channel=([13]) requested=4294967295 code=(0|-1) range=5000 duty=4500",
        "PI5_MA": r" sample_id=1 monitor_ns=\d+",
        "PI5_MC": r" sample_id=1 ns=\d+ kind=pwm ch=1 val=90",
    }
    for marker, fields in expected.items():
        count = 2 if marker == "PI5_PWM_REQUEST" else 1
        if text.count(marker) != count or len(re.findall(r"^" + marker + fields + r"$", text, re.M)) != count:
            raise SystemExit("unexpected or missing containment marker: " + marker)
    requests = re.findall(r"^PI5_PWM_REQUEST" + expected["PI5_PWM_REQUEST"] + r"$", text, re.M)
    if requests != [("1", "1", "0"), ("2", "3", "-1")]:
        raise SystemExit("need clamp sample 1 followed by rejected sample 2 with unchanged readback")
    if text.count("PI5_GPIO_IRQ_PROVEN") != 1 or "PI5_REFLEX_REARM" in text or "PI5_ESTOP_REARM" in text:
        raise SystemExit("containment requires one GPIO route proof and no re-arm")
    raise SystemExit(0)
ma = re.findall(r"PI5_MA sample_id=(\d+) monitor_ns=\d+", text)
mc = re.findall(r"PI5_MC sample_id=(\d+) ns=\d+ kind=pwm ch=1 val=0", text)
if len(ma) != 1 or len(mc) != 1 or ma != mc or text.count("PI5_MC ") != 1 or text.count("PI5_GPIO_IRQ_PROVEN") != 1:
    raise SystemExit("need exactly one correlated PWM M-A/M-C pair and GPIO route proof")
if "PI5_REFLEX_REARM" in text or "PI5_ESTOP_REARM" in text:
    raise SystemExit("PWM smoke must not re-arm")
PY
    if [[ "$OUTPUT_MODE" = pwm-containment || "$OUTPUT_MODE" = pwm-corpus ]]; then
        echo "CAPTURE COMPLETE: PWM containment software checks complete; physical waveform review required."
    else
        echo "CAPTURE COMPLETE: PWM smoke software correlation only; physical carrier/stop review required."
    fi
else
    python3 -B "$REPO/scripts/benchmark/analyze-v03.py" --sensor "$UART_LOG" --sensor-count "$PULSE_COUNT" || die "software cycle correlation failed; retain capture for diagnosis"
    echo "CAPTURE COMPLETE: software cycles checked; physical waveform review is required."
fi
echo "Shrike reports GPIO22=LOW and GPIO21=LOW (e-stop asserted). Power off the Pi."
