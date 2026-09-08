#!/usr/bin/env bash
# Unloaded GPIO reflex capture; physical waveform review is still required.
# Shrike GP22 -> 220 ohm -> Pi pin16/GPIO23, analyzer D0 (input1).
# Shrike GP21 -> 220 ohm -> Pi pin18/GPIO24 (active-low e-stop).
# Analyzer D1 (input2) -> Pi pin32/GPIO12. All grounds common.
# No motors/drivers/actuators or static GPIO24-to-3.3V jumper permitted.
# Requires bench-reflex-rearm: GP21 is released before boot for initial arming,
# then asserted in the pulse program's finally block and host cleanup.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$REPO/artifacts/runs/axiomos-hil-20260720T134903Z/03-gpio}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
SHRIKE_UART="${SHRIKE_UART:-/dev/serial/by-id/usb-SHRIKE_Board_in_Micropython_Mode_de65143857942625-if00}"
MPREMOTE="${MPREMOTE:-mpremote}"
LOGIC_CONN="${LOGIC_CONN:-fx2lafw}"
SAMPLERATE="${SAMPLERATE:-24m}"
UART_SECONDS="${UART_SECONDS:-240}"
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
    *) die "supported capture rates: 1m (functional) or 24m (timing capture)" ;;
esac
CAPTURE_MS=$((PULSE_COUNT * (PULSE_HIGH_MS + PULSE_LOW_MS) + CAPTURE_MARGIN_MS))
CAPTURE_SAMPLES=$((CAPTURE_MS * SAMPLES_PER_MS))
CAPTURE_SECONDS=$(((CAPTURE_MS + 999) / 1000 + 10))
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
ANALYZER_LOG="$PREFIX-analyzer.log"
SHRIKE_LOG="$PREFIX-shrike.log"
printf 'rate=%s samples=%s count=%s high_ms=%s low_ms=%s\n' \
    "$SAMPLERATE" "$CAPTURE_SAMPLES" "$PULSE_COUNT" "$PULSE_HIGH_MS" "$PULSE_LOW_MS" > "$PREFIX-config.txt" || die "could not retain capture configuration"
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
    ! rg -aiq 'PI5_BENCH_FAIL|panic|fatal|watchdog|SIGNED_BPF_(INPUT_MISSING|INPUT_INVALID|LOAD_REJECTED)' "$UART_LOG" || die "kernel failure marker"
}
waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" && rg -aq 'SIGNED_BPF_LOAD_OK' "$UART_LOG"; do
    check_uart
    [ "$waited" -lt "$((READY_TIMEOUT * 10))" ] || die "boot readiness timeout"
    sleep 0.1; waited=$((waited + 1))
done
check_uart
rg -aq 'PI5_V03B_READY output=gpio sample_ids=true auto_rearm=true' "$UART_LOG" || die "wrong image: bench-reflex-rearm required"
rg -aq 'PI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false' "$UART_LOG" || die "initial output arm denied; check e-stop wiring"
! rg -aq 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG" || die "unexpected sensor edge before capture; cold boot required"

# Continuous capture includes idle baseline, every pulse and the final stop.
# Do not trigger on an edge that we have not yet authorized Shrike to generate.
timeout --signal=TERM --kill-after=2s "${CAPTURE_SECONDS}s" \
    sigrok-cli -l 4 -d "$LOGIC_CONN" -c "samplerate=$SAMPLERATE" -C D0,D1 \
    --samples "$CAPTURE_SAMPLES" -O srzip -o "$LOGIC_LOG" > "$ANALYZER_LOG" 2>&1 &
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
sha256sum "$UART_LOG" "$LOGIC_LOG" "$ANALYZER_LOG" "$SHRIKE_LOG" "$PREFIX-config.txt" | tee "$PREFIX.sha256" || die "could not hash capture artifacts"
rg -a 'PI5_OUT_ARM|PI5_GPIO_IRQ_PROVEN|PI5_REFLEX_REARM|PI5_MC|PI5_MA sample_id=' "$UART_LOG" || true
python3 -B "$REPO/scripts/benchmark/analyze-v03.py" --sensor "$UART_LOG" --sensor-count "$PULSE_COUNT" || die "software cycle correlation failed; retain capture for diagnosis"
echo "CAPTURE COMPLETE: software cycles checked; physical waveform review is required."
echo "Shrike reports GPIO22=LOW and GPIO21=LOW (e-stop asserted). Power off the Pi."
