#!/usr/bin/env bash
# Shrike-driven GPIO23 multi-pulse probe.
#
# Wiring (see docs/hil-gpio23-schematic for the full diagram):
#   Shrike GPIO22 --[ 220 ohm ]--> Pi GPIO23 / physical pin 16
#   Shrike GND -------------------> Pi GND (pin 20 or 14)
#   Logic D0 ---> Pi side of the resistor (pin 16 node = what RP1 sees)
#   Logic D1 ---> Pi GPIO12 / physical pin 32 (reflex PWM output)
#   Logic GND --> common GND
#
# The series resistor MUST be small (~220 ohm, not 2.2 kOhm). A 2.2 kOhm source
# into the analyzer's input capacitance slows the GPIO23 rising edge enough that
# the RP1 edge detector misses it: the node still reads a valid 3.3 V high and
# the analyzer still triggers, but no interrupt is latched. 220 ohm keeps the
# edge fast while still limiting fault current to ~15 mA on a 3.3 V clash.
#
# The script arms UART + logic capture, tells the operator when to power the Pi,
# waits for the kernel's built-in reflex attachment, then emits repeated clean
# GPIO22 pulses. PI5_BENCH_READY is printed only after that attachment succeeds.
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
RUN_DIR="${RUN_DIR:-$REPO/artifacts/runs/axiomos-hil-20260720T134903Z/03-gpio}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
SHRIKE_UART="${SHRIKE_UART:-/dev/serial/by-id/usb-SHRIKE_Board_in_Micropython_Mode_de65143857942625-if00}"
LOGIC_CONN="${LOGIC_CONN:-}"
SAMPLERATE="${SAMPLERATE:-24m}"
SAMPLES="${SAMPLES:-25m}"
UART_SECONDS="${UART_SECONDS:-45}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"
TRIGGER="${TRIGGER:-1}"
PULSE_COUNT="${PULSE_COUNT:-5}"
PULSE_HIGH_MS="${PULSE_HIGH_MS:-800}"
PULSE_LOW_MS="${PULSE_LOW_MS:-800}"

EXPECTED=(PI5_BENCH_READY PI5_GPIO_IRQ_PROVEN)
FORBIDDEN=(PI5_BENCH_FAIL panic fatal watchdog)

mkdir -p "$RUN_DIR"

idx=0
for f in "$RUN_DIR"/shrike-gpio23-pulse-*; do
    n=${f##*/shrike-gpio23-pulse-}
    n=${n%%[-.]*}
    case $n in
        ''|*[!0-9]*) continue ;;
    esac
    [ "$((10#$n))" -gt "$idx" ] && idx=$((10#$n))
done
PROBE="$(printf '%02d' "$((idx + 1))")"
UART_LOG="$RUN_DIR/shrike-gpio23-pulse-$PROBE-uart.log"
LOGIC_LOG="$RUN_DIR/shrike-gpio23-pulse-$PROBE.sr"

require_rw() {
    local path="$1"
    local label="$2"
    local target

    if ! test -e "$path"; then
        echo "ABORT: $label missing: $path" >&2
        exit 1
    fi

    target="$(readlink -f "$path")"
    if test -r "$path" && test -w "$path"; then
        return 0
    fi

    echo "$label needs ACL on $target"
    sudo setfacl -m "u:$(id -un):rw" "$target"
}

if ! command -v sigrok-cli >/dev/null; then
    echo "ABORT: sigrok-cli not found" >&2
    exit 1
fi
if ! command -v mpremote >/dev/null; then
    echo "ABORT: mpremote not found" >&2
    exit 1
fi

require_rw "$PI_UART" "Pi UART"
require_rw "$SHRIKE_UART" "Shrike UART"

PI_DEV="$(readlink -f "$PI_UART")"
UART_PID=""

# A reader left over from a previous aborted run keeps the serial port open.
# Two readers on one device split the byte stream, so markers like
# PI5_BENCH_READY arrive corrupted and are never matched. Free the port first,
# and guarantee our own reader dies on any exit path (killing the tee alone
# leaves the cat blocked on read, which is exactly how the leak happens).
free_pi_uart() {
    if fuser "$PI_DEV" >/dev/null 2>&1; then
        echo "Freeing stale reader(s) on $PI_DEV..."
        fuser -k "$PI_DEV" 2>/dev/null || true
        sleep 1
    fi
}
cleanup() {
    [ -n "$UART_PID" ] && kill "$UART_PID" 2>/dev/null || true
    fuser -k "$PI_DEV" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
free_pi_uart

if [ -z "$LOGIC_CONN" ]; then
    LOGIC_CONN="$(sigrok-cli --scan |
        sed -n 's/^\(fx2lafw[^ ]*\) - Saleae Logic.*/\1/p' |
        head -n 1)"
fi
if [ -z "$LOGIC_CONN" ]; then
    echo "ABORT: logic analyzer not found" >&2
    sigrok-cli --scan || true
    exit 1
fi

echo "probe $PROBE"
echo "  UART  -> $UART_LOG"
echo "  logic -> $LOGIC_LOG"
echo "  logic device: $LOGIC_CONN"
echo

echo "Setting Shrike GPIO22 idle low..."
mpremote connect "$SHRIKE_UART" exec \
  "from machine import Pin; p=Pin(22, Pin.OUT); p.value(0); print('GPIO22_LOW')"

stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo

timeout --signal=INT --kill-after=2s "${UART_SECONDS}s" \
  stdbuf -o0 cat "$PI_UART" |
  stdbuf -o0 tr -d '\r' |
  stdbuf -o0 tee "$UART_LOG" &
UART_PID=$!

sleep 1

echo
echo "CAPTURE ARMED."
echo "Plug in / power on the Pi when countdown starts."
for n in 5 4 3 2 1; do
    echo "  $n"
    sleep 1
done
echo "Pi should be powering now. Waiting for PI5_BENCH_READY..."

waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" 2>/dev/null; do
    if [ "$waited" -ge "$READY_TIMEOUT" ]; then
        echo "FAIL: no PI5_BENCH_READY after ${READY_TIMEOUT}s"
        kill "$UART_PID" 2>/dev/null || true
        wait "$UART_PID" 2>/dev/null || true
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done

echo "PI5_BENCH_READY seen; the built-in reflex is attached."
echo "Sending $PULSE_COUNT Shrike GPIO22 pulses..."
timeout --signal=INT --kill-after=2s 20s \
  sigrok-cli \
    -d "$LOGIC_CONN" \
    -c "samplerate=$SAMPLERATE" \
    -C D0,D1 \
    ${TRIGGER:+-t D0=r} \
    -w \
    --samples "$SAMPLES" \
    -O srzip \
    -o "$LOGIC_LOG" &
LOGIC_PID=$!

sleep 1
mpremote connect "$SHRIKE_UART" exec \
  "from machine import Pin; import time; p=Pin(22, Pin.OUT); p.value(0); time.sleep_ms(500); print('MULTIPULSE_START')
for _ in range($PULSE_COUNT): p.value(1); time.sleep_ms($PULSE_HIGH_MS); p.value(0); time.sleep_ms($PULSE_LOW_MS)
print('MULTIPULSE_DONE')"

wait "$LOGIC_PID"
LOGIC_STATUS=$?
wait "$UART_PID" || true

echo
echo "logic-analyzer exit: $LOGIC_STATUS"
ls -lh "$UART_LOG" "$LOGIC_LOG" 2>/dev/null
sha256sum "$UART_LOG" "$LOGIC_LOG" 2>/dev/null

echo
if [ ! -s "$LOGIC_LOG" ]; then
    echo "NO LOGIC CAPTURE - $LOGIC_LOG missing or empty"
    LOGIC_ANALYSIS_OK=0
else
    LOGIC_ANALYSIS_OK=1
    sigrok-cli -i "$LOGIC_LOG" -O csv 2>/dev/null | python3 -c '
import sys
triggered = sys.argv[1] != ""
prev = None
rising = falling = n = 0
first = None
for line in sys.stdin:
    line = line.strip()
    if not line or line[0] in ";t":
        continue
    parts = line.split(",")
    try:
        d0 = int(parts[-2])
        d1 = int(parts[-1])
    except (ValueError, IndexError):
        continue
    if prev is not None and d0 != prev:
        if d0:
            rising += 1
            if first is None:
                first = n
        else:
            falling += 1
    prev = d0
    n += 1
print(f"D0(GPIO23): {n} samples, {rising} rising, {falling} falling")
if first is not None:
    print(f"    first rising edge at sample {first}")
if triggered and rising == 0 and falling > 0:
    print("    capture began after the D0 rising trigger; falling edge confirms the pulse")
elif rising == 0:
    print("    NO RISING EDGE - Shrike pulse was not captured on D0")
' "$TRIGGER" || {
        echo "(could not analyse $LOGIC_LOG)"
        LOGIC_ANALYSIS_OK=0
    }
fi

echo
rg -a -n 'PI5_BENCH_READY|PI5_GPIO_IRQ_DIAG|PI5_GPIO_IRQ_PROVEN|SIGNED_BPF_(LOAD_OK|INPUT_MISSING)|PI5_BENCH_FAIL|panic|fatal|watchdog' \
  "$UART_LOG" || true

# Handler-entry vs pulse-count census. PI5_GPIO_IRQ_PROVEN latches once per boot,
# so it cannot show a storm; the per-entry PI5_GPIO_IRQ_DIAG lines can. Roughly
# one handler entry per delivered rising edge is expected. Many more than
# PULSE_COUNT means the source is not being cleanly acknowledged (level-like
# re-trigger); zero means no edge reached the handler at all.
handler_entries=$(rg -ac 'PI5_GPIO_IRQ_DIAG' "$UART_LOG" 2>/dev/null || echo 0)
echo "handler entries (PI5_GPIO_IRQ_DIAG): $handler_entries  (pulses sent: $PULSE_COUNT)"
if [ "$handler_entries" -gt "$((PULSE_COUNT * 2))" ]; then
    echo "WARNING: entries >> pulses - possible interrupt storm / bad acknowledge"
fi

echo
ok=1
for m in "${EXPECTED[@]}"; do
    if rg -aq "$m" "$UART_LOG"; then
        echo "ok      $m"
    else
        echo "MISSING $m"
        ok=0
    fi
done
for m in "${FORBIDDEN[@]}"; do
    if rg -aiq "$m" "$UART_LOG"; then
        echo "FORBIDDEN MARKER PRESENT: $m"
        ok=0
    fi
done

if [ "$LOGIC_STATUS" != 0 ] || [ "${LOGIC_ANALYSIS_OK:-0}" != 1 ]; then
    echo "LOGIC_CAPTURE_INCOMPLETE"
    ok=0
fi

if [ "$ok" = 1 ]; then
    echo "PASS: Shrike GPIO22 -> Pi GPIO23 interrupt probe"
    exit 0
fi

echo "FAIL: Shrike GPIO23 pulse probe"
exit 1
