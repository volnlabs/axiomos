#!/usr/bin/env bash
# Single-edge GPIO23 interrupt probe: capture Pi UART + logic analyzer together,
# then grade the run against PI5_GPIO_IRQ_PROVEN.
#
# The kernel latches PI5_GPIO_IRQ_PROVEN once per boot, so a probe only counts
# on a freshly powered Pi that has printed PI5_BENCH_READY. Power-cycle between
# attempts or the marker cannot appear no matter how clean the edge is.
set -uo pipefail

RUN_DIR="${RUN_DIR:-$(git rev-parse --show-toplevel)/artifacts/runs/axiomos-hil-20260720T134903Z/03-gpio}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
LOGIC_CONN="${LOGIC_CONN:-fx2lafw:conn=3.9}"
SAMPLERATE="${SAMPLERATE:-1m}"
# A cold boot reaches PI5_BENCH_READY at ~6.5 s, and the edge must come after
# that, so the window has to cover boot plus a human reaction. 12 s did not.
SAMPLES="${SAMPLES:-30m}"
UART_SECONDS="${UART_SECONDS:-40}"
READY_TIMEOUT="${READY_TIMEOUT:-25}"

mkdir -p "$RUN_DIR"

# One past the highest index present, so numbering stays chronological and a
# repeat run never overwrites evidence. Counting free slots instead would
# refill earlier gaps and misorder the record.
idx=0
for f in "$RUN_DIR"/gpio23-probe-*; do
    n=${f##*/gpio23-probe-}
    n=${n%%[-.]*}
    case $n in
        ''|*[!0-9]*) continue ;;
    esac
    [ "$((10#$n))" -gt "$idx" ] && idx=$((10#$n))
done
PROBE="$(printf '%02d' "$((idx + 1))")"
UART_LOG="$RUN_DIR/gpio23-probe-$PROBE-uart.log"
LOGIC_LOG="$RUN_DIR/gpio23-probe-$PROBE.sr"

if ! test -r "$PI_UART" || ! test -w "$PI_UART"; then
    echo "ABORT: no read/write access to $PI_UART" >&2
    echo "  sudo setfacl -m \"u:\$(id -un):rw\" /dev/ttyACM0" >&2
    exit 1
fi
if ! command -v sigrok-cli >/dev/null; then
    echo "ABORT: sigrok-cli not found" >&2
    exit 1
fi

echo "probe $PROBE -> $UART_LOG"
echo "            $LOGIC_LOG"

stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo

timeout --signal=INT --kill-after=2s "${UART_SECONDS}s" \
  stdbuf -o0 cat "$PI_UART" |
  stdbuf -o0 tr -d '\r' |
  stdbuf -o0 tee "$UART_LOG" &
UART_PID=$!

sleep 1

sigrok-cli -d "$LOGIC_CONN" -c "samplerate=$SAMPLERATE" -C D0 \
  --samples "$SAMPLES" -O srzip -o "$LOGIC_LOG" &
LOGIC_PID=$!

echo
echo "CAPTURE ACTIVE. Keep the lead OFF pin 16 and power-cycle the Pi now."
echo "GPIO23 is armed rising-edge-only, so it must sit low until the route is up."
echo

# The interrupt is only armed once the kernel prints PI5_BENCH_READY. Touching
# before that puts the edge in the bootloader window, where nothing is
# listening, and a lead already resting on pin 16 gives a falling edge that is
# correctly ignored.
waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" 2>/dev/null; do
    if [ "$waited" -ge "$READY_TIMEOUT" ]; then
        echo "WARNING: no PI5_BENCH_READY after ${READY_TIMEOUT}s."
        echo "         Did the Pi power-cycle? Probing anyway."
        break
    fi
    sleep 1
    waited=$((waited + 1))
done

echo
echo "  >>> ROUTE UP - touch the resistor lead to physical pin 16 now,"
echo "      hold ~0.5 s, remove it ONCE, then wait for the capture to end."
echo

wait "$LOGIC_PID"
LOGIC_STATUS=$?
wait "$UART_PID"

echo
echo "logic-analyzer exit: $LOGIC_STATUS"
ls -lh "$UART_LOG" "$LOGIC_LOG" 2>/dev/null
sha256sum "$UART_LOG" "$LOGIC_LOG" 2>/dev/null

# Edge census. A missing marker is ambiguous on its own: no stimulus and a
# broken route look identical in the UART log. The capture tells them apart.
echo
sigrok-cli -i "$LOGIC_LOG" -O csv 2>/dev/null | python3 -c '
import sys
prev = None
rising = falling = n = 0
first = None
for line in sys.stdin:
    line = line.strip()
    if not line or line[0] in ";t":
        continue
    try:
        v = int(line.split(",")[-1])
    except ValueError:
        continue
    if prev is not None and v != prev:
        if v:
            rising += 1
            if first is None:
                first = n
        else:
            falling += 1
    prev = v
    n += 1
print(f"D0: {n} samples, {rising} rising, {falling} falling")
if first is not None:
    print(f"    first rising edge at sample {first}")
if rising == 0:
    print("    NO RISING EDGE - the stimulus never reached pin 16 while armed")
' || echo "(could not analyse $LOGIC_LOG)"

echo
proven=$(rg -ac 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG" 2>/dev/null || echo 0)
rg -a -n 'PI5_BENCH_READY|PI5_GPIO_IRQ_PROVEN|PI5_BENCH_FAIL|panic|fatal|watchdog' \
  "$UART_LOG" || true

echo
if [ "$proven" = "1" ]; then
    echo "PASS: PI5_GPIO_IRQ_PROVEN seen exactly once"
    exit 0
elif [ "$proven" = "0" ]; then
    echo "FAIL: marker absent. Was the Pi power-cycled for this probe, and did"
    echo "      PI5_BENCH_READY appear in this log?"
    exit 1
else
    echo "FAIL: marker seen $proven times - interrupt storm or bad acknowledge"
    exit 1
fi
