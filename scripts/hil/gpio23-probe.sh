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
LOGIC_CONN="${LOGIC_CONN:-fx2lafw}"
SAMPLERATE="${SAMPLERATE:-1m}"
# Begin the analyzer window only after the verbose instrumented boot finishes.
SAMPLES="${SAMPLES:-30m}"
UART_SECONDS="${UART_SECONDS:-240}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
ANALYZER_READY_TIMEOUT="${ANALYZER_READY_TIMEOUT:-10}"

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
ANALYZER_LOG="$RUN_DIR/gpio23-probe-$PROBE-analyzer.log"

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

# Never split UART bytes with an existing reader or kill another terminal's job.
if ! command -v fuser >/dev/null; then
    echo "ABORT: fuser not found" >&2
    exit 1
fi
if fuser "$PI_UART" >/dev/null 2>&1; then
    echo "ABORT: UART already open; stop the previous capture first." >&2
    exit 1
fi

UART_PID=""
LOGIC_PID=""
cleanup() {
    for pid in "$LOGIC_PID" "$UART_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo || exit 1
# Keep raw UART bytes; one owned timeout process, no orphaned tee/cat pipeline.
timeout --signal=TERM --kill-after=2s "${UART_SECONDS}s" \
  cat "$PI_UART" > "$UART_LOG" &
UART_PID=$!

echo "UART RECORDING - power on the Pi with the stimulus DISCONNECTED."
echo "Wait for the action prompt; do not apply an edge during boot."

check_uart() {
    if ! kill -0 "$UART_PID" 2>/dev/null; then
        echo "ABORT: UART capture ended before the test completed." >&2
        exit 1
    fi
    if rg -aiq 'PI5_BENCH_FAIL|PI5_BENCH_LOG_LOSS|panic|fatal|watchdog|SIGNED_BPF_(INPUT_MISSING|INPUT_INVALID|LOAD_REJECTED)' "$UART_LOG"; then
        echo "ABORT: kernel failure marker; leave the stimulus disconnected." >&2
        exit 1
    fi
}

waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" && rg -aq 'SIGNED_BPF_LOAD_OK' "$UART_LOG"; do
    check_uart
    if [ "$waited" -ge "$((READY_TIMEOUT * 10))" ]; then
        echo "ABORT: boot readiness timed out; DO NOT apply the stimulus." >&2
        exit 1
    fi
    sleep 0.1
    waited=$((waited + 1))
done
check_uart
if rg -aq 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG"; then
    echo "ABORT: GPIO edge occurred before the prompt; cold boot required." >&2
    exit 1
fi

sigrok-cli -l 4 -d "$LOGIC_CONN" -c "samplerate=$SAMPLERATE" -C D0,D1 \
  --samples "$SAMPLES" -O srzip -o "$LOGIC_LOG" > "$ANALYZER_LOG" 2>&1 &
LOGIC_PID=$!

waited=0
until rg -q 'Received SR_DF_LOGIC' "$ANALYZER_LOG"; do
    check_uart
    if ! kill -0 "$LOGIC_PID" 2>/dev/null || [ "$waited" -ge "$((ANALYZER_READY_TIMEOUT * 10))" ]; then
        echo "ABORT: analyzer did not deliver data; DO NOT apply the stimulus." >&2
        exit 1
    fi
    sleep 0.1
    waited=$((waited + 1))
done
check_uart
if ! kill -0 "$LOGIC_PID" 2>/dev/null || rg -aq 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG"; then
    echo "ABORT: capture ended or an edge occurred before the prompt." >&2
    exit 1
fi

echo
echo "  >>> TOUCH NOW: connect the free end AFTER the 220-ohm resistor"
echo "      to the GPIO23 node (Pi physical pin 16 / analyzer D0)."
echo "      Hold ~0.5 s, remove ONCE, then leave it disconnected."
echo

while kill -0 "$LOGIC_PID" 2>/dev/null; do
    check_uart
    sleep 0.1
done
wait "$LOGIC_PID"
LOGIC_STATUS=$?
LOGIC_PID=""
check_uart
cleanup
UART_PID=""

if [ "$LOGIC_STATUS" -ne 0 ]; then
    echo "FAIL: analyzer exited with status $LOGIC_STATUS; capture is invalid." >&2
    exit 1
fi
ls -lh "$UART_LOG" "$LOGIC_LOG"
sha256sum "$UART_LOG" "$LOGIC_LOG" "$ANALYZER_LOG"

# Edge census. A missing marker is ambiguous on its own: no stimulus and a
# broken route look identical in the UART log. The capture tells them apart.
echo
sigrok-cli -i "$LOGIC_LOG" -C D0 -O csv 2>/dev/null | python3 -c '
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
    sys.exit(1)
' || { echo "FAIL: no usable GPIO23 edge evidence" >&2; exit 1; }

echo
proven=$(rg -ac 'PI5_GPIO_IRQ_PROVEN' "$UART_LOG" 2>/dev/null || true)
proven=${proven:-0}
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
