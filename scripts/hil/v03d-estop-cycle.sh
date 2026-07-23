#!/usr/bin/env bash
# V03-D physical e-stop latency HIL runner.
#
# Required wiring (all signals are 3.3 V only; actuators and motors MUST stay
# disconnected for this bench):
#   Shrike GPIO21 --[ 220 ohm ]--> Pi GPIO24 / physical pin 18 (active-low e-stop)
#   Shrike GND -------------------> Pi GND
#   Logic analyzer D0 ------------> Pi GPIO24 / physical pin 18
#   Logic analyzer D1 ------------> Pi GPIO12 (bench output)
#   Logic analyzer GND -----------> common GND
#
# GPIO21 is held high before the Pi boots (e-stop released).  Once the kernel
# announces PI5_BENCH_READY, it generates N presses: N-1 low/high cycles and
# one final low.  Thus every press after the first is preceded by the kernel's
# GPIO12 re-arm and the run ends electrically safe.
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
RUN_DIR="${RUN_DIR:-$REPO/artifacts/runs/axiomos-hil-v03d}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
SHRIKE_UART="${SHRIKE_UART:-/dev/serial/by-id/usb-SHRIKE_Board_in_Micropython_Mode_de65143857942625-if00}"
LOGIC_CONN="${LOGIC_CONN:-}"
# V03-D acceptance is explicitly a 24 MHz measurement; the reducer uses the
# same fixed rate for its sample-index-to-time conversion.
SAMPLERATE="24m"
PRESS_COUNT="${PRESS_COUNT:-100}"
PRESS_LOW_MS="${PRESS_LOW_MS:-25}"
REARM_HIGH_MS="${REARM_HIGH_MS:-75}"
FINAL_LOW_MS="${FINAL_LOW_MS:-100}"
CAPTURE_MARGIN_MS="${CAPTURE_MARGIN_MS:-1000}"
UART_SECONDS="${UART_SECONDS:-90}"
READY_TIMEOUT="${READY_TIMEOUT:-45}"

EXPECTED=(PI5_BENCH_READY PI5_V03D_READY)
FORBIDDEN=(PI5_BENCH_FAIL panic fatal watchdog)
UART_PID=""
LOGIC_PID=""
SHRIKE_TOUCHED=0

wiring_instructions() {
    cat >&2 <<'EOF'
ABORT: V03-D is permitted only with actuators and motors disconnected.

Required wiring:
  REMOVE any GPIO24-to-3.3V or other static-high jumper first.
  Shrike GPIO21 -> 220 ohm -> Pi GPIO24 / physical pin 18 (active-low e-stop)
  Shrike GND ----------------> Pi GND (common ground)
  Logic analyzer D0 ---------> Pi GPIO24 / physical pin 18
  Logic analyzer D1 ---------> Pi GPIO12 (bench output)
  Logic analyzer GND --------> common ground

Do not connect a motor driver, motor, or actuator to this bench.  After
disconnecting them, re-run with ACTUATORS_MOTORS_DISCONNECTED=YES.
EOF
}

die() {
    echo "ABORT: $*" >&2
    exit 1
}

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

require_rw() {
    local path="$1" label="$2" target
    test -e "$path" || die "$label missing: $path"
    target="$(readlink -f "$path")"
    if ! test -r "$path" || ! test -w "$path"; then
        echo "$label needs ACL on $target" >&2
        sudo setfacl -m "u:$(id -un):rw" "$target"
    fi
}

set_shrike_low() {
    mpremote connect "$SHRIKE_UART" exec \
      "from machine import Pin; p=Pin(21, Pin.OUT); p.value(0); print('GPIO21_LOW')" \
      >/dev/null 2>&1
}

cleanup() {
    # An asserted active-low e-stop is the only acceptable cleanup state.
    if [ "$SHRIKE_TOUCHED" -eq 1 ]; then
        set_shrike_low || true
    fi
    if [ -n "$LOGIC_PID" ]; then
        kill "$LOGIC_PID" 2>/dev/null || true
        wait "$LOGIC_PID" 2>/dev/null || true
    fi
    if [ -n "$UART_PID" ]; then
        kill "$UART_PID" 2>/dev/null || true
        wait "$UART_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [ "${ACTUATORS_MOTORS_DISCONNECTED:-}" != "YES" ]; then
    wiring_instructions
    exit 1
fi

for value in "$PRESS_COUNT" "$PRESS_LOW_MS" "$REARM_HIGH_MS" "$FINAL_LOW_MS" \
             "$CAPTURE_MARGIN_MS" "$UART_SECONDS" "$READY_TIMEOUT"; do
    is_uint "$value" || die "numeric settings must be non-negative integers"
done
[ "$PRESS_COUNT" -ge 100 ] || die "PRESS_COUNT must be >= 100 (got $PRESS_COUNT)"
[ "$PRESS_LOW_MS" -gt 0 ] || die "PRESS_LOW_MS must be > 0"
[ "$REARM_HIGH_MS" -gt 0 ] || die "REARM_HIGH_MS must be > 0"

command -v sigrok-cli >/dev/null || die "sigrok-cli not found"
command -v mpremote >/dev/null || die "mpremote not found"
command -v sha256sum >/dev/null || die "sha256sum not found"

require_rw "$PI_UART" "Pi UART"
require_rw "$SHRIKE_UART" "Shrike UART"

PI_DEV="$(readlink -f "$PI_UART")"
SHRIKE_DEV="$(readlink -f "$SHRIKE_UART")"
if fuser "$PI_DEV" >/dev/null 2>&1; then
    echo "ABORT: Pi serial port is already in use:" >&2
    fuser -v "$PI_DEV" || true
    exit 1
fi
if fuser "$SHRIKE_DEV" >/dev/null 2>&1; then
    echo "ABORT: Shrike serial port is already in use:" >&2
    fuser -v "$SHRIKE_DEV" || true
    exit 1
fi

mkdir -p "$RUN_DIR"
idx=0
for file in "$RUN_DIR"/v03d-estop-cycle-*-uart.log; do
    number="${file##*/v03d-estop-cycle-}"
    number="${number%%-*}"
    case "$number" in
        ''|*[!0-9]*) continue ;;
    esac
    [ "$((10#$number))" -gt "$idx" ] && idx=$((10#$number))
done
RUN="$(printf '%02d' "$((idx + 1))")"
UART_LOG="$RUN_DIR/v03d-estop-cycle-$RUN-uart.log"
LOGIC_LOG="$RUN_DIR/v03d-estop-cycle-$RUN.sr"

if [ -z "$LOGIC_CONN" ]; then
    LOGIC_CONN="$(sigrok-cli --scan |
        sed -n 's/^\(fx2lafw[^ ]*\) - Saleae Logic.*/\1/p' |
        head -n 1)"
fi
[ -n "$LOGIC_CONN" ] || {
    echo "ABORT: logic analyzer not found" >&2
    sigrok-cli --scan || true
    exit 1
}

# 24 MHz is 24,000 samples/ms.  The capture starts on the first falling D0
# edge and includes every low/high interval plus a post-final-low margin.
CAPTURE_MS=$((PRESS_COUNT * PRESS_LOW_MS + (PRESS_COUNT - 1) * REARM_HIGH_MS + FINAL_LOW_MS + CAPTURE_MARGIN_MS))
CAPTURE_SAMPLES=$((CAPTURE_MS * 24000))

echo "V03-D run $RUN"
echo "  UART:  $UART_LOG"
echo "  logic: $LOGIC_LOG"
echo "  samplerate: $SAMPLERATE; post-trigger capture: ${CAPTURE_MS} ms (${CAPTURE_SAMPLES} samples)"
echo "  N=$PRESS_COUNT, GPIO21 low=${PRESS_LOW_MS} ms, re-arm high=${REARM_HIGH_MS} ms"
echo
echo "Confirmed: actuators/motors disconnected. Required wiring:"
echo "  GPIO24 static-high/3.3V jumper removed"
echo "  Shrike GPIO21 -> 220 ohm -> Pi GPIO24 / physical pin 18"
echo "  Shrike GND -> Pi GND; analyzer D0=GPIO24, D1=GPIO12, analyzer GND=common"

echo "Holding Shrike GPIO21 HIGH (e-stop released) before Pi boot..."
SHRIKE_TOUCHED=1
mpremote connect "$SHRIKE_UART" exec \
  "from machine import Pin; p=Pin(21, Pin.OUT); p.value(1); print('GPIO21_HIGH', p.value())" ||
  die "could not drive Shrike GPIO21 high"

stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo
timeout --signal=INT --kill-after=2s "${UART_SECONDS}s" \
  stdbuf -o0 cat "$PI_UART" |
  stdbuf -o0 tr -d '\r' |
  stdbuf -o0 tee "$UART_LOG" &
UART_PID=$!

echo
echo "GPIO21 is HIGH. Power/boot the Pi now; waiting for PI5_BENCH_READY..."
waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" 2>/dev/null; do
    if rg -aiq 'PI5_BENCH_FAIL|panic|fatal|watchdog' "$UART_LOG" 2>/dev/null; then
        die "Pi emitted a forbidden marker before PI5_BENCH_READY"
    fi
    [ "$waited" -lt "$READY_TIMEOUT" ] || die "no PI5_BENCH_READY after ${READY_TIMEOUT}s"
    sleep 1
    waited=$((waited + 1))
done

if ! rg -aq 'PI5_V03D_READY output=gpio auto_rearm=true' "$UART_LOG"; then
    die "image is not the GPIO V03-D auto-rearm diagnostic build"
fi

echo "PI5_BENCH_READY seen; arming 24 MHz D0/D1 capture on D0 falling edge..."
timeout --signal=INT --kill-after=2s "$((CAPTURE_MS / 1000 + 15))s" \
  sigrok-cli -d "$LOGIC_CONN" -c "samplerate=$SAMPLERATE" -C D0,D1 \
    -t D0=f --samples "$CAPTURE_SAMPLES" -O srzip -o "$LOGIC_LOG" &
LOGIC_PID=$!
sleep 1

echo "Generating $PRESS_COUNT active-low presses; final state is GPIO21 LOW/safe..."
mpremote connect "$SHRIKE_UART" exec \
  "from machine import Pin; import time
p=Pin(21, Pin.OUT); p.value(1); print('V03D_PRESS_START')
for _ in range($((PRESS_COUNT - 1))):
    p.value(0); time.sleep_ms($PRESS_LOW_MS)
    p.value(1); time.sleep_ms($REARM_HIGH_MS)
p.value(0); time.sleep_ms($FINAL_LOW_MS); print('V03D_PRESS_DONE', p.value())" ||
  die "Shrike press cycle failed"

wait "$LOGIC_PID"
LOGIC_STATUS=$?
LOGIC_PID=""
wait "$UART_PID" || true
UART_PID=""

echo
echo "logic-analyzer exit: $LOGIC_STATUS"
ls -lh "$UART_LOG" "$LOGIC_LOG" 2>/dev/null || true
sha256sum "$UART_LOG" "$LOGIC_LOG" 2>/dev/null || true

echo
rg -a -n 'PI5_BENCH_READY|PI5_V03D_READY|PI5_MB|PI5_ESTOP_REARM|PI5_BENCH_FAIL|panic|fatal|watchdog' \
  "$UART_LOG" || true

ok=1
for marker in "${EXPECTED[@]}"; do
    if rg -aq "$marker" "$UART_LOG"; then
        echo "ok      $marker"
    else
        echo "MISSING $marker"
        ok=0
    fi
done
for marker in "${FORBIDDEN[@]}"; do
    if rg -aiq "$marker" "$UART_LOG"; then
        echo "FORBIDDEN MARKER PRESENT: $marker"
        ok=0
    fi
done

mb_count="$(rg -ac 'PI5_MB' "$UART_LOG" 2>/dev/null || echo 0)"
rearm_count="$(rg -ac 'PI5_ESTOP_REARM' "$UART_LOG" 2>/dev/null || echo 0)"
rearm_ok_count="$(rg -ac 'PI5_ESTOP_REARM mode=gpio code=0' "$UART_LOG" 2>/dev/null || echo 0)"
echo "PI5_MB count: $mb_count (need >= $PRESS_COUNT)"
echo "successful PI5_ESTOP_REARM count: $rearm_ok_count (need >= $((PRESS_COUNT - 1)))"
if [ "$mb_count" -lt "$PRESS_COUNT" ] ||
   [ "$rearm_ok_count" -lt "$((PRESS_COUNT - 1))" ] ||
   [ "$rearm_count" -ne "$rearm_ok_count" ]; then
    ok=0
fi

if [ "$LOGIC_STATUS" -ne 0 ] || [ ! -s "$LOGIC_LOG" ]; then
    echo "LOGIC_CAPTURE_INCOMPLETE"
    ok=0
elif ! "$REPO/scripts/hil/v03d-reduce.py" --count "$PRESS_COUNT" "$LOGIC_LOG"; then
    ok=0
fi

if [ "$ok" -eq 1 ]; then
    echo "PASS: V03-D GPIO24 active-low e-stop -> GPIO12 LOW, N=$PRESS_COUNT"
    exit 0
fi
echo "FAIL: V03-D e-stop HIL run (GPIO21 remains LOW/safe)"
exit 1
