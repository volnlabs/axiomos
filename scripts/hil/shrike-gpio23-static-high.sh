#!/usr/bin/env bash
# Static-high electrical isolation check for Shrike GPIO22 -> Pi GPIO23.
#
# Required wiring:
#   Shrike GPIO22 -> 2.2 kOhm -> Pi physical pin 16 / GPIO23
#   Shrike GND ----------------> Pi GND
#   Logic-analyzer D0 must be disconnected for this test.
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
RUN_DIR="${RUN_DIR:-$REPO/artifacts/runs/axiomos-hil-20260720T134903Z/03-gpio}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
SHRIKE_UART="${SHRIKE_UART:-/dev/serial/by-id/usb-SHRIKE_Board_in_Micropython_Mode_de65143857942625-if00}"
READY_TIMEOUT="${READY_TIMEOUT:-35}"
UART_SECONDS="${UART_SECONDS:-180}"
UART_PID=""
HIGH_ACTIVE=0

die() {
    echo "ABORT: $*" >&2
    exit 1
}

require_rw() {
    local path="$1"
    local label="$2"
    local target

    test -e "$path" || die "$label missing: $path"
    target="$(readlink -f "$path")"
    if ! test -r "$path" || ! test -w "$path"; then
        echo "$label needs ACL on $target"
        sudo setfacl -m "u:$(id -un):rw" "$target"
    fi
}

set_shrike_low() {
    mpremote connect "$SHRIKE_UART" exec \
      "from machine import Pin; p=Pin(22,Pin.OUT); p.value(0); print('GPIO22_LOW')" \
      >/dev/null 2>&1
}

cleanup() {
    if [ "$HIGH_ACTIVE" = 1 ]; then
        echo
        echo "Returning Shrike GPIO22 low..."
    fi
    set_shrike_low || true
    HIGH_ACTIVE=0

    if [ -n "$UART_PID" ]; then
        kill "$UART_PID" 2>/dev/null || true
        wait "$UART_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

require_rw "$PI_UART" "Pi UART"
require_rw "$SHRIKE_UART" "Shrike UART"

SHRIKE_DEV="$(readlink -f "$SHRIKE_UART")"
if fuser "$SHRIKE_DEV" >/dev/null 2>&1; then
    echo "ABORT: Shrike serial port is already in use:"
    fuser -v "$SHRIKE_DEV" || true
    exit 1
fi

mkdir -p "$RUN_DIR"
idx=0
for file in "$RUN_DIR"/shrike-gpio23-static-high-*-uart.log; do
    number="${file##*/shrike-gpio23-static-high-}"
    number="${number%%-*}"
    case "$number" in
        ''|*[!0-9]*) continue ;;
    esac
    [ "$((10#$number))" -gt "$idx" ] && idx=$((10#$number))
done
PROBE="$(printf '%02d' "$((idx + 1))")"
UART_LOG="$RUN_DIR/shrike-gpio23-static-high-$PROBE-uart.log"

echo "Required wiring:"
echo "  Shrike GPIO22 -> 2.2 kOhm -> Pi physical pin 16 / GPIO23"
echo "  Shrike GND ----------------> Pi GND"
echo "  Logic D0 DISCONNECTED"
echo "  Pi currently UNPOWERED"
echo
read -r -p "Type READY when that is true: " CONFIRMATION
[ "$CONFIRMATION" = "READY" ] || die "confirmation did not match"

echo "Forcing Shrike GPIO22 low before Pi power-on..."
if ! mpremote connect "$SHRIKE_UART" exec \
  "from machine import Pin; p=Pin(22,Pin.OUT); p.value(0); print('GPIO22_LOW')"; then
    echo
    echo "Shrike serial access failed. Current users:"
    fuser -v "$SHRIKE_DEV" || true
    exit 1
fi

stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo
timeout --signal=INT --kill-after=2s "${UART_SECONDS}s" \
  stdbuf -o0 cat "$PI_UART" |
  stdbuf -o0 tr -d '\r' |
  stdbuf -o0 tee "$UART_LOG" &
UART_PID=$!

echo
echo "Power the Pi from its official supply during this countdown:"
for n in 5 4 3 2 1; do
    echo "  $n"
    sleep 1
done
echo "Waiting for PI5_BENCH_READY..."

waited=0
until rg -aq 'PI5_BENCH_READY' "$UART_LOG" 2>/dev/null; do
    if rg -aiq 'PI5_BENCH_FAIL|panic|fatal|watchdog' "$UART_LOG" 2>/dev/null; then
        die "Pi emitted a failure marker before PI5_BENCH_READY"
    fi
    if [ "$waited" -ge "$READY_TIMEOUT" ]; then
        die "no PI5_BENCH_READY after ${READY_TIMEOUT}s"
    fi
    sleep 1
    waited=$((waited + 1))
done

echo "PI5_BENCH_READY seen. Driving Shrike GPIO22 high..."
mpremote connect "$SHRIKE_UART" exec \
  "from machine import Pin; p=Pin(22,Pin.OUT); p.value(1); print('GPIO22_HIGH',p.value())" ||
  die "could not drive Shrike GPIO22 high"
HIGH_ACTIVE=1

echo
echo "GPIO22 is now held HIGH. Measure against Pi GND:"
echo "  1. Shrike side of resistor"
echo "  2. Pi side of resistor / physical pin 16"
echo "  3. Directly across the resistor"
echo
read -r -p "Press Enter after recording all three readings. "

echo "Measurements complete."
set_shrike_low || die "could not return Shrike GPIO22 low"
HIGH_ACTIVE=0

kill "$UART_PID" 2>/dev/null || true
wait "$UART_PID" 2>/dev/null || true
UART_PID=""

echo "GPIO22_LOW"
echo "UART log: $UART_LOG"
sha256sum "$UART_LOG"
