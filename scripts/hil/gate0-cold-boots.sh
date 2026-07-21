#!/usr/bin/env bash
# Gate 0: three cold boots from the exact retained image must pass.
#
# Grades each boot against the expected/forbidden marker lists in the image's
# build.toml. PI5_BENCH_READY proves route initialisation only - the physical
# GPIO interrupt probe is scripts/hil/gpio23-probe.sh, a separate gate.
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
RUN_DIR="${RUN_DIR:-$REPO/artifacts/runs/axiomos-hil-20260720T134903Z/02-pi-boot}"
IMAGE_DIR="${IMAGE_DIR:-$RUN_DIR/image-v03-gate0}"
PI_UART="${PI_UART:-/dev/serial/by-id/usb-Raspberry_Pi_Debug_Probe__CMSIS-DAP__E6633861A355B838-if01}"
BOOTS="${BOOTS:-3}"
BOOT_SECONDS="${BOOT_SECONDS:-30}"

EXPECTED=(PI5_BENCH_READY INIT_PROCESS_STARTED PI5_BOOT_OK SIGNED_BPF_LOAD_OK)
FORBIDDEN=(PI5_BENCH_FAIL panic fatal watchdog)

if ! test -r "$PI_UART" || ! test -w "$PI_UART"; then
    echo "ABORT: no read/write access to $PI_UART" >&2
    exit 1
fi
if ! ( cd "$IMAGE_DIR" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
    echo "ABORT: $IMAGE_DIR fails its own SHA256SUMS" >&2
    exit 1
fi

want=$(awk -F'"' '/^kernel8_sha256/ {print $2}' "$IMAGE_DIR/build.toml")
echo "Gate 0: $BOOTS cold boots from $(basename "$IMAGE_DIR")"
echo "kernel8.img must be $want"
echo "Flash it first if the card still holds another build."
echo

stty -F "$PI_UART" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo

pass=0
for boot in $(seq 1 "$BOOTS"); do
    log="$RUN_DIR/gate0-cold-boot-$boot.log"
    if [ -e "$log" ]; then
        echo "ABORT: $log already exists - move the previous Gate 0 evidence aside" >&2
        exit 1
    fi

    echo "--- boot $boot/$BOOTS: power the Pi OFF, then ON when capture starts ---"
    timeout --signal=INT --kill-after=2s "${BOOT_SECONDS}s" \
      stdbuf -o0 cat "$PI_UART" |
      stdbuf -o0 tr -d '\r' |
      stdbuf -o0 tee "$log" >/dev/null &
    uart_pid=$!
    sleep 1
    echo "    CAPTURE ACTIVE - power on now (${BOOT_SECONDS}s window)"
    wait "$uart_pid"

    ok=1
    for m in "${EXPECTED[@]}"; do
        if rg -aq "$m" "$log"; then
            echo "    ok      $m"
        else
            echo "    MISSING $m"
            ok=0
        fi
    done
    for m in "${FORBIDDEN[@]}"; do
        if rg -aq "$m" "$log"; then
            echo "    FORBIDDEN MARKER PRESENT: $m"
            ok=0
        fi
    done

    if [ "$ok" = 1 ]; then
        echo "    boot $boot PASS"
        pass=$((pass + 1))
    else
        echo "    boot $boot FAIL -> $log"
    fi
    echo
done

echo "Gate 0: $pass/$BOOTS boots passed"
[ "$pass" = "$BOOTS" ] || exit 1
echo "GATE 0 PASS - v0.3 wiring may begin"
