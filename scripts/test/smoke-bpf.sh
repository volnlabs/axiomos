#!/bin/bash
# BPF load-path smoke test (#146).
#
# Boots the kernel in QEMU (x86_64, headless) and asserts that the
# /bin/sched_switch_export_demo BPF path runs end-to-end: ringbuf MAP_CREATE
# -> PROG_LOAD -> PROG_ATTACH -> OBJ_PIN. This demo consumes per-hook context
# data through ctx.data, the exact path that #146 (and the whole Track A era)
# silently broke because nothing checked the demo's own load result.
#
# Fails loudly if any success marker is missing or any reject/panic appears.
#
# Usage: ./scripts/smoke-bpf.sh
# Requires /dev/kvm for the x86 accel path.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG="$(mktemp -t axiomos-smoke-bpf.XXXXXX.log)"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-540}"

cd "$PROJECT_DIR"

echo "=== BPF smoke: booting x86_64 kernel in QEMU (timeout ${BOOT_TIMEOUT}s) ==="
# Kernel idles forever after boot, so timeout is the normal exit; we judge by
# the serial log, not the exit code.
timeout "$BOOT_TIMEOUT" cargo run -- --headless >"$LOG" 2>&1 || true

# Markers that must ALL be present for a healthy BPF load path.
REQUIRED=(
    "program loaded with id"
    "attached prog 0 to type 7"
    "Pinning ringbuf map object"
)
# Any of these means a broken load/verify/boot.
FORBIDDEN="rejected by verifier|VerificationFailed|wrong type|kernel panic|\bpanic\b"

fail=0
for marker in "${REQUIRED[@]}"; do
    if ! grep -qF "$marker" "$LOG"; then
        echo "FAIL: missing expected marker: '$marker'"
        fail=1
    fi
done

if grep -qiE "$FORBIDDEN" "$LOG"; then
    echo "FAIL: found reject/panic in boot log:"
    grep -niE "$FORBIDDEN" "$LOG" | head
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "=== BPF smoke FAILED. Full log: $LOG ==="
    exit 1
fi

echo "=== BPF smoke PASSED (sched_switch_export_demo loaded + attached + pinned) ==="
rm -f "$LOG"
