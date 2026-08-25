#!/usr/bin/env bash
set -euo pipefail

readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly UF2="$(realpath -- "${1:?usage: flash-uf2.sh custom.uf2 RPI-RP2-mountpoint}")"
readonly MOUNT="${2:?usage: flash-uf2.sh custom.uf2 RPI-RP2-mountpoint}"
readonly SIDECAR="$UF2.sha256"

test -f "$SIDECAR" || { echo "missing UF2 hash sidecar: $SIDECAR" >&2; exit 1; }
line="$(awk -v file="$UF2" '$2 == file { if (++n == 1) print; else exit 1 } END { exit n == 1 ? 0 : 1 }' "$SIDECAR")" || {
    echo "UF2 hash sidecar must contain exactly one entry for $UF2" >&2
    exit 1
}
printf '%s\n' "$line" | sha256sum --check --status - || {
    echo "UF2 hash sidecar does not verify $UF2" >&2
    exit 1
}
python3 "$HERE/verify_flash_contract.py" --root "$(cd "$HERE/../../.." && pwd)" --uf2 "$UF2"
test -d "$MOUNT"
cp "$UF2" "$MOUNT/"
sync
