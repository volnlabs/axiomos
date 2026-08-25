#!/usr/bin/env bash
set -euo pipefail

readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly UF2="${1:?usage: flash-uf2.sh custom.uf2 RPI-RP2-mountpoint}"
readonly MOUNT="${2:?usage: flash-uf2.sh custom.uf2 RPI-RP2-mountpoint}"

python3 "$HERE/verify_flash_contract.py" --root "$(cd "$HERE/../../.." && pwd)" --uf2 "$UF2"
test -d "$MOUNT"
cp "$UF2" "$MOUNT/"
sync
