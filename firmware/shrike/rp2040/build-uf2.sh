#!/usr/bin/env bash
set -euo pipefail

# Pin the standalone converter: cargo install elf2uf2-rs@2.2.0 --locked.
readonly ELF2UF2_PACKAGE='elf2uf2-rs@2.2.0'
readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET='thumbv6m-none-eabi'
readonly ELF="$HERE/target/$TARGET/release/shrike_rp2040"
readonly UF2="$HERE/target/$TARGET/release/shrike_rp2040.uf2"

cd "$HERE"
RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo build --locked --release --target "$TARGET"
command -v elf2uf2-rs >/dev/null || {
    echo "install pinned converter: cargo install $ELF2UF2_PACKAGE --locked" >&2
    exit 1
}
elf2uf2-rs "$ELF" "$UF2"
python3 "$HERE/verify_flash_contract.py" --root "$(cd "$HERE/../../.." && pwd)" --uf2 "$UF2"
sha256sum "$ELF" "$UF2" > "$UF2.sha256"
