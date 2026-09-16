#!/usr/bin/env bash
set -euo pipefail

readonly ELF2UF2_PACKAGE='elf2uf2-rs@2.2.0'
readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET='thumbv6m-none-eabi'
readonly ELF="$HERE/target/$TARGET/release/shrike_rp2040"
readonly BITSTREAM="$HERE/../fpga/forgefpga/axiomos_r04_mcu.bin"
readonly ELF2UF2_ROOT="$HERE/target/tools/elf2uf2-rs-2.2.0"
readonly ELF2UF2="$ELF2UF2_ROOT/bin/elf2uf2-rs"

case "${1:-}" in
    '') readonly UF2="$HERE/target/$TARGET/release/shrike_rp2040.uf2"; readonly -a FEATURES=(); readonly -a FPGA_CHECK=() ;;
    --runtime) readonly UF2="$HERE/target/$TARGET/release/shrike_rp2040_runtime.uf2"; readonly -a FEATURES=(--features fpga-runtime); readonly -a FPGA_CHECK=(--fpga-bitstream "$BITSTREAM") ;;
    *) echo "usage: build-uf2.sh [--runtime]" >&2; exit 2 ;;
esac

cd "$HERE"
RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo build --locked --release --target "$TARGET" "${FEATURES[@]}"
cargo install --locked --force --no-default-features --root "$ELF2UF2_ROOT" "$ELF2UF2_PACKAGE"
"$ELF2UF2" "$ELF" "$UF2"
python3 "$HERE/verify_flash_contract.py" --root "$(cd "$HERE/../../.." && pwd)" --allow-missing-factory --converter-version 2.2.0 --uf2 "$UF2" "${FPGA_CHECK[@]}"
if ((${#FPGA_CHECK[@]})); then
    sha256sum "$ELF" "$UF2" "$BITSTREAM" > "$UF2.sha256"
else
    sha256sum "$ELF" "$UF2" > "$UF2.sha256"
fi
