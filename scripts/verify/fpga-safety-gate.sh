#!/usr/bin/env bash
# Verify the synthesizable Shrike-lite final PWM safety gate.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

for command in iverilog vvp; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "error: FPGA safety-gate verification requires $command" >&2
        echo "install Icarus Verilog (for example: sudo apt install iverilog)" >&2
        exit 2
    fi
done

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/shrike-fpga.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

iverilog -g2012 -s tb_shrike_safety_gate -o "$tmpdir/safety-gate.vvp" \
    firmware/shrike/fpga/shrike_safety_gate.sv \
    firmware/shrike/fpga/tb_shrike_safety_gate.sv
vvp "$tmpdir/safety-gate.vvp"

iverilog -g2005 -Wall -s tb_axiomos_r04_top -o "$tmpdir/runtime-link.vvp" \
    firmware/shrike/fpga/forgefpga/ffpga/src/top.v \
    firmware/shrike/fpga/forgefpga/ffpga/src/spi_target.v \
    firmware/shrike/fpga/forgefpga/ffpga/src/shrike_safety_gate.v \
    firmware/shrike/fpga/forgefpga/sim/tb_axiomos_r04_top.v
runtime_log="$(vvp "$tmpdir/runtime-link.vvp")"
printf '%s\n' "$runtime_log"
if grep -q '^FAIL:' <<<"$runtime_log" \
    || ! grep -q '^PASS: axiomos_r04_forgefpga_runtime_link$' <<<"$runtime_log"; then
    exit 1
fi

echo "NOTE: software simulation passed; ForgeFPGA synthesis/bitstream evidence is not produced by this gate."
