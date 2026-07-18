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

output="$(mktemp "${TMPDIR:-/tmp}/shrike-safety-gate.XXXXXX.vvp")"
trap 'rm -f "$output"' EXIT

iverilog -g2012 -s tb_shrike_safety_gate -o "$output" \
    firmware/shrike/fpga/shrike_safety_gate.sv \
    firmware/shrike/fpga/tb_shrike_safety_gate.sv
vvp "$output"
