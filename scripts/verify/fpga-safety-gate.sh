#!/usr/bin/env bash
# Verify the synthesizable Shrike-lite final PWM safety gate.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

for command in python3 iverilog vvp; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "error: FPGA safety-gate verification requires $command" >&2
        echo "install Icarus Verilog (for example: sudo apt install iverilog)" >&2
        exit 2
    fi
done

# The reference gate, runtime RTL and declared pin/clock contract must agree.
python3 - <<'PY_CONTRACT'
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
base = Path("firmware/shrike/fpga")
assert (base / "shrike_safety_gate.sv").read_text().splitlines() == (base / "forgefpga/ffpga/src/shrike_safety_gate.v").read_text().splitlines()[1:]
project = ET.parse(base / "forgefpga/axiomos_r04.ffpga").getroot()
records = project.findall(".//io-spec-tool/records/record")
actual = {r.findtext("port-name"): r.attrib["id"] for r in records}
with (base / "forgefpga/io-plan.csv").open() as stream:
    rows = [r for r in csv.DictReader(stream) if r["fabric_resource"]]
expected = {r["logical_signal"]: r["fabric_resource"] for r in rows}
assert len(actual) == len(records) == len(set(actual.values())) == 17
assert len(expected) == len(rows) == 17 and actual == expected
assert [r.attrib["filename"] for r in project.findall(".//timing-constraints/module")] == ["clk_50mhz.sdc"]
print("PASS: FPGA reference/runtime source and 17 pin assignments agree; nominal clock registered")
PY_CONTRACT

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/shrike-fpga.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

iverilog -g2012 -s tb_shrike_safety_gate -o "$tmpdir/safety-gate.vvp" \
    firmware/shrike/fpga/shrike_safety_gate.sv \
    firmware/shrike/fpga/tb_shrike_safety_gate.sv
vvp "$tmpdir/safety-gate.vvp"

for watchdog_cycles in 2048 2049 4097 2500000; do
    printf 'FPGA watchdog model: %s cycles\n' "$watchdog_cycles"
    iverilog -g2005 -Wall -s tb_axiomos_r04_top \
        -Ptb_axiomos_r04_top.WATCHDOG_CYCLES="$watchdog_cycles" -o "$tmpdir/runtime-link.vvp" \
        firmware/shrike/fpga/forgefpga/ffpga/src/top.v \
        firmware/shrike/fpga/forgefpga/ffpga/src/spi_target.v \
        firmware/shrike/fpga/forgefpga/ffpga/src/shrike_safety_gate.v \
        firmware/shrike/fpga/forgefpga/sim/tb_axiomos_r04_top.v
    runtime_status=0
    runtime_log="$(vvp "$tmpdir/runtime-link.vvp")" || runtime_status=$?
    printf '%s\n' "$runtime_log"
    if ((runtime_status != 0)) || grep -q '^FAIL:' <<<"$runtime_log" \
        || ! grep -q '^PASS: axiomos_r04_forgefpga_runtime_link$' <<<"$runtime_log"; then
        exit 1
    fi
done

echo "NOTE: software simulation passed; ForgeFPGA synthesis/bitstream evidence is not produced by this gate."
