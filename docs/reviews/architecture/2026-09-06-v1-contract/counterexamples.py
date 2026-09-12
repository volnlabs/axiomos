#!/usr/bin/env python3
"""Reproduce review counterexamples against the checked-out source; not a pass gate.

Requires python3, rustc, iverilog, and vvp. No repository source is modified.
The RTL probe exercises shrike_safety_gate, not electrical hardware or full top.
"""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]


def run(*args):
    subprocess.run(args, check=True)


with tempfile.TemporaryDirectory(prefix="axiomos-review-") as directory:
    tmp = Path(directory)
    rust = tmp / "watchdog.rs"
    rust.write_text('''
#[allow(dead_code)]
pub enum Msg {
    MotorSetpoint { seq: u8, left: i16, right: i16 },
    Estop { assert: bool },
    HeartbeatToShrike { seq: u8 },
    Sensor { ultrasonic_echo_us: u32, estop_line: bool, flags: u8 },
    HeartbeatToPi { seq: u8 },
}
#[path = "''' + str(ROOT / "kernel/crates/shrike_link/src/watchdog.rs") + '''"]
#[allow(dead_code)]
mod watchdog;
use watchdog::{Output, Watchdog};
fn main() {
    let mut wd = Watchdog::new(100);
    wd.on_msg(&Msg::MotorSetpoint { seq: 1, left: 50, right: 50 }, 0);
    for now in [90, 180, 270, 360] {
        assert!(wd.on_msg(&Msg::HeartbeatToShrike { seq: 7 }, now));
        assert_eq!(wd.output(now), Output::Drive { left: 50, right: 50 });
    }
    println!("REPLAYED_HEARTBEAT_RETAINS_OLD_DRIVE");
    assert_eq!(wd.output(460), Output::SafeStop);
    wd.on_msg(&Msg::HeartbeatToShrike { seq: 7 }, 461);
    assert_eq!(wd.output(461), Output::Drive { left: 50, right: 50 });
    println!("HEARTBEAT_AFTER_TIMEOUT_REVIVES_OLD_DRIVE");
}
''')
    run("rustc", "--edition=2021", str(rust), "-o", str(tmp / "watchdog"))
    run(str(tmp / "watchdog"))

    rtl = tmp / "gate.v"
    rtl.write_text('''
`timescale 1ns/1ps
module tb;
  reg valid = 1, estop_n = 1, pwm = 1;
  reg signed [11:0] duty = 1;
  wire left_out, right_out;
  shrike_safety_gate dut (
    .command_valid(valid), .estop_n(estop_n),
    .left_duty_permille(duty), .right_duty_permille(duty),
    .left_pwm_in(pwm), .right_pwm_in(pwm),
    .left_pwm_out(left_out), .right_pwm_out(right_out)
  );
  initial begin
    #1000;
    if (left_out !== 1 || right_out !== 1) $fatal(1, "gate changed");
    $display("ONE_PERMILLE_COMMAND_PASSES_CONTINUOUS_HIGH");
    estop_n = 0; #1;
    if (left_out !== 0 || right_out !== 0) $fatal(1, "assert did not stop");
    estop_n = 1; #1;
    if (left_out !== 1 || right_out !== 1) $fatal(1, "release behavior changed");
    $display("ESTOP_RELEASE_RESTORES_OUTPUT_WITHOUT_NEW_COMMAND");
    $finish;
  end
endmodule
''')
    run("iverilog", "-g2012", "-s", "tb", "-o", str(tmp / "gate"), str(rtl),
        str(ROOT / "firmware/shrike/fpga/forgefpga/ffpga/src/shrike_safety_gate.v"))
    run("vvp", str(tmp / "gate"))

spec = importlib.util.spec_from_file_location(
    "v04", ROOT / "scripts/benchmark/analyze-v04.py")
v04 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v04)
rows = ["V04_CHUNK chunk_id=1 stage=start ts_ns=0"]
for i in range(1, 101):
    start = 1 + (i - 1) * 210_000_000
    for j, stage in enumerate(v04.STAGES):
        rows.append(f"V04_BEHAVIOR sample_id={i} behavior=drive stage={stage} ts_ns={start + j * 40_000_000}")
now = 21_000_000_000
for i in range(1, 1001):
    rows.extend([
        f"V04_ECHO_DONE sample_id={i} echo_us=100 ts_ns={now}",
        f"V04_HOOK_ENTRY sample_id={i} ts_ns={now + 1}",
        f"V04_MOTOR_CMD sample_id={i} seq={i % 256} left=1 right=1 ts_ns={now + 2}",
    ])
    now += 3
for i in range(1, 101):
    rows.append(f"V04_ESTOP event_id={i} source=operator stage=assert ts_ns={now}")
    now += 1
rows.extend([f"V04_HEARTBEAT seq=1 ts_ns={now}",
             f"V04_CHUNK chunk_id=1 stage=end ts_ns={now + 1}"])
result = v04.analyze("\n".join(rows), max_chunk_gap_ns=1_000_000_000,
                     max_heartbeat_gap_ns=1_000_000_000)
assert any(stats.get("max") == 200_000_000 for stats in result.values())
print("SERIAL_ANALYZER_ACCEPTS_200MS_LOADS_100_ASSERTS_ONLY_21SECOND_CAPTURE")
print("Counterexamples reproduced. This is evidence of gaps, not release acceptance.")
