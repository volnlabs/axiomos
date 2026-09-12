# Shrike Firmware

- `control/`: platform-independent control and motor state machines.
- `rp2040/`: physical RP2040 firmware and target configuration.
- `simulation/`: mock-HAL host simulation and state-machine tests.
- `vendor/`: hash-pinned Shrike-lite V1.0/R0.4 electrical sources and the
  upstream ForgeFPGA scaffold.

Crate package names remain `shrike_control`, `shrike_rp2040`, and
`shrike_rp2040_host_sim`. Paths communicate product ownership; package names
preserve dependency and artifact identity.

The compile-time R0.4 profile reserves GPIO0–3 for FPGA SPI, GPIO12/13 for
FPGA power/enable, GPIO14/15 for the post-configuration FPGA link, and GPIO4
for the MCU LED. Provisional external assignments are GPIO5 e-stop observe,
GPIO6–9 motor direction, GPIO10/11 ultrasonic, and GPIO16/17 Pi UART.

GPIO14/15 are retained MCU-to-FPGA interconnects; the current RTL ignores their
PWM inputs and generates both final PWM outputs from accepted signed commands.
GPIO6–9 belong to the legacy MCU direction adapter. The operational path requires
both FPGA direction outputs and final PWM outputs on reviewed FPGA pads.
GPIO18/19 are unused and must not be connected to an L298N.

The current firmware owns the R0.4 FPGA pins but deliberately remains safe-low
and non-operational: the validated bitstream/timing manifest and concrete paired
UART/watchdog/e-stop runtime adapter are absent. The bench wiring review must
confirm the physical FPGA e-stop path, GPIO5 observation, common ground,
GPIO10/11 wiring, and the required 5 V-to-3.3 V echo divider. Follow the
[bench plan](../../docs/plans/active/shrike-fpga-bench.md); keep motors, drivers
and motor power disconnected throughout electronics acceptance.
