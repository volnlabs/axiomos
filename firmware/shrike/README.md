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
GPIO6–9 motor direction, GPIO10/11 ultrasonic, GPIO16/17 Pi UART, and GPIO18/19
unloaded PWM.

Do not flash or connect GPIO18/19 to an L298N. They only keep the existing
control firmware buildable while the ForgeFPGA runtime link is implemented.
Tomorrow's wiring review must confirm the GPIO5 normally-closed e-stop loop,
common ground, GPIO10/11 wiring, and the required 5 V-to-3.3 V echo divider.
