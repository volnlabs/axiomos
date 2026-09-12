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

GPIO14/15 are the only RP2040 PWM inputs to the FPGA; GPIO18/19 are unused and
must not be connected to an L298N. The current firmware owns the R0.4 FPGA pins
but deliberately remains safe-low and non-operational because no validated
bitstream/timing manifest or atomic UART/watchdog/e-stop runtime adapter exists.
Tomorrow's wiring review must confirm the GPIO5 normally-closed e-stop loop,
common ground, GPIO10/11 wiring, and the required 5 V-to-3.3 V echo divider.
