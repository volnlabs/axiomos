# Shrike Firmware

- `control/`: platform-independent control and motor state machines.
- `rp2040/`: physical RP2040 firmware and target configuration.
- `simulation/`: mock-HAL host simulation and state-machine tests.

Crate package names remain `shrike_control`, `shrike_rp2040`, and
`shrike_rp2040_host_sim`. Paths communicate product ownership; package names
preserve dependency and artifact identity.
