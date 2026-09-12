# Operations

These documents are the canonical instructions for repository workflows.
Stable orchestration uses `cargo xtask`; focused scripts remain implementation
adapters.

- [Build](build.md)
- [Boot and run](boot.md)
- [Testing](testing.md)
- [Release verification](release-verification.md)
- [Hardware validation and benchmarking](hardware-validation-and-benchmarking.md)
- Wiring sheets: [Pi 5 UART](wiring/axiomos-test-01-pi5-uart-wiring.pdf),
  [unloaded e-stop](wiring/axiomos-estop-wiring.pdf), and
  [unloaded PWM](wiring/axiomos-pwm-wiring.pdf). Their generators and previews
  are retained alongside the PDFs in `wiring/`.
- [Ring-3 debugging](debugging/ring3-triage.md)
