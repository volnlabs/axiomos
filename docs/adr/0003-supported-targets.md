# ADR-0003: Supported target and feature matrix

- Status: Accepted
- Date: 2026-07-14

## Decision

| Target | Status | Required release evidence |
|---|---|---|
| x86_64 QEMU/OVMF | Supported | Build, strict lint, host suites, signed production boot, unsigned development negative tests, and SMP QEMU integration tests. |
| AArch64 Raspberry Pi 5 | Supported after HIL | Build, strict lint, production signing policy, physical boot, GPIO IRQ, control-link, timer, storage, and failure-state HIL. |
| AArch64 `virt` | Experimental | Compile check only; it is not a production hardware claim. |
| RISC-V demo | Experimental standalone | Lives outside the production kernel and release artifact. It receives compile/lint coverage but no axiomos compatibility claim. |
| RP2040 firmware | Supported after HIL | Target lint/build, mock-HAL state-machine tests, and physical control-link/watchdog/failsafe HIL. |

Only `cloud-profile` and `embedded-profile` are shipped BPF limit sets. Production
images are signed-only. Unsigned BPF is an explicit development-image feature
and must never appear in production provenance.

Parallel RISC-V kernel entrypoints and unused architecture features will be
removed or relocated under an `experiments/` boundary. Generated target tables
and CI inventory are derived from the component manifest rather than prose.
