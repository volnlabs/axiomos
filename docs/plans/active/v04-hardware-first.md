---
title: Hardware-first path from PR 35 to v1
status: active
updated: 2026-09-07
---

# Hardware-first implementation sequence

The immediate deliverable is the v0.4 prerequisite repair, followed by physical
acceptance of v0.3/v0.4. Later milestones remain gated; this document does not
claim that v0.4 hardware or v1 runtime evolution is complete. Baseline:
`4f5aa9037832b9ee27145c5ffc87f4c3ca707e18` (PR #35 implementation snapshot).

## Milestones and exit conditions

| Order | Milestone | Work and exit condition | Deliberately waits |
|---|---|---|---|
| 1 | v0.4 software prerequisites | Preserve interrupted registers; remove PWM-driver callbacks into behavior dispatch; signed atomic motor pairs with bounded pending work; command freshness independent of heartbeat; final FPGA PWM, stop/rearm and accepted-sequence acknowledgement; reject evidence that misses its stated bound. | Hardware claims and v0.5 lifecycle machinery. |
| 2 | v0.3 physical closure | Run the existing staged GPIO/helper/PWM/e-stop campaign on the exact candidate; retain raw captures, wiring and artifact identities. Model-only helper benchmarks cannot substitute for the live helper path. | New boards, generic HAL, additional peripherals. |
| 3 | v0.4 reference robot | Supply the validated board inputs below, implement the one concrete MCU adapter and paired loop, then run existing sensor-to-behavior-to-final-output fault tests and 24-hour soak. | Runtime replacement, general migration, Linux integration. |
| 4 | v0.5 A: behavior ownership | Use existing BpfManager, bounded maps and generational handles. Add one kernel-owned behavior record covering code, private maps, admission and attachments; failed preparation must leave live state/resource usage unchanged. Repeated retire/unload cycles return to the defined bound. | New parallel registries, persistent state migration. |
| 5 | v0.5 B: runtime replacement | Prepare a verified/admitted candidate off the active path; publish at a quiescent boundary; start with fresh private state. Retain at most one previous artifact for explicit manual rollback with fresh state. Bounded flight recorder identifies activation, requests, decisions and stop causes; overflow never blocks control. | Automatic policy rollback, general state migration, fleet management. |
| 6 | v0.6: operational hardening | Make cold boot/restart and failed update behavior explicit; signed bundle/tooling, resource and error contracts usable by another engineer. Retained audit export must distinguish software decisions from observed physical outputs. | Persistent security anti-rollback, recovery partitions, durable execution history unless justified by actual v1 failure cases. |
| 7 | v0.9: release candidate | Freeze only the narrow versioned behavior/helper/context/link contract exercised by the reference robot. Run the full acceptance gate, including 72-hour whole-system soak and independent clean artifact comparison. | Broad syscall compatibility and speculative APIs. |
| 8 | v1.0 | Ship the signed, verified, admitted, bounded runtime-programmable reference robot and its retained evidence. Publish explicit timing models, measured maxima and non-guarantees separately. | Linux/AMP, Jetson, ROS2 breadth, fleet infrastructure and research mechanisms. |

## Hardware inputs blocking the operational MCU adapter

1. Generated R0.4 runtime bitstream with exact length/hash, tool/project identity
   and its flash placement/programming procedure. The current project is not a
   synthesized artifact.
2. Authoritative PWR/EN/configuration/READY sequence and timing, SPI/CS bounds,
   and configuration-to-runtime pin handoff. The status read after a command
   must identify that command's accepted sequence.
3. Reviewed final FPGA pin assignments and continuity for reset, physical
   e-stop, both motor enables and direction signals; resolve provisional
   interconnect assignments. No pin or polarity is inferred from simulation.
4. Attributable board-compatible factory recovery UF2. The recovery record
   currently has `factory_uf2.ready=false`; retain the flash guard.

After those inputs arrive, implement `R04Platform` once, replace the legacy
control loop's independent motor calls with one paired FPGA transaction, and
wire accepted Pi command freshness into that loop. Keep startup fail-closed on
hash, configuration, READY, transfer or acknowledgement failure. Do not enable
`fpga-runtime` or remove its build guard merely because host tests pass.

## Software verification for this tranche

The regression checks execute production vector assembly, watchdog/control
logic, FPGA lifecycle, monitor and RTL. They do not establish physical timing,
synthesis success, pad routing, motor polarity or electrical fail-safe behavior.

```sh
python3 -B scripts/verify/aarch64-exception-context.py
python3 -B scripts/verify/rootfs-selection.py
cargo test --locked -p shrike_link -p shrike_control -p shrike_rp2040_host_sim
cargo test --locked -p kernel_bpf --features embedded-profile
EMBEDDED_DISK_PATH=/dev/null cargo test --locked -p kernel --lib --features embedded-profile pwm_observation_attach_is_rejected_without_publication
scripts/verify/fpga-safety-gate.sh
python3 scripts/verify/abi-surface.py
```

The rootfs test checks Cargo's A → B → unset input selection and equal fallback
bytes in two clean output directories. It is not a reproducibility claim for
the complete kernel/MCU/FPGA release. The AArch64 canary executes SVC and a real
emulated timer IRQ through production vector code; it is not physical Pi IRQ
latency evidence.

## Verification record for the prerequisite patch

Executed locally on 2026-09-07:

- Production AArch64 vector canary: SVC and timer IRQ pass; the original x9
  save order failed the same canary.
- Rootfs selection: A → B → unset and independent fallback build pass; the
  original missing Cargo environment dependency failed A → B.
- Full embedded `kernel_bpf`, `shrike_link`, `shrike_control` and Shrike host
  simulation suites pass. The cloud `kernel_bpf` suite also passes.
- Real BpfManager PWM-attach rejection test passes; before central rejection
  the same test observed successful publication.
- Both FPGA RTL simulations pass, including exact four-clock CS setup,
  accepted-sequence readback, stop-overlapping frames, generated duty and
  signed direction. This is simulation, not synthesis or board acceptance.
- V03 and V04 reducer self-tests pass (12 and 11 tests respectively).
- ABI catalog and local documentation link checks pass; generated ABI docs
  remove supported PWM observation and include experimental motor helper 1008.
- AArch64 kernel checks with `embedded-rpi5` and with `embedded-rpi5,bench`
  pass using build-only public-key/rootfs fixtures. RP2040 debug target check
  and the retired PWM demo target check pass. Existing compiler warnings remain.
- Strict Clippy passes for `kernel_bpf` and `shrike_link`. A broader direct
  Clippy invocation including `shrike_control` hits the pre-existing
  eight-argument `control::run` lint. Its signature is retained pending the
  paired FPGA adapter; this is not a claim that every repository check passes.
- Workflow YAML parses and `git diff --check` passes. Hosted CI, complete release
  builds, physical HIL and soak results are not produced by this patch.

The TX regressions execute the production `shrike_link::tx::TxState`, including
stalled UART work, expiry across promotion, stop priority and a zero frame
preserved through reversal coalescing. A frame already submitted to a UART FIFO
cannot be recalled; MCU/FPGA watchdogs and the physical gate remain necessary.
Transport order does not prove the motor driver observed a particular pulse or
adequate electrical reversal dead time.

## Next engineering handoff

The existing V03-C corpus runs a private decision monitor; its report cannot
close physical containment. A live helper-to-facility exercise with correlated
final output capture remains part of v0.3 physical closure. The legacy L298N
per-wheel adapter is not promoted into the FPGA runtime.

Finish review and software regression checks on this prerequisite branch, then
close the four concrete board inputs above. The next implementation after that
is the single R0.4 adapter and paired FPGA loop. Do not start v0.5 to route around
an unclosed hardware gate. Retain the existing physical runbook rather than
introducing another acceptance framework.
