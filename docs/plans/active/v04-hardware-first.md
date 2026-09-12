---
title: Hardware-first path from PR 35 to v1
status: active
updated: 2026-09-11
---

# Hardware-first implementation sequence

The next development gate is **24-hour unloaded electronics acceptance** on the
real Pi5, RP2040 and programmed FPGA. Motors and motor power stay disconnected.
Passing this gate permits v0.5 runtime development; powered-motor and assembled-car
acceptance remain separate later requirements. This sequencing decision, approved
2026-09-11, supersedes this plan's earlier requirement to finish the powered v0.4
robot before beginning v0.5. It does not close PR #35's powered-robot checklist,
authorize motion, or establish a release claim.

Original implementation baseline: `4f5aa9037832b9ee27145c5ffc87f4c3ca707e18`
(PR #35). Freeze the actual candidate and each diagnostic image separately;
results from later commits must not be attributed to that original baseline.

## Milestones and exit conditions

| Order | Milestone | Work and exit condition | Deliberately waits |
|---|---|---|---|
| 1 | v0.4 software prerequisites | Preserve interrupted registers; remove PWM-driver callbacks into behavior dispatch; signed atomic motor pairs with bounded pending work; command freshness independent of heartbeat; final FPGA PWM, stop/rearm and accepted-sequence acknowledgement; reject evidence that misses its stated bound. | Hardware claims and v0.5 lifecycle machinery. |
| 2 | v0.3 physical closure | Run the existing staged GPIO/helper/PWM/e-stop campaign on the exact candidate; retain raw captures, wiring and artifact identities. Model-only helper benchmarks cannot substitute for the live helper path. | New boards, generic HAL, additional peripherals. |
| 3 | v0.4 electronics development gate | Supply the validated board inputs below, implement the one concrete MCU adapter and paired loop, complete unloaded final-output functional/fault tests, then a one-hour pilot and 24-hour electronics soak. | Motor power, assembled-car claims and full v0.4 acceptance. |
| 4 | v0.5 A: behavior ownership | Use existing BpfManager, bounded maps and generational handles. Add one kernel-owned behavior record covering code, private maps, admission and attachments; failed preparation must leave live state/resource usage unchanged. Repeated retire/unload cycles return to the defined bound. | New parallel registries, persistent state migration. |
| 5 | v0.5 B: runtime replacement | Prepare a verified/admitted candidate off the active path; publish at a quiescent boundary; start with fresh private state. Retain at most one previous artifact for explicit manual rollback with fresh state. Bounded flight recorder identifies activation, requests, decisions and stop causes; overflow never blocks control. | Automatic policy rollback, general state migration, fleet management. |
| 6 | v0.6: operational hardening | Make cold boot/restart and failed update behavior explicit; signed bundle/tooling, resource and error contracts usable by another engineer. Retained audit export must distinguish software decisions from observed physical outputs. | Persistent security anti-rollback, recovery partitions, durable execution history unless justified by actual v1 failure cases. |
| 7 | Deferred powered v0.4 acceptance | Test secured motors and the driver before assembling the car; then validate motion, stopping and the existing powered pilot/24-hour robot soak. This may follow v0.5 development, but must precede powered-robot acceptance and the reference-robot release candidate. | Treating correct logic levels as proof of motor movement, current, heat or stopping distance. |
| 8 | v0.9: release candidate | Freeze only the narrow versioned behavior/helper/context/link contract exercised by the reference robot. Run the full acceptance gate, including 72-hour whole-system soak and independent clean artifact comparison. | Broad syscall compatibility and speculative APIs. |
| 9 | v1.0 | Ship the signed, verified, admitted, bounded runtime-programmable reference robot and its retained evidence. Publish explicit timing models, measured maxima and non-guarantees separately. | Linux/AMP, Jetson, ROS2 breadth, fleet infrastructure and research mechanisms. |

## Electronics acceptance checklist

Use the existing [hardware runbook](../../operations/hardware-validation-and-benchmarking.md)
and reducers. No new ABI, protocol, registry or acceptance framework is needed for
this sequencing change. The long-run capture procedure still needs qualification;
the current short-capture harness is not a validated 24-hour runner.

- [ ] Resolve the analyzer's early termination and qualify acquisition/storage
  before a long run. An incomplete capture is not a smaller passing soak.
- [ ] Freeze clean source, feature-specific Pi images, RP2040 firmware, FPGA
  bitstream, boot firmware, wiring, instrument identities/uncertainty and workload.
  Complete three attributable cold boots of the designated baseline image.
- [ ] V03-A: at least 10,000 paired baseline/monitor samples; maximum added
  overhead below 5 microseconds. V03-B: at least 10,000 physical input/output pairs
  per declared load condition, covering cold/warm starts and background load.
- [ ] V03-C: exactly 1,000 correlated live-helper requests with physical output
  evidence and zero escapes. V03-D: at least 100 physical GPIO e-stop cycles,
  maximum below 1 ms, with latch/hold/re-arm behavior explicitly checked.
- [ ] Complete the four board inputs below, the concrete MCU adapter and the
  paired FPGA transaction path. MicroPython stimulus firmware does not satisfy
  the operational RP2040/FPGA requirement.
- [ ] Capture at least 1,000 valid Pi/RP2040 frames; test CRC corruption,
  truncation, stale/replayed commands, Pi/Shrike silence and RP2040 reset.
- [ ] Validate sensor voltage conditioning and sensor-to-behavior operation.
  Probe both final FPGA PWM and direction outputs for permitted, rejected and
  out-of-range commands, startup, power cycle, configuration failure and watchdog.
- [ ] V04-D: at least 100 physical FPGA e-stop assertions; both PWM outputs low
  within 1 ms and held safe while stopped. Release alone must not restart drive;
  require the specified fresh-command re-arm sequence. Verify no output bypass.
- [ ] Retain V04-A load measurements (at least 100 per behavior, maximum target
  below 100 ms), V04-B hook-to-final-output measurements (at least 1,000 per
  behavior), and V04-C sensor-trigger-to-final-output measurements (at least
  1,000 at each frozen distance). Report distributions and measurement uncertainty.
- [ ] Pass the one-hour unloaded acquisition pilot and then the 24-hour
  electronics soak specified in runbook section 4.5. Preserve UART, continuous
  physical output evidence, configurations, reductions and hashes.
- [ ] Review results and rerun provenance and required candidate checks.

Every acceptance row receives its own pass/fail/blocked classification. A known,
characterized timing-target miss remains an open performance finding and blocks
that timing claim; it need not block isolated v0.5 ownership/lifecycle development
after the electronics functional, fault and soak gates pass. Unexpected output,
missed required responses, unsafe recovery, unexplained resets or evidence gaps
still block electronics acceptance. Do not silently relax thresholds. Rerun
affected bench checks whenever later changes touch actuation, execution or timing.

## Retained progress and next action

The September 9 campaigns establish Pi GPIO dispatch, a 100-response physical
reflex diagnostic, 200 GPIO e-stop diagnostic presses (largest measured response
6.125 microseconds), and physical PWM clamping/invalid-channel rejection. The
e-stop image automatically re-arms for diagnostics; it does not close production
latching behavior. The measured roughly 5-microsecond typical GPIO reflex does
not meet the legacy sub-1-microsecond fallback.

The containment series has 200 accepted requests in two 50-pulse batches; 40
additional diagnostic requests are separate. The single-boot 500-pulse attempt
ended early after 359,656,448 samples at nominal 6 MHz (about 59.94 seconds).
Its 245 correct UART requests do not count toward acceptance because physical
coverage is incomplete. The analyzer reported repeated empty USB timeouts;
the underlying cause remains unconfirmed. Reboot/rate/port changes are diagnostic
attempts, not established fixes.

These records are under `.reboot-saves/2026-09-07/pi5-corpus-20260909/` in the
operator's main checkout: `corpus-series-progress.json`, the per-run reviews,
and `one-shot/aborted-capture-01-review.json`. The tested corpus kernel is
`7d9c5f64cb134ce5e3b670920e25680877140d20`; host tools are at
`9b7d63b49475d831b25dc3f60ababe2b74ac457c`. Saved captures are not automatically
evidence for a future frozen image. No operational FPGA, motor or 24-hour soak
pass is recorded here.

Next: inspect USB topology after host reboot, isolate the acquisition failure,
then complete containment. The previously accepted batching route has 800 requests
remaining; a fresh single-boot campaign requires all 1,000 requests in that boot.

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

The original V03-C private decision-monitor corpus cannot close physical
containment. The later live helper/PWM campaign supplies partial physical evidence
as recorded above; finish its required population. The legacy L298N per-wheel
adapter is not promoted into the FPGA runtime.

Finish review and software regression checks on this prerequisite branch, then
close the four concrete board inputs above. The next implementation after that
is the single R0.4 adapter and paired FPGA loop. Electronics acceptance permits
v0.5 development while powered validation remains pending. It is not permission
to skip an unclosed electronics safety gate or call full v0.4 complete. Retain
the existing physical runbook rather than introducing another acceptance framework.
