# Shrike/RP2040/FPGA bench execution

Status: in progress. Baseline: `05e2b25763546bcf4b6031b4767ac7be125dd31b`
(`baseline/v0.5-fpga-start`), repository `volnlabs/axiomos`, branch
`feat/fpga-bringup`, worktree `worktree/fpga-bringup`.

## Contract

Validate the real Pi -> RP2040 -> programmed FPGA path with motors, drivers
and motor power disconnected. v0.5 runtime work is a separate workstream.
Use [the hardware runbook](../../operations/hardware-validation-and-benchmarking.md)
and [the recorded baseline](../../reviews/releases/2026-09-12-v0.5-fpga-baseline/README.md).
Preserve the completed 10,000-event reflex result as functional PASS / legacy
timing FAIL. Preserve the 10,000 paired overhead samples, 1,000 containment
requests and 200 diagnostic GPIO e-stop responses with their original identities;
they are not operational FPGA acceptance. No unchanged capture is repeated.

### Task 1: Workspace and prerequisite documentation

- [x] Fast-forward the requested branch from `volngithub/main`, establish its
  upstream, and create the ignored project-local worktree without changing main.
- [ ] Correct stale progress/firmware documentation and the 38 existing broken
  documentation references. Do not weaken the link checker or edit v0.5 designs.
- [ ] Retain focused checks and a full candidate gate before physical deployment.

### Task 2: Board and vendor readiness

- [ ] Obtain an attributable board-compatible recovery UF2, its SHA-256 and
  restoration procedure. Prove restoration before custom runtime flashing.
  Keep the existing flash guard. Use missing/corrupt fixtures for negative
  recovery tests once the actual recovery record becomes ready.
- [ ] Install and identify the vendor ForgeFPGA toolchain in Ubuntu 24.04;
  record installer/compiler/device identities and retained artifact locations.
- [ ] Review clock/reset, e-stop, both PWM/direction outputs and all MCU
  interconnect through the vendor I/O planner and powered-off continuity.
  Review voltage domains, common ground and sensor conditioning with the operator.
- [ ] Establish PWR/EN/configuration/READY semantics, SPI/CS bounds and runtime
  handoff. Generate the bitstream with synthesis, fit, timing and pin reports.
  Record actual clock calibration, bitstream hash/length and flash placement.
- No guessed pin coordinates/timings, OTP programming or hardware claim from
  simulation. The nominal clock/carrier/watchdog defaults remain tunable.

### Task 3: Concrete adapter and paired control

- [ ] Complete existing `R04Platform`/`FpgaLifecycle` with bounded hash-checked
  bitstream reads and the qualified configuration/runtime sequence.
- [ ] Replace independent motor writes with one paired interface carrying the
  accepted Pi sequence and signed duties. Preserve command age; heartbeats,
  status reads and cached commands never manufacture freshness.
- [ ] Preserve zero-before-reverse even when both frames arrive in one RX batch.
  Require the existing separate `A5 00` acknowledgement with matching sequence.
- [ ] Make startup/fault/recovery fail closed. Reconfiguration never replays
  stored motion; release alone never drives. Enable `fpga-runtime` only after
  the board/artifact prerequisites and concrete adapter checks are satisfied.
- First write focused failing regressions for paired publication, reversal,
  duplicate suppression, watchdog expiry, bad status and recovery behavior.

### Task 4: Bounded host observer

- [ ] Add `scripts/hil/shrike-bench.py` with capture/replay/self-test modes,
  reusing installed sigrok, `zstd -1` and existing validation rules. No web UI,
  database, new kernel recorder or alternative acceptance framework.
- Consume raw one-byte digital samples and UART records incrementally. Preserve
  all selected sample bits losslessly in compressed chunks; never create an
  uncompressed capture copy. A chunk may be discarded from RAM after processing.
- Keep observer buffering <=128 MiB. Existing reducers accumulate all edges or
  records: reuse their rules, not their unbounded whole-run representation.
  Carry PWM state, previous sample and pending correlations across chunks.
- Capture both final PWM outputs, both FPGA direction signals, physical e-stop
  and required independent stimulus references simultaneously. Freeze channel
  mapping and expected workload independently of kernel output logs; qualify
  separate SPI diagnostic layouts when needed. Start qualification at 24 MHz
  sample rate (20 kHz is the PWM carrier), retaining timebase/skew uncertainty.
- One acquisition process feeds ordered compressed files without acquisition
  restarts. Manifest chunk IDs, uncompressed sample counts/offsets, SHA-256,
  timestamps, all process exit statuses and final acquisition completion.
  Pin the actually loaded sigrok/libsigrok and retained FX2 counter correction.
- Replay every retained sample and verify integrity/coverage against independent
  expected output intervals. Report count/duty/direction/latency/stop violations;
  queued command logs alone cannot prove final output. Preserve UART loss checks.
- Hard cap: 50,000,000,000 bytes of cumulative campaign evidence, including
  pilot, logs, failed attempts and temporary outputs. Begin controlled stop at
  45,000,000,000 bytes cumulative; reserve 5 GB for finalization. Never delete
  older evidence or silently lower resolution/drop data to fit the cap.
- Pilot must fit <=1.5 GB per hour with full sustained acquisition/replay
  throughput and zero drops. The earlier synthetic ~37 GB/25h projection is
  feasibility only. A budget-stop run is not a passing soak.
- First prove real round-trip and rejection tests: malformed configuration,
  bad/truncated/missing/duplicate/reordered chunks, transitions at chunk
  boundaries, counter wrap, wrong duty/direction, output while stopped, missing
  responses, UART loss, unplanned reset, disk exhaustion and compressor failure.
  Test streaming memory/work across repeated chunks; never label synthetic
  fixtures or offline replay as physical acceptance.

### Task 5: Physical acceptance

- [ ] Three attributable cold boots; safe startup/reset/configuration failures.
- [ ] >=1,000 valid operational frames; malformed and out-of-range commands,
  stale/replayed/wrapping sequences, heartbeat-only traffic, link silence,
  RP2040 faults, SPI failure and both watchdog layers.
- [ ] >=100 physical FPGA e-stop assertions with active PWM: both outputs low
  within 1 ms including uncertainty, safe hold and fresh-command-only re-arm;
  include stop overlapping a transaction and verify no FPGA bypass.
- [ ] V04-A >=100 loads/behavior (target maximum <100 ms); V04-B >=1,000
  hook-to-final-output samples/behavior; V04-C >=1,000 sensor-to-final-output
  samples at each frozen condition. Keep populations separate and report timing
  verdicts independently of functional results.
- [ ] One-hour acquisition pilot, then a new continuous 24-hour unloaded
  electronics soak on the same frozen workload/artifacts. Reset/configuration
  fault campaigns are separate. Retain the final safe state and full replay.
- Unexpected output, missed response, unexplained reset or evidence loss
  invalidates the run. Preserve failures, fix the cause and restart the full
  soak. Software tests and simulated traces never close physical rows.

## Initial audit

On 2026-09-12: 91 Shrike Rust tests, nine flash-contract tests, one host board
profile test, both RTL simulations and benchmark provenance passed. The disabled
RP2040 UF2 builds. Actual factory recovery is NOT READY; the Forge project is
unsynthesized and external pins remain provisional. Documentation link check
reports 38 failures. No full-gate or new physical pass is claimed.

Record each task's commands, results and remaining external inputs here as work
progresses. Keep raw local evidence outside tracked source and never attribute
earlier diagnostic images to the new candidate.
