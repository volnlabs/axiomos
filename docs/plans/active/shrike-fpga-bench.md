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
- [x] Correct stale progress/firmware documentation and broken documentation
  references (52 in the fresh worktree; 38 in the operator checkout). Do not weaken the link checker or edit v0.5 designs.
- [ ] Retain focused checks and a full candidate gate before physical deployment.

### Task 2: Board and vendor readiness

- [ ] Obtain an attributable board-compatible recovery UF2, its SHA-256 and
  restoration procedure. Prove restoration before custom runtime flashing.
  Keep the existing flash guard. Use missing/corrupt fixtures for negative
  recovery tests once the actual recovery record becomes ready.
- [x] Install and identify the vendor ForgeFPGA toolchain in Ubuntu 24.04 userspace;
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

- [x] Add `scripts/hil/shrike-bench.py` with capture/replay/self-test modes,
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

## Execution record — 2026-09-12

The feature branch was fast-forwarded to the baseline and pushed to
`volngithub` before creating this plan; implementation is isolated in the
requested worktree. The existing 10,000-event reflex analysis is carried forward.
No boards are currently enumerated under `/dev/serial/by-id` on this host.

Documentation links now pass in a fresh worktree: 116 Markdown files and 335
local links. Missing ignored research artifacts and sibling planning sources
are explicitly marked unpublished, with original paths retained. No acceptance
threshold or link-checker exception was introduced. The historical baseline's
38-failure record is unchanged; the fresh worktree exposed 14 further references
to operator-only evidence.

Vendor readiness remains blocked on concrete inputs:

- [Renesas Go Configure Software Hub](https://www.renesas.com/en/software-tool/go-configure-software-hub)
  v6.55.001 is now installed from the operator's downloaded Ubuntu amd64 DEB.
  The earlier unauthenticated download was blocked by login/Cloudflare; that
  installer dependency is resolved. Package and environment identities are
  recorded below. The Arch host runs the Ubuntu userspace through unprivileged
  Bubblewrap; this is not a full Ubuntu guest or a vendor-certified host setup.
- [Vicharak release v1.0.0](https://github.com/vicharak-in/shrike/releases/tag/v1.0.0)
  remains the only published release on recheck. Its Shrike-Lite MicroPython
  UF2 is 676,864 bytes, but the release does not bind it to V1.0/R0.4 recovery.
  `factory_uf2.ready=false` remains correct. Board-compatible provenance and an
  observed restore are required before custom flashing.
- `forgefpga/io-plan.csv` still leaves physical e-stop, final PWM and direction
  pads provisional/unassigned. The I/O planner, actual board continuity review,
  configuration/READY bounds and generated fit/timing reports are outstanding.
  `R04Platform` cannot be completed using guessed values. `fpga-runtime` stays
  disabled. These dependencies block physical chain, pilot and soak execution.

The full audit is retained under the ignored
`artifacts/runs/1789194472-check-all/`, with console output in
`.superpowers/sdd/shrike-fpga-bench/full-gate.log`. It started before the RP2040
workspace fix and is not a clean final-candidate pass. Its result is recorded
below; a started gate is not a pass.

### Configuration reference retained

[Renesas Configuration Guide](https://www.renesas.com/en/document/mah/forgefpga-configuration-guide),
R19US0005EU0250 Rev.2.5 (2026-01-28), section 8.1/page 28 and Figure 26 were
read and visually checked. The PDF is retained beside the local gate log;
SHA-256 `abdf240a09ecdbf7e9019a05c71d10a018e1c31be6525d587a9e903002ef6651`.
It specifies `FPGA_bitstream_MCU.bin`, a 3 ms initial delay, a 3 microsecond
CS pulse, CONFIG completion and SPI high-impedance handoff within 10 microseconds.
These are reference requirements to reconcile with the R0.4 circuit and capture,
not measured board timings. Do not use the external-flash bitstream interchangeably.

The text names CONFIG as SPI_SO initially and SPI_SI in a later step; Figure 26
shows completion on MISO. Resolve that inconsistency against the datasheet and
board nets. Configuration completion is a pin level, distinct from our runtime
`0x80` READY status and separate `A5 00` accepted-sequence read. Qualification
must cover the high-impedance interval and runtime pin reacquisition; a successful
host lifecycle mock does not establish either transition electrically.

### Software checks and observer

`0ff336a` adds an explicit standalone Cargo workspace to the RP2040 package.
Without it, Cargo climbs out of the nested worktree and rejects the package as
an undeclared member of the operator's main checkout. The existing flash-contract
regression reproduced the failure; after the fix all nine tests pass, including
the disabled release UF2 build. Debug and release RP2040 Clippy checks with
`-D clippy::all` also pass. Lockfiles and runtime guards are unchanged.

The observer is confined to `scripts/hil/shrike-bench.py` and
`tests/scripts/test_shrike_bench.py`. Run its hardware-free checks with:

```sh
python3 -B scripts/hil/shrike-bench.py self-test
```

The recorder retains all eight sampled bits with bounded 4 MiB compression
blocks, ordered chunk and UART/analyzer integrity records, and cumulative
campaign accounting. Use one dedicated campaign directory for pilot, soak and
failed attempts; unrelated writers must not bypass its lock. Its independent
oracle is a frozen repeated workload advanced by physical stimulus strobes.
The configuration schema and synthetic example are in the script and test;
that example is not a board wiring profile. Freeze real pins, timing uncertainty,
workload and sigrok/library/patch hashes before using capture mode.

The software check cannot replace the separate SPI diagnostic captures or
V04-A/B/C populations. It neither generates Pi commands nor decodes sampled
UART bits. Captured serial V04 records are checked incrementally, and physical
acceptance remains false in every software/synthetic report. The real pilot
must still prove continuous USB capture and <=1.5 GB/hour including all logs.

Independent review found a last-cycle duty-validation gap, analyzer-log clipping
before error scanning, missing UART chunk continuity and a malformed completion
value accepted by truthiness. These findings and a further overlong pulse ending at a strobe are fixed in
`0f7d79e`; the reviewer independently reran the counterexamples and healthy
boundary sweep. All 15 self-test groups pass. The latest parent run processed
24,000,000 synthetic samples in 0.233 seconds combined (98.5 MiB/s), with
45,040 KiB peak RSS. This regular trace is a software check, not a real storage
forecast. Physical capture still requires the board and pilot qualifications.

### Audit checkpoint

The initial full audit completed at 06:59:07 UTC with exit 1: 147 stages,
141 PASS, four FAIL and two explicit SKIPs, in 31 minutes 15 seconds. All 17
Miri stages (setup plus 16 tests) and tracked-lockfile finalization passed.
The two skips are the opt-in fault injection and deferred SMP4 scheduler check.
This is not a passing full gate.
The four recorded failures are product naming, flash contract, and RP2040
debug/release Clippy. The last three pass on the focused reruns after `0ff336a`;
those reruns do not rewrite the failed original audit. Historical-name lint
failures remain in moved architecture reviews, original source paths and the
UART-sheet generator. Do not rename evidence identities or relax the gate to
claim readiness. A clean final-candidate full pass remains required before
physical deployment.

Next dependent action: resolve the synthesis preflight findings, establish
board-compatible recovery, then review the actual FPGA pins and configuration
handoff before completing the concrete adapter. v0.5 implementation is outside
this branch; motors, drivers and motor power remain disconnected.


### Installed vendor environment

The downloaded `go-configure-sw-hub-v6.55.001-ubuntu-22.04-amd64.deb` is
293,600,164 bytes. SHA-256:
`610eb83b5c40c7da3bb83f39ad5cd136f67486a3b436f2df66273889d9a08c47`.
Its Debian metadata identifies package `go-configure-sw-hub` version `6.55-1`,
architecture amd64; the complete compressed payload integrity check passed.
This locally calculated hash identifies the received file, not a separately
verified vendor signature. `GPLauncher --version` reports
`Go Configure Software Hub v.6.55 6.55.001`.

The official [Ubuntu Base 24.04 image directory](https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/)
provided `ubuntu-base-24.04.5-base-amd64.tar.gz`; its published SHA256SUMS entry
matched `e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86`.
The local environment is
`/home/utkarsh/.local/share/axiomos-tools/forgefpga-6.55.001/`.
Installation logs preserve the initial single-UID fontconfig and missing icon
index failures. Reconfiguration and installing `hicolor-icon-theme` resolved
both; `dpkg --audit` now returns no findings. Vendor files stay outside Git.

The local `run` script uses the Ubuntu rootfs, binds this feature worktree at
`/workspace`, and exposes no USB hardware or network. Headless version check:

```sh
/home/utkarsh/.local/share/axiomos-tools/forgefpga-6.55.001/run /usr/bin/GPLauncher --version
```

For the vendor GUI on the operator's existing X11 display:

```sh
FORGE_QT_PLATFORM=xcb /home/utkarsh/.local/share/axiomos-tools/forgefpga-6.55.001/run /usr/bin/GPLauncher
```

The GUI process launched; this is not evidence of a reviewed I/O planner or
successful build. The installed launcher/designer help exposes file opening,
not a documented command-line Forge build. Bundled Yosys is `0.59+0`, git
`946048486`; generic RTL preflight cannot establish device fit, routing, timing
or a configuration bitstream.


### RTL synthesis blockers repaired

The installed compiler exposed two rejected dual-edge/OR reset processes that
Icarus simulation accepted. Combining the same-value POR/e-stop resets into one
active-low reset signal fixes the release synchronizer and both gate source
mirrors. The next compiler stage exposed eight logic loops in the asynchronous
set/clear feedback for replay and status registers retained during e-stop.
Those four registers now have POR-only reset with a clocked e-stop hold; their
commit conditions and old-value snapshot semantics remain unchanged.

Both existing simulations pass, including new reset-overlap release orders,
immediate output suppression during active PWM, release-only disarm, fresh
command recovery, replay rejection after e-stop and POR clearing replay history.
Independent review and parent reruns pass. The checked-in structural regression
can be repeated in this local environment with:

```sh
/home/utkarsh/.local/share/axiomos-tools/forgefpga-6.55.001/run \
  /usr/local/go-configure-sw-hub/bin/external/yosys/v59/yosys \
  -s scripts/verify/fpga-safety-preflight.ys
```

Hierarchy, process lowering, `check -assert` and absence of inferred latches pass;
zero check problems remain. One `Complex async reset` warning for `frame_bad`
remains (`$dffsr`, POR=0/e-stop=1); actual Forge mapping must resolve support.
Generic arithmetic cells are not device resource estimates. No fit, routed
clock timing, bitstream or physical acceptance is claimed.

Original failures, intermediate eight-loop failure and final passing commands,
source hashes and logs are retained under ignored
`.superpowers/sdd/shrike-fpga-bench/vendor-synthesis/`. The parent run uses the
tracked preflight script; documentation links pass at 116 files / 336 links.
A working project copy is prepared at
`.superpowers/sdd/shrike-fpga-bench/vendor-project/axiomos_r04.ffpga` (visible as
`/workspace/.superpowers/sdd/shrike-fpga-bench/vendor-project/axiomos_r04.ffpga`
inside the vendor environment). The hub remains launched for the operator;
file-argument attempts exited without a persistent designer process, so opening
the project is not verified. Native desktop UI control is unavailable in this
session. The next GUI action is to open that copy and run the Forge build/I/O
planner; any resulting project changes and reports require review before use.
