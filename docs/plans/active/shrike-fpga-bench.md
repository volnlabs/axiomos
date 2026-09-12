# Shrike/RP2040/FPGA bench execution

Status: in progress. Baseline: `05e2b25763546bcf4b6031b4767ac7be125dd31b`
(`baseline/v0.5-fpga-start`), repository `volnlabs/axiomos`, branch
`feat/fpga-bringup`, worktree `worktree/fpga-bringup`.

## Current gate status

The software continuation starts from `e0da976` (including CI fix `135e53b`).
The dated execution records below preserve earlier failures; use this table
and the final timing-closure record for the current status.

| Requirement | Status |
|---|---|
| Vendor toolchain, generated MCU bitstream, device fit/routing | Complete for the recorded candidate |
| Nominal 20 ns and all five 18 ns setup corners | Complete; worst setup margin +0.300 ns |
| Project/I/O-planner/post-route pin assignments | All 17 match; electrical continuity remains open |
| Post-route hold/pulse, asynchronous interfaces, actual oscillator | Open; setup success does not close these requirements |
| Factory recovery UF2 and observed restoration | Open; `factory_uf2.ready=false` and flash guard retained |
| Paired sink, reverse TX ownership and local drain model | Host implementation and focused regressions pass; no hardware acceptance |
| Concrete configuration/runtime adapter and physical reset/drain | Open; `fpga-runtime` remains disabled |
| Functional/fault campaign, one-hour pilot, 24-hour soak | Open; no new physical acceptance |

Current software work repairs the naming gate, preserves zero/readback host
regressions, makes retained build verification portable, and replaces batched
independent wheel writes with ordered pairs and bounded telemetry transmission.
Stops return to the outer owner for requalification: `FpgaLifecycle::fail_safe`
removes runtime readiness, and the control loop must not invent a command
sequence or automatically resume a stopped installation. Local reset-drain
tests are prerequisites, not proof of UART/peer quiescence on the board.

The read-only evidence command is:

```sh
python3 -B scripts/verify/fpga-build-evidence.py --evidence-dir \
  .superpowers/sdd/shrike-fpga-bench/vendor-synthesis/timing-closure-20260912
```

It checks the retained manifest and six builds against current canonical RTL,
settings, SDC and pins, then compares its result with retained `results.json`.
It never rewrites the retained evidence. It does not qualify hold/pulse timing,
runtime enabling, programming or physical hardware. The documented Tcl flow
already produces bitstreams; opening a GUI to obtain the first bitstream is
no longer the next prerequisite.

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
- [x] Retain focused checks and a full candidate gate before physical deployment.
  The disabled software candidate passes; changed deployment images require a new gate.

### Task 2: Board and vendor readiness

- [ ] Obtain an attributable board-compatible recovery UF2, its SHA-256 and
  restoration procedure. Prove restoration before custom runtime flashing.
  Keep the existing flash guard. Use missing/corrupt fixtures for negative
  recovery tests once the actual recovery record becomes ready.
- [x] Install and identify the vendor ForgeFPGA toolchain in Ubuntu 24.04 userspace;
  record installer/compiler/device identities and retained artifact locations.
- [x] Bind clock/reset, e-stop, both PWM/direction outputs and MCU interconnect
  through the vendor I/O planner and confirm all 17 post-route assignments.
- [x] Generate bitstreams with synthesis, fit/routing and all-corner setup
  reports; retain exact source/configuration and artifact hashes/lengths.
- [ ] Verify powered-off continuity, voltage domains, common ground and sensor
  conditioning with the operator.
- [ ] Establish PWR/EN/configuration/READY semantics, SPI/CS bounds and runtime
  handoff. Close hold/pulse/interface timing and record actual clock calibration
  and the qualified flash placement/programming procedure.
- No guessed pin coordinates/timings, OTP programming or hardware claim from
  simulation. The nominal clock/carrier/watchdog defaults remain tunable.

### Task 3: Concrete adapter and paired control

- [ ] Complete existing `R04Platform`/`FpgaLifecycle` with bounded hash-checked
  bitstream reads and the qualified configuration/runtime sequence.
- [x] Replace independent motor writes with one paired interface carrying the
  accepted Pi sequence and signed duties. Preserve command age; heartbeats,
  status reads and cached commands never manufacture freshness.
- [x] Preserve zero-before-reverse even when both frames arrive in one RX batch.
  Require the existing separate `A5 00` acknowledgement with matching sequence.
- [x] Use bounded whole-frame reverse TX with accepted-byte backpressure and
  explicit software-owned telemetry loss counts. UART acceptance is not delivery;
  hardware FIFO loss on reset is unknown.
- [x] Prepare a bounded local reset-drain model requiring at least 200 ms of
  continuous motion-inhibited quiescence; readiness is not rearm.
- [ ] Qualify reset draining against both peers and the actual queues/FIFOs.
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
inside the vendor environment). Excluding PID isolation for the GUI launcher
allowed its detached designer process to persist. The operator confirmed the
project opened and completed synthesis on 2026-09-12 at 12:22 with zero errors,
using Go Configure 6.55.001 and bundled Yosys 0.59+0 (`946048486`). Native desktop
UI control remains unavailable in this session.

The saved GUI-generated script uses `synth_xilinx` as its synthesis mapping.
The post-synthesis report contains 1,253 primitives, including 660 LUTs,
315 CARRY4, 230 flip-flops and one LDCE latch. The `frame_bad` asynchronous
set/reset warning is emulated with flip-flops, a mux and that latch; downstream
Forge acceptance remains unverified. These intermediate counts do not establish
Forge device fit or timing. The project, exact script, matching RTL sources,
Verilog netlist, EDIF and report are preserved with SHA-256 hashes under ignored
`.superpowers/sdd/shrike-fpga-bench/vendor-synthesis/gui-synthesis-20260912-1222/`.
The next GUI step is offline Generate Bitstream to obtain implementation reports.
I/O assignments remain provisional; recovery, electrical and configuration
handoff gates still apply before programming hardware.

### First Forge place-and-route failure and arithmetic correction

The operator's 2026-09-12 12:29 run failed with exit 3: 382 logic CLBs were
required against 140 available, and carry chains reached 17 CLBs against a
10-CLB limit. Forge also warned that the mapped data-clock latch was unsupported
and emulated it in LUTs. The 16.424 MHz post-packing estimate was before routing;
the clock group was `UDEF_clk`. Neither fit nor 50 MHz timing passed.

The PWM gate's two 64-bit divide-by-1000 paths caused the arithmetic growth.
Both gate mirrors now reduce the constant period/1000 ratio before synthesis
(2500/1000 becomes 5/2), size the product to its proven range and size the PWM
counter to the configured period. Clock/carrier calibration and integer-floor
PWM behavior remain supported. `frame_bad` now starts invalid under either
reset; a fresh qualified CS clears it. This removes asynchronous set/reset
emulation without changing command acceptance after a fresh transaction.

Both simulation benches pass. An exhaustive comparison with the original
64-bit scaling formula passes all 4,096 signed duty values at periods 1, 20,
2500, 2501 and 100,000,000. Structural preflight rejects `$dffsr` as well as
inferred latches. The new mapping preflight reproduced the old capacity problem
(273 carry blocks in that local run) and passes after the correction. Running
the saved GUI synthesis script on the corrected sources yields 39 carry blocks,
277 LUTs, 209 flip-flops and zero latches; the longest connected CARRY4 chain is
six. These remain intermediate mapping results, not a Forge fit result.

Failure summary, before/after mapping logs, structural log and candidate hashes
are under ignored
`.superpowers/sdd/shrike-fpga-bench/vendor-synthesis/pnr-failure-20260912-1229/`.
The original GUI project remains preserved. The corrected copy is
`.superpowers/sdd/shrike-fpga-bench/vendor-project-compact/axiomos_r04_compact.ffpga`.
Its Forge synthesis/place-and-route rerun and explicit clock timing constraints
remain pending; physical gates are unchanged.

### Compact design fits and routes; board integration remains open

The operator's 2026-09-12 12:39–12:40 Forge run completed normally (exit 0):
92/140 logic CLBs (65.71%), longest carry chain six, 451 routed nets verified,
zero final congestion and bitstream generation complete. The GUI resource
report lists 461/1120 LUT5s and 209 flip-flops. This closes the device-capacity
and carry-length failures for this exact source/configuration.

Post-route achievable frequency is 79.719 MHz at `tt1p1v25c_Typical`.
`PNR_TIMING.log` still assigns `<UDEF_clk>` an automatic 2000 ps period and
reports WNS -10545 ps. That is an automatic 500 MHz target, not a constrained
50 MHz sign-off. Define the intended 20 ns clock constraint and review timing
corners, I/O timing and the direct-clock-without-CLKBUF warning before acceptance.

`PNR_IO.log` confirms automatic placement of previously unassigned reset,
e-stop, PWM, direction and output-enable signals. These fabric locations do
not establish board package-pin connectivity. Review them through the I/O
planner against the board schematic, reset/clock resources and continuity;
do not accept the post-PnR mapping mismatch warning as a qualified pin map.

The exact project, matching RTL, synthesis inputs/outputs, PnR reports and all
bitstream variants are preserved with SHA-256 hashes under ignored
`.superpowers/sdd/shrike-fpga-bench/vendor-synthesis/gui-pnr-20260912-1240/`
(31 files, 25,733,596 bytes). The generated MCU variant is 46,408 bytes with
SHA-256 `603b372b706457e81bcb267f0e76170b7d068667afca8e76385736e94383611f`.
It is diagnostic evidence only: no programming or physical acceptance occurred.
Recovery provenance/restore and configuration handoff remain open.


### Explicit 50 MHz constraint and pin integration — 2026-09-12

The approved nominal 20 ns SDC is registered in both source and working
projects; separate 18 ns projects exercise all five installed timing corners.
Fresh synthesis/PnR and bitstream generation completed via Forge 6.55.001's
experimental, documented `GP6 --tcl` entry point. Each report reads back the
intended period and timing corner. This initial run failed all-corner setup;
the timing-closure run below supersedes it:

| Build | Constraint (ns) | Post-route setup WNS (ns) | Fmax (MHz) | Setup |
|---|---:|---:|---:|---|
| guard-0-tt1p1v25c_Typical | 18 | +4.462 | 73.872 | PASS |
| guard-1-ss0p99v85c_RCworst | 18 | -7.312 | 39.509 | FAIL |
| guard-2-ss0p99vn40c_RCworst | 18 | -8.105 | 38.308 | FAIL |
| guard-3-ff1p21v85c_RCbest | 18 | +8.947 | 110.473 | PASS |
| guard-4-ff1p21vn40c_RCbest | 18 | +9.495 | 117.592 | PASS |
| nominal | 20 | +6.462 | 73.872 | PASS |
| trial-slow-hot-no-dense | 18 | -6.032 | 41.613 | FAIL |

The nominal build uses 92/140 CLBs (65.71%), 461 LUT5s and 209 FFs.
The no-dense-packing trial uses 118/140 CLBs and still fails setup, so its setting
was not adopted. Both slow-corner achievable periods exceed 20 ns. These
results establish typical-corner 50 MHz setup success, not full-corner closure.
All seven tool exits were zero; bitstream generation does not imply timing pass.

Fresh Forge I/O Planner export and each post-PnR report confirm all 17 explicit
bindings from the pinned GPIO-expander reference. Runtime reset now uses
RP2040 GPIO14 / FPGA GPIO18 / package9; GPIO7 is e-stop and GPIO8–11 are paired
PWM/direction outputs with their OE bindings. Unused compatibility PWM inputs
are unbound. The MCU initializes GPIO14 as ordinary GPIO LOW and force_safe
asserts it LOW. NVM, PLL configuration, dedicated OSC_CLK and clkbuf_inhibit
are retained. PWR/EN configuration control and runtime/recovery gates remain.

Final exported timing includes setup only. Placement-estimated positive hold
slack is not post-route hold sign-off; final hold/pulse evidence, asynchronous
interface timing, oscillator measurement at board voltage, continuity and
recovery remain open. No blanket timing exceptions or physical claims were added.
Both simulation benches, structural and mapping preflights, nine flash-contract
tests, board-profile test, MCU debug/release builds, formatting and both Clippy
profiles pass. The fpga-runtime feature remains intentionally uncompilable.

Exact inputs, all reports/bitstream variants, source/reference hashes, runnable
readback checks and the full matrix are preserved under ignored
`.superpowers/sdd/shrike-fpga-bench/vendor-synthesis/clock-pin-20260912/`.
Open its `nominal/axiomos_r04_50mhz.ffpga` for the fresh nominal build; the older
compact working project's build directory is historical. Nominal MCU image is
46,408 bytes, SHA-256 `a3f71894eedf8fad621a4b158499607406c98d7b60dbb08cace7e3efa341a290`.
No programming or physical acceptance occurred.

### Timing closure with the 18 ns guard — 2026-09-12

The production RTL now passes the nominal 20 ns clock and all five installed
18 ns setup corners. Each final build was freshly synthesized, placed, routed
and generated a bitstream from the same frozen sources/settings. The readback
checker verifies the actual period and corner, all 17 I/O assignments, source
and SDC bytes, synthesis/packing settings, retained NVM/PLL configuration and
bitstream size/hash. All six builds have zero failing setup endpoints and TNS 0.

| Build | Corner | Period (ns) | Setup WNS (ns) | Fmax (MHz) |
|---|---|---:|---:|---:|
| final-nominal | tt1p1v25c_Typical | 20 | +9.710 | 97.191 |
| final-guard-0 | tt1p1v25c_Typical | 18 | +7.710 | 97.191 |
| final-guard-1 | ss0p99v85c_RCworst | 18 | +0.300 | 56.500 |
| final-guard-2 | ss0p99vn40c_RCworst | 18 | +0.475 | 57.065 |
| final-guard-3 | ff1p21v85c_RCbest | 18 | +11.092 | 144.781 |
| final-guard-4 | ff1p21vn40c_RCbest | 18 | +11.493 | 153.704 |

All six use 114/140 CLBs (81.43%), 567 LUT5s and 255 FFs. The worst setup guard
margin is +0.300 ns at slow 85 °C. This qualifies modeled setup timing for the
50 MHz production profile; it does not establish board oscillator frequency,
post-route hold/pulse width, asynchronous interface timing or physical safety.
The prior slow-corner failures and intermediate unsuccessful trials are retained.

The retained RTL changes precompute received-byte prefix checks, CRC and payload
destinations before consumption; split range validation; predict PWM wrap and
SPI byte boundaries; and split the watchdog increment into 11-bit pieces with
registered carry. Frame-error set/clear priority is expressed directly. Small
combinational boundaries preserve one-LUT history/receive enables. Command and
status response cycles, signed duty bounds, replay behavior, E-stop assertion
and the exact watchdog expiry/commit ordering remain unchanged in the regressions.
No retiming or blanket timing exceptions were introduced.

The selected synthesis flow is classic ABC with hard-mux inference disabled.
The additional synthesis commands unset keep_hierarchy and flatten only after
mapping, so Forge receives a flat netlist. Hard-mux inference produced a mapped
simulation mismatch in an accelerated regression and was rejected. Native-LUT-only,
extra routing, I/O packing and other RTL trials did not improve the selected
result. The final compiler argument is `-TIMING_DRIVEN_PACKING_THR 0.8`;
effective compiler configuration readback confirms the override from 0.7. Changing
these settings or production parameters requires renewed mapping/route checks.

Maintained safety/runtime benches, exhaustive range and PWM arithmetic/wrap
checks, cycle-exact comparison with the frozen baseline, strict mapped state
and 11-pin comparison, structural/mapping preflights, and the production saved
netlist smoke all pass. The watchdog differential checks timeout values 1, 2,
3, 255, 256, 257, 65539 and 2500000, including natural commit/expiry/recovery.
The actual nominal netlist smoke checks the 2500-clock PWM period, duties,
valid commit, coherent status, replay rejection, bad-CRC kill, recovery and E-stop.

Evidence and runnable checks are under ignored
`.superpowers/sdd/shrike-fpga-bench/vendor-synthesis/timing-closure-20260912/`:
`results.json`, `verify-results.py`, `summary.md`, `SHA256SUMS`, `final-*` projects
and reports, `final-qualified-preflights.log`, `final-qualified-baseline.log`,
`mapped-regression/final-qualified.log`, `watchdog-parameter-check/final-qualified.log`
and `production-mapped-smoke/final-nominal-smoke.log`. The extended native compiler
stdout is retained for the last two final runs; all six retain the normal Forge
reports, source/project snapshots and successful Tcl completion logs.

Open `final-nominal/timing.ffpga` in that evidence directory for the fresh 50 MHz
project. Older working-copy build directories remain historical. The final
nominal MCU image is 46,408 bytes, SHA-256
`2bb027130b9cdcfdda1e47e9b51fb437f138f9daab25ffcc589eb9468febbc4c`.

The source `top.v` SHA-256 is
`97656bc2501ec5fb531eb042e0bcdecddbc349505c5acc85668a49c650c41bdd`.
No flashing, runtime enable or physical acceptance occurred. Clock measurement
at the actual board voltage, continuity, recovery, post-route hold/pulse evidence
and controlled hardware bring-up remain separate open gates.

### M1 host prerequisites — 2026-09-12

The software continuation is frozen at `05b078dc02ebfdcd381f3c144ffda9c00838c046`.
`5fba4fe` carries the qualified naming fix and three atomic-zero/readback
regressions; `c6e05b5` replaces separate wheel writes with one ordered paired
sink and bounded UART ownership; `05b078d` adds the portable evidence verifier,
its rejection tests and audit integration. The main CI fix `135e53b` is already
an ancestor. No runtime branch, hardware pins, FPGA source or retained build
archive was changed by this continuation.

Each fresh pair reaches `FpgaLifecycle` once with its accepted Pi sequence and
separate post-transaction acknowledgement. Zero-before-reverse survives a
single RX batch. A fault or stop inhibits the sink, resets local transport and
returns borrowed peripherals for explicit requalification. It never invents a
stop sequence or automatically rearms. Reverse telemetry owns at most one active
and one pending frame, advances only on accepted bytes, and reports software
queue losses. UART acceptance is not delivery; hardware FIFO loss on reset is
unknown. The local drain model requires 200 ms of continuous quiescence and
cannot establish a session or authorize motion.

Focused checks passed: 108 Shrike host tests, host Clippy with `-D warnings`,
14 evidence-verifier tests, 15 observer tests, both RTL simulations, nine flash
contract tests, one board-profile test, and correctly linked RP2040 debug/release
builds plus Clippy. The runtime feature still fails compilation deliberately;
flash-contract tests prove missing recovery rejects before copying. An initial
root-directory target build omitted the firmware linker configuration and is
excluded as linked firmware evidence; the correct-directory builds supersede it.
The initial strict Clippy warning was an existing boolean assertion and was
corrected before freezing the candidate. Retained focused logs, command record,
artifact hashes and these exclusions are under ignored
`target/audit-verification/fpga-m1-05b078d-focused/`.

The portable verifier independently reproduces all six required setup corners
and validates all 17,984 manifest entries. Negative tests reject corrupted or
unbound files, duplicate identities/settings/results, malformed or contradictory
timing records, substituted corners, incomplete pin tokens and false completion
records. Review findings were fixed and scoped re-review passed. The retained
archive still reports physical qualification pending, runtime disabled and
programming false.

The recovery UF2/provenance, actual bench connection, continuity, configuration
handoff and remaining physical timing inputs are still missing. The concrete
`R04Platform`, physical reset/drain qualification, functional/fault campaign,
one-hour pilot and 24-hour soak remain open. M1 and v0.5 are not complete;
broad M2–M7 runtime implementation remains behind the hardware-first gate.

The full audit on the clean frozen commit passed **149 checks, zero failures,
two gate skips** in 28 minutes 7 seconds (17:23:17–17:51:24 UTC). Run:

```sh
scripts/verify/engineering-audit.sh --full \
  --output target/audit-verification/fpga-m1-05b078d-full
```

The retained manifest, exact commands, logs, environment, lockfile and production
artifact hashes are in that directory. QEMU signed/release/SMP1, release-profile
tests, fresh RISC-V Clippy, Lean, concurrency models and Miri pass. The two gate
skips are optional QEMU fault injection (`RUN_AUDIT_FAULT` unset) and the explicitly
deferred SMP4 scheduler check. Test-level ignored cases remain visible in the
raw logs. This supersedes the earlier failing software gate for this candidate;
it does not supersede any physical gate. Repeat the full gate after integrating
the concrete adapter and before deploying its changed image.

Retained `summary.json` SHA-256: `5c2c821504b1f6145a31013bba7bc2bca1e96f37dad8914dda12798f437bd86b`.
Retained `manifest.txt` SHA-256: `ca3012b5be04e2b7844a7af731f770d612cf89e9a3b453cced86fb30ba078ee8`.


### Elapsed-I/O quiescence correction — 2026-09-13

Commit `41a5a01` closes an additional local drain-model timing gap. Previously,
reset/receive handling time could count toward the 200 ms quiet interval. The
model now starts its timer after reset completes, brackets each receive attempt
with the existing monotonic clock, uses the earlier timestamp to qualify an
empty observation and the later timestamp to restart quiet after a byte.
Regression checks cover 50 microseconds spent in reset, receive and empty-read
return handling. Clock regression still poisons readiness; each poll still reads
at most 64 bytes. No session or rearm authority is created.

Independent review passed. The follow-up passes 111 host tests, strict Clippy,
19 control Miri tests and the RP2040 no_std target check. Focused commands,
source hash, regression failure/pass and logs are retained under ignored
`target/audit-verification/quiescence-41a5a01/`, covered by `SHA256SUMS`.
The full audit above belongs to `05b078d`; the successful GitHub run
[34709566663](https://github.com/volnlabs/axiomos/actions/runs/34709566663)
belongs to `5d4745c`. The new correction has the separately recorded focused
verification, not a retroactive full-audit claim. Actual UART/FIFO observations,
clock calibration and the real adapter still require the physical gate.
