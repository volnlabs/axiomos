# Hardware validation and benchmarking runbook

This is the execution checklist for `release/v0.5.0-alpha.2`. Its purpose is
to turn the source-level alpha into attributable Raspberry Pi 5, Shrike RP2040,
and final-PWM safety-gate evidence. It does **not** authorize a safety-relevant
robot deployment. Do not claim physical performance or safety until every
required physical check below has retained evidence.

Use this document with the [performance methodology](../performance/methodology.md),
the [current-results policy](../performance/current-results.md), and the
[Pi 5 verifier-cost calibration plan](../plans/active/pi5-verifier-cost-calibration.md).

## 0. Rules and stop conditions

- [ ] Work only from `release/v0.5.0-alpha.2`; record its commit before every
  build and do not mix artifacts from another revision.
- [ ] Keep the production Ed25519 public key offline except when exporting the
  32-byte public-key file required by the Pi build. Never commit keys, UART
  captures containing secrets, or removable-media device names.
- [ ] Begin with motors disconnected or mechanically unloaded, with an
  independently accessible physical e-stop. Do not bypass the final PWM gate.
- [ ] Treat an unexpected reset, a kernel panic, missing serial marker, failed
  provenance hash, watchdog reset, PWM output while e-stop is active, or any
  uncontrolled actuator movement as a **stop condition**. Remove motor power,
  preserve the capture and artifacts, and file a regression before retrying.
- [ ] Do not convert QEMU or RTL simulation numbers into physical timing or
  safety claims. They are preflight evidence only.

## 1. Host and lab preflight

Record the following in the campaign directory before compiling:

- [ ] Operator, UTC date/time, repository commit, dirty-tree status, and
  `rustc --version --verbose`.
- [ ] Host CPU/OS, Pi 5 board revision, boot-firmware revision/hash, SD-card
  identifier, RP2040 board/firmware revision, FPGA board revision, power
  supply, motor-driver revision, sensor wiring, and UART/logic-analyzer model.
- [ ] The tested wiring diagram, pin map, voltage domains, common ground, and
  e-stop path. Have a second person review the motor/e-stop wiring before power
  is applied.
- [ ] Confirm the Pi boot medium is removable and the deployment mount point
  is the **boot partition**, not the host root filesystem.

Install the repository toolchain and required local tools. The full gate needs
QEMU, Icarus Verilog (`iverilog` and `vvp`), Lean, Miri, clang/cargo-fuzz, and
the RISC-V GCC cross compiler. It also needs the targets declared in
[`ci/manifests/targets.toml`](../../ci/manifests/targets.toml).

```sh
git switch release/v0.5.0-alpha.2
git status --short
git rev-parse HEAD
cargo xtask check all --profile quick
cargo xtask check all --profile full
```

- [ ] Retain the full-gate `manifest.txt`, `results.tsv`, logs, and artifact
  hashes. A failed or skipped required check blocks hardware deployment.
- [ ] Run the RTL gate explicitly and retain its output:

```sh
scripts/verify/fpga-safety-gate.sh
```

Icarus compiles the SystemVerilog testbench and `vvp` executes it. This proves
the RTL truth table only; it does not prove a synthesized bitstream, pin
constraints, board routing, or electrical timing.

## 2. Build an attributable Pi 5 image

Create a campaign directory outside the repository build outputs, then provide
the exact 32-byte production public key to the build. The build embeds that
trust root and writes a provenance manifest covering the ELF, `kernel8.img`,
root filesystem, and public key.

```sh
export CAMPAIGN="$PWD/../axiomos-hil-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CAMPAIGN"
export AXIOM_BPF_TRUSTED_KEY_PATH=/secure/path/axiomos-ed25519.pub
test "$(wc -c < "$AXIOM_BPF_TRUSTED_KEY_PATH")" -eq 32

# Baseline hardware image.
cargo xtask build rpi5 -- release embedded-rpi5
cp target/aarch64-unknown-none/release/rpi5-artifacts.sha256 "$CAMPAIGN/"
sha256sum -c "$CAMPAIGN/rpi5-artifacts.sha256"
```

- [ ] Record the build command, commit, key-file SHA-256 (not its contents),
  image/ELF/rootfs SHA-256 values, and the feature set.
- [ ] Confirm `kernel8.img` and `rpi5-artifacts.sha256` exist below
  `target/aarch64-unknown-none/release/`.
- [ ] Rebuild rather than reusing a stale image whenever the commit, feature
  set, key, or root filesystem changes.

For verifier-cost calibration, make a **separate** instrumented image. Do not
use it as a production image:

```sh
cargo xtask build rpi5 -- release embedded-rpi5,verifier-cost
cp target/aarch64-unknown-none/release/rpi5-artifacts.sha256 \
  "$CAMPAIGN/verifier-cost-artifacts.sha256"
```

For GPIO-to-actuation timing work, build a separate `bench` feature image and
record its hashes in a distinct campaign. Benchmark instrumentation must never
be silently combined with the production artifact.

```sh
cargo xtask build rpi5 -- release embedded-rpi5,bench
```

## 3. Deploy and establish serial capture

First inspect the deployment command without writing media, then deploy only to
the mounted Pi boot partition. The deploy script verifies the retained artifact
hashes before copying `kernel8.img` and the provenance manifest.

```sh
cargo xtask deploy rpi5 --dry-run -- /path/to/mounted/pi-boot
cargo xtask deploy rpi5 -- /path/to/mounted/pi-boot
sync
```

- [ ] Record the boot-firmware revision/hash already present on the card. The
  repository does not fetch or pin that external firmware.
- [ ] Safely unmount/eject the card before moving it to the Pi.
- [ ] Connect the debug-probe UART, identify its stable `/dev/serial/by-id/...`
  path, and capture at 115200 baud before applying Pi power.

```sh
PORT=/dev/serial/by-id/<debug-probe-uart>
sudo timeout 120s cat "$PORT" | tr -d '\r' | tee "$CAMPAIGN/pi5-boot.log"
```

Raspberry Pi’s official setup guidance identifies power and boot media as
baseline requirements; its Pico-series documentation describes BOOTSEL/UF2
mass-storage recovery for RP2040-class boards. Keep those vendor procedures
separate from the repository’s image/provenance procedure.

## 4. Pi 5 staged bring-up checklist

Perform these stages in order. Do not connect motor power until the preceding
stage has a retained capture and explicit pass decision.

### 4.1 Kernel and rootfs

- [ ] Baseline boot reaches `QEMU_BOOT_OK`-equivalent physical boot markers and
  `INIT_PROCESS_STARTED` in UART output.
- [ ] Record absence of kernel panic, page fault, repeated reboot, or watchdog
  reset for the selected observation interval.
- [ ] Verify the expected signed-BPF path, including `SIGNED_BPF_LOAD_OK` for
  the production image.

### 4.2 GPIO, timer, and BPF dispatch

- [ ] With actuators disconnected, inject one documented GPIO edge at a time.
- [ ] Capture the GPIO IRQ, immutable-route dispatch, BPF load/attach result,
  and expected audit marker on UART.
- [ ] Repeat at least 100 times per edge type; record successes, drops,
  unexpected routes, and any missed event.
- [ ] Exercise e-stop assertion and release while outputs are unloaded. The
  expected safe state is PWM disabled; any contrary result is a stop condition.

### 4.3 Shrike control link and RP2040

- [ ] Build the firmware and host simulation checks through the full gate
  before flashing hardware.
- [ ] Flash only the reviewed binary using the board’s documented BOOTSEL/UF2
  or debug-probe procedure; record firmware SHA-256 and the exact flashing
  command.
- [ ] Capture RP2040 startup, control-link framing, watchdog/fail-safe
  behavior, invalid-frame handling, and loss-of-link behavior with motors
  disconnected.
- [ ] Verify that an asserted e-stop and invalid/out-of-range command both
  produce a motor-disabled state before a powered actuator test.

### 4.4 Final PWM safety gate and powered actuator test

- [ ] Record the exact FPGA board, toolchain, board project, constraint files,
  bitstream SHA-256, and programmed-device identifier. These are currently
  external to the repository and must be retained in the campaign.
- [ ] Probe both PWM outputs with a logic analyzer while toggling physical
  e-stop and testing commands below/at/above the ±800 per-mille limit.
- [ ] Confirm the gate drives both PWM outputs low for active-low e-stop and
  either out-of-range signed command. Repeat after power cycle and after Pi ↔
  RP2040 link loss.
- [ ] Only after the unloaded tests pass, attach a mechanically constrained
  actuator. Start at the lowest safe duty cycle and keep independent power cut
  access available.

## 5. Benchmark campaigns

Every publishable result needs a commit, command, pinned toolchain, host or
hardware boundary, raw output, and hashes for raw output and measured artifact.
Follow the repository’s [methodology](../performance/methodology.md); do not
add a headline number without that evidence.

### 5.1 Host verifier baseline

```sh
CARGO_TERM_COLOR=never cargo bench --locked -p kernel_bpf --bench verifier \
  --features embedded-profile | tee "$CAMPAIGN/verifier-host.log"
```

- [ ] Record the Cargo-reported benchmark executable path and SHA-256.
- [ ] Record the raw-log SHA-256, host CPU/OS, toolchain, and source-input
  hashes in `docs/performance/evidence/<commit>/manifest.toml`.
- [ ] Add only the confidence intervals present in the raw Criterion output to
  `docs/performance/current-results.md`.

### 5.2 Pi 5 verifier-cost calibration

Boot the `verifier-cost` image from section 2, then capture the whole run:

```sh
sudo timeout 70s cat "$PORT" | tr -d '\r' | tee "$CAMPAIGN/verifier-cost.log"
cargo xtask bench verifier -- "$CAMPAIGN/verifier-cost.log" \
  -o "$CAMPAIGN/verifier-cost.csv" \
  --plot "$CAMPAIGN/verifier-cost.png" \
  --cntfrq 54000000
```

- [ ] Run `/bin/verifier_bench` and retain all `AXIOM VERIFIER COST` and
  `AXIOM EXEC COST` lines.
- [ ] Check that `states == insns` for loop-free linear programs, verification
  cycles scale linearly with instruction count, and emitted WCET is monotonic.
- [ ] Confirm the actual counter frequency instead of assuming 54 MHz; record
  the measured value used by the analysis.
- [ ] Treat zero/saturated counter values, missing instrumentation, failed
  benchmark markers, or an implausible slope as invalid data—not a result.

### 5.3 GPIO-to-actuation and e-stop latency

- [ ] Use the `bench` image only and record the input stimulus and the logic
  analyzer clock calibration.
- [ ] Capture at least: GPIO edge, IRQ entry, BPF dispatch, monitor decision,
  and final PWM transition. Preserve raw analyzer exports, not screenshots
  alone.
- [ ] Report distribution statistics (sample count, min/median/p95/p99/max),
  trigger configuration, analyzer sample rate, and all excluded samples.
- [ ] Repeat after cold boot, warm boot, and representative non-critical load.
  Do not call a single best run a latency bound.

## 6. Evidence review and readiness decision

- [ ] Put raw UART logs, analyzer exports, CSV/plots, command transcripts,
  hardware/firmware/bitstream hashes, and a concise test matrix in a retained
  campaign directory.
- [ ] Add a provenance manifest under `docs/performance/evidence/<commit>/`.
  Update `docs/performance/current-results.md` only with directly supported
  measurements.
- [ ] Link failures and anomalies to GitHub issues; do not delete failed runs.
- [ ] Run `python3 -B scripts/verify/benchmark-provenance.py` and the full
  local gate after adding evidence.
- [ ] Require a human review of wiring, stop-condition results, and the
  campaign manifest before any new tag or hardware claim.

Completion of this checklist establishes a documented hardware campaign. It
does not by itself close the outstanding HIL, soak, secure-boot, SMP, or
runtime-evolution issues.

## References

- [Repository build procedure](build.md)
- [Boot and deployment procedure](boot.md)
- [Release verification boundary](release-verification.md)
- [Raspberry Pi computer getting-started documentation](https://www.raspberrypi.com/documentation/computers/getting-started.html)
- [Raspberry Pi Pico-series documentation](https://www.raspberrypi.com/documentation/microcontrollers/raspberry-pi-pico.html)
- [Icarus Verilog documentation](https://steveicarus.github.io/iverilog/)
