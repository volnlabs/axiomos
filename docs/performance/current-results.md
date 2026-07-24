# axiomos benchmark evidence

This page is the current benchmark authority. A number is current release
evidence only when its campaign records the exact source commit, toolchain,
command, host or hardware boundary, tracked raw output, and SHA-256 hashes for
both the raw log and measured artifact. Provisional lab observations may be
retained in a separately labeled section, but they do not satisfy this
publication contract and must not support release claims. Methodology and
unsupported legacy claims are retained in the
[historical benchmark record](../archive/benchmarks/2026-06-legacy-benchmarks.md),
not silently presented as current results.

## Current attributable campaign

### Host BPF verifier, `2ef74f0`

| Field | Value |
|---|---|
| Source | `2ef74f0d43b6beeebf24e984d7b8c74ad1b27e8f` |
| Date | 2026-07-17 |
| Toolchain | `nightly-2026-07-02`; `rustc 1.98.0-nightly (4c9d2bfe4 2026-07-01)` |
| Host | Linux 7.0.9 x86_64; AMD Ryzen 7 7735HS; 16 logical CPUs |
| Command | `CARGO_TERM_COLOR=never cargo bench --locked -p kernel_bpf --bench verifier --features embedded-profile` |
| Raw output | [`evidence/2ef74f0/verifier-host.log`](evidence/2ef74f0/verifier-host.log) |
| Evidence manifest | [`evidence/2ef74f0/manifest.toml`](evidence/2ef74f0/manifest.toml) |

Criterion collected 100 samples per group after its normal warm-up. Values are
the reported 95% confidence intervals from the tracked raw output.

| Benchmark | 95% confidence interval |
|---|---:|
| minimal program | 943.28–945.39 ns |
| arithmetic program | 1.6903–1.6936 µs |
| 10 instructions | 3.1151–3.1216 µs |
| 50 instructions | 15.257–15.293 µs |
| 100 instructions | 31.437–31.465 µs |
| 500 instructions | 180.98–183.22 µs |
| 1000 instructions | 376.43–379.28 µs |
| linear control flow | 1.9926–1.9994 µs |
| one branch | 2.3288–2.3420 µs |
| multiple branches | 3.3792–3.3837 µs |

This is a single unpinned developer-host campaign, not a latency service-level
objective or a cross-machine comparison. Criterion's change annotations compare
against an untracked local baseline and are not part of the published result;
only the absolute intervals above are claimed.

## Provisional Pi 5 v0.3 HIL observations

These measurements are retained for engineering use, not as current release
evidence. The deployed-image records all say `worktree_dirty = true`. Clean
rebuilds of the subsequent commits produced different `kernel8.img` hashes, so
the deployed binaries cannot be tied to exact source commits under the contract
above. The tracked [capture notes](evidence/hil-v03-20260724/README.md) and
[provisional hash manifest](evidence/hil-v03-20260724/provisional.toml) preserve
the raw UART logs, sigrok captures, deployed-image hashes, and failed
clean-rebuild comparisons.

| Field | Value |
|---|---|
| Date | 2026-07-24 |
| Toolchain | `nightly-2026-07-02`; `rustc 1.98.0-nightly (4c9d2bfe4 2026-07-01)` |
| Hardware | Raspberry Pi 5 (8 GB, RP1); Shrike-Lite GPIO22 stimulus; fx2lafw logic analyzer at 24 MHz; Pi Debug Probe UART |
| Boundary | GPIO23 sensor edge → verified BPF reflex → ARM-A monitor → GPIO12 GPIO-level actuation |
| Timebase | on-chip `CNTVCT_EL0`, converted with `CNTFRQ_EL0` |
| Reduction | `python3 scripts/hil/v03b-reduce.py --warmup 16 latency-smoke-uart.log latency-main-uart.log` |

The two latency logs are separate cold boots of the same deployed image. The
reducer drops 16 cold-cache/TLB samples from each log before pooling and uses
nearest-rank percentiles.

| Metric | n | median | p95 | p99 | p99.9 | max | target | observation |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| **M-A** monitor decision overhead (V03-A) | 10 164 | 37 ns | 55 ns | 55 ns | 55 ns | 55 ns | < 5 µs | target met; provenance provisional |
| **M-C** IRQ-entry→actuate software path (V03-B) | 10 162 | 4.500 µs | 5.462 µs | 5.481 µs | 5.500 µs | 6.888 µs | < 1 µs | **target failed** |

- The M-C sample-count requirement is met, but its latency requirement is not:
  the median is 4.5 times the 1 µs target.
- The single GPIO23-rising→GPIO12-falling analyzer sample was **9.25 µs**
  (D1 fell at sample 222 at 24 MHz). It validates the rig only; it is not a
  distribution or bound.
- The V03-C log reports
  `PI5_V03C n=1000 escapes=0 safed=450 seed=0x5652303343000001`. This is a
  successful provisional observation, not an attributable acceptance result.
- V03-D (physical e-stop edge→output low, N≥100) has not run.
- No hardware-PWM latency is claimed; the tested output was GPIO-level because
  RP1 `clk_pwm0` bring-up remains unresolved.

## Historical claim disposition

| Legacy campaign | Disposition |
|---|---|
| QEMU x86 boot, BPF-load, and timer numbers | Invalid as timing evidence because the H-02 HPET tick-to-nanosecond conversion was wrong; no tracked raw capture or artifact hash. |
| Raspberry Pi 5 boot, memory, BPF, and interrupt numbers at `bedc93c` | Historical only. The document named a commit and hardware but did not retain the UART capture or artifact hash. |
| Raspberry Pi OS/Linux comparison | Historical only. No tracked raw `dmesg`, `cyclictest`, binary, or artifact hashes. |
| 2026-06 host verifier table | Superseded by the attributable `2ef74f0` campaign above; its raw Criterion output and executable hash were not retained. |
| Pi 5 verifier/WCET calibration and admission tables | Historical only. Local UART text was not committed, and the kernel artifact was not hashed into a campaign manifest. |
| ARM-A monitor and GPIO latency | Provisional 2026-07-24 observations are retained above, but the dirty deployed-image source prevents promotion to attributable current evidence. |

No QEMU, Pi, Linux, boot-time, interrupt-latency, WCET, or comparative-speed
headline is current release evidence until it is rerun under this contract.

## Reproduction and verification

Check out the recorded commit and run the command in the campaign table. Cargo
prints the exact benchmark executable path in the raw log. Hash that executable,
the raw output, and every declared source input, then compare them with the
manifest. The required local gate performs the durable checks:

```sh
python3 -B scripts/verify/benchmark-provenance.py
```

The checker verifies the tracked raw-log hash, confirms the Cargo-reported
artifact path and all ten result markers appear in the log, validates the
recorded source-input hashes against the exact Git commit, and requires a
well-formed executable hash. It does not claim reproducible binary bytes across
different hosts or linker environments; the executable hash identifies the
artifact that produced this specific campaign.

### Reproducing a Pi 5 HIL image

Pi 5 kernel images are bit-reproducible on the same host and toolchain. A clean
rebuild at the campaign's `source_commit`, with the same feature set and the
same embedded trust-root inputs, must reproduce `kernel8_sha256` exactly:

```sh
export AXIOM_BPF_TRUSTED_KEY_PATH=~/.local/share/axiomos-lab/axiomos-v03-v04-lab.pub
export AXIOM_SIGNED_BPF_STARTUP_PATH=~/.local/share/axiomos-lab/axiomos-v03-v04-startup.rbpf
cargo clean
cargo xtask build rpi5 -- release <features from build.toml>
sha256sum target/aarch64-unknown-none/release/kernel8.img
```

This holds only because the embedded ext2 rootfs is generated deterministically.
`mke2fs` otherwise stamps a random filesystem UUID, a random directory hash
seed, and the current time into the superblock and inodes, so every build
produced a different `disk.img` and therefore a different `kernel8.img`. Both
generators (`build.rs` and `kernel/build.rs`) now pin `-U`, `-E hash_seed=`, and
`SOURCE_DATE_EPOCH`. The hash-seed UUID must be non-zero: `mke2fs` treats the
all-zero UUID as unset and falls back to a random seed.

An image whose `build.toml` records `worktree_dirty = true` cannot be
reproduced, because its source is not fully described by the commit. Such
evidence stays provisional regardless of how well its hashes are recorded.

## Adding a campaign

1. Start from a clean, committed tree and use the pinned repository toolchain.
2. Store raw output and `manifest.toml` under
   `docs/performance/evidence/<commit>/`.
3. Record the Cargo-reported executable, its SHA-256, host/hardware controls,
   exact command, and hashes of benchmark source, `Cargo.lock`, and
   `rust-toolchain.toml` at that commit.
4. Add only results directly present in the raw output. Hardware campaigns must
   also retain UART/logic-analyzer captures and deployed-image hashes.
5. Run the required benchmark-provenance and documentation-link checks.
