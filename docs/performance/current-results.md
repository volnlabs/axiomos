# axiomos benchmark evidence

This page is the current benchmark authority. A number is publishable here only
when its campaign records the exact source commit, toolchain, command, host or
hardware boundary, tracked raw output, and SHA-256 hashes for both the raw log
and the Cargo-reported benchmark executable. Methodology and unsupported legacy
claims are retained in the [historical benchmark record](../archive/benchmarks/2026-06-legacy-benchmarks.md),
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

## Historical claim disposition

| Legacy campaign | Disposition |
|---|---|
| QEMU x86 boot, BPF-load, and timer numbers | Invalid as timing evidence because the H-02 HPET tick-to-nanosecond conversion was wrong; no tracked raw capture or artifact hash. |
| Raspberry Pi 5 boot, memory, BPF, and interrupt numbers at `bedc93c` | Historical only. The document named a commit and hardware but did not retain the UART capture or artifact hash. |
| Raspberry Pi OS/Linux comparison | Historical only. No tracked raw `dmesg`, `cyclictest`, binary, or artifact hashes. |
| 2026-06 host verifier table | Superseded by the attributable `2ef74f0` campaign above; its raw Criterion output and executable hash were not retained. |
| Pi 5 verifier/WCET calibration and admission tables | Historical only. Local UART text was not committed, and the kernel artifact was not hashed into a campaign manifest. |
| ARM-A monitor and GPIO latency | Not measured; requires the physical HIL contract and retained serial/logic-analyzer captures. |

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
