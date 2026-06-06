# BPF verifier fuzz harness

Closes the loop that #82 set up: continuous adversarial input against the
verifier so soundness issues surface here rather than in a kernel that
already shipped.

## Targets

Three `libfuzzer-sys` targets, each with a different oracle:

| Target | Oracle | What it catches |
| --- | --- | --- |
| `verify_only` | crash | The verifier must terminate on every input within bounded resources. Panics, hangs, OOM are all surfaced. |
| `verify_then_exec` | soundness | If the verifier accepts a program, the interpreter must execute it without panicking. A panic here is a verifier soundness bug — the most serious class of finding. |
| `streaming_match` | differential | If the streaming verifier accepts a program, the full verifier must also accept it. The forward direction matters because streaming is the cheaper check we'd use in resource-constrained paths. |

All three reinterpret libfuzzer's `&[u8]` input as `&[BpfInsn]` (8-byte
`#[repr(C)]` POD). Any bit pattern is a syntactically valid (if often
malformed) instruction stream — that's the input space the verifier has
to handle.

## Running locally

```bash
# One-time
cargo install cargo-fuzz

# Short smoke (use during development)
cd kernel/crates/kernel_bpf
cargo fuzz run verify_only -- -max_total_time=60

# Long campaign (use after merging changes that touch the verifier)
cargo fuzz run verify_only -- -max_total_time=28800   # 8 hours
cargo fuzz run verify_then_exec -- -max_total_time=28800
```

The first run for any new target seeds an empty corpus and finds easy
bugs fast. Subsequent runs reuse the accumulated corpus in
`fuzz/corpus/<target>/` and explore deeper.

## Reproducing a crash

When libfuzzer finds a crash it writes the input to
`fuzz/artifacts/<target>/crash-<hash>`. Reproduce with:

```bash
cargo fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

Triage notes: the input is the raw byte stream that triggered the crash.
Treat it as `[BpfInsn; N]`. The first 8 bytes are instruction 0, the next
8 bytes are instruction 1, and so on.

## Known findings

`known-findings/` holds inputs that are known to crash a specific target
but are tracked under a separate issue. Inputs there should *not* be in
the active corpus, because libfuzzer would otherwise crash on every run.
Each file has a corresponding issue documenting the analysis.

- `streaming-divergence-001.bin` — `streaming_match` reproduces a divergence
  where the streaming verifier accepts a two-instruction program the full
  verifier rejects. Filed as a separate issue under `verifier-hardening`.

## CI integration

GitHub Actions runs `verify_only` for 60 seconds on every PR via the
`fuzz-smoke` job. A scheduled nightly workflow runs each target for 8
hours; new artifacts surface as auto-filed issues for triage.

The PR job is intentionally narrow — 60s of `verify_only` is enough to
catch regression-class panics without making CI slow. Soundness work
happens in the long nightly runs.

## Adding a new fuzz target

1. New `fuzz_targets/<name>.rs` following the pattern of the existing
   three. Reuse the `as_insns` helper for input shape.
2. Add the corresponding `[[bin]]` block in `Cargo.toml`.
3. Add a row to the table above.
4. Decide whether it belongs in the PR-smoke job (fast, narrow oracle) or
   the nightly run (broader, more expensive).

## Why not cargo-fuzz init defaults

cargo-fuzz's `init` generates a single fuzz target named `fuzz_target_1`
in a workspace named after the parent crate. We renamed the workspace to
`kernel-bpf-fuzz` and replaced the placeholder with three named targets
so the binaries are self-describing in CI logs and crash reports.
