# The bounded verifiable fragment & verifier-WCET

This document defines the **fragment of BPF the verifier can analyse in bounded
cost**, states the cost bound, and describes how to measure it. It is the
engineering reference for the bounded-verification track (#93); the research
write-up lives separately.

## Why bound verification cost?

Axiom's pitch is on-device, hot-reloadable kernel extensions for real-time
systems. If a program can be *loaded* on a running robot, the act of *verifying*
it competes for CPU with the control loop. Unlike Linux — whose verifier has
only a heuristic "complexity limit" and whose verification time is effectively
unbounded — we want verification cost to be **bounded and pre-declarable** as a
function of program size. That requires (a) restricting to a fragment where the
bound holds and (b) a verifier whose per-state work and total state count are
themselves bounded.

## The fragment `F`

A program is in `F` when:

1. **Loop-free control flow.** No back edges in the CFG. The embedded profile
   already enforces this — `verify_profile_constraints` rejects programs with
   back edges (`verifier/core.rs`, `verify_embedded_constraints`). (The cloud
   profile permits loops and is therefore *not* in `F`; it relies on the
   recorded-state budget below to stay bounded.)
2. **Bounded helper set.** Only helpers in the profile's allow-list
   (`verifier/helpers.rs`), none performing dynamic allocation.
3. **No dynamic allocation / unbounded memory.** Enforced by (2) plus the
   profile's static-memory strategy.
4. **Instruction count ≤ `P::MAX_INSN_COUNT`** (`check_basic`).

## Abstract domain

Per register: a **tnum** (known-bits) × **unsigned interval**, plus a flat
register-**type** lattice (`verifier/state.rs`). Stack slots take one of a few
`StackSlot` values. The domain has finite height `h`: along any path a
register's abstraction can only be refined (narrowed) a bounded number of times
before reaching a fixed point.

## Cost bound

The cost metric is **distinct states explored** (`VerifyStats::states_explored`,
returned by `Verifier::verify_with_stats`). It dominates both verification time
(per-state work is bounded — a pruner subsumption walk plus one instruction
transfer) and memory (one recorded state each).

For `P ∈ F` with `n` instructions over a domain of height `h`, monotone
exploration visits each program point at most `h + 1` times, so:

```
states_explored  ≤  (h + 1) · n        ⇒    verification cost = O(n)
```

For straight-line code (`h` irrelevant, single path) this is exactly one state
per instruction — see the `bounded_fragment_state_count_is_linear` test in
`verifier/core.rs`, which asserts `states_explored ≤ n` across a range of `n`.

## What makes the bound real in the implementation

| Mechanism | File | Role |
|---|---|---|
| Loop-free fragment (embedded) | `verifier/core.rs` `verify_embedded_constraints` | keeps `h` small, removes the back-edge blow-up |
| Explicit worklist (no recursion) | `verifier/core.rs` `explore` (#117) | bounds **native-stack** use — verification can't overflow the kernel stack |
| Sparse stack state | `verifier/state.rs` `StackState` (#118) | per-state cost ~1 KiB instead of ~1 MiB |
| Recorded-state budget | `verifier/pruner.rs` `DEFAULT_MAX_STATES` (#116, raised in #118) | hard cap; exceeding it rejects with `StateLimitExceeded` rather than running unbounded |
| Liveness-aware pruning | `verifier/{liveness,pruner}.rs` | fewer distinct states ⇒ tighter constant |

## Current ceiling & next lever

With sparse stacks, memory is no longer the binding constraint. The current
ceiling is the **pruner's per-pc subsumption walk**, which is `O(states²)` on a
non-converging loop (cloud profile). That is why `DEFAULT_MAX_STATES` is 8192
rather than larger. Making the pruner **sub-quadratic** (hash/bucket the per-pc
states, à la Linux `is_state_visited`) is the next change that lets the budget —
and thus the size of programs verifiable in bounded cost — rise substantially.

## How to measure

- **Automated (CI):** `bounded_fragment_state_count_is_linear`
  (`cargo test -p kernel_bpf --features cloud-profile`) asserts the linear
  state-count bound and guards against super-linear regressions.
- **Cost of any program:** call `Verifier::verify_with_stats(...)` and read
  `VerifyStats::states_explored`.
- **Wall-clock WCET curve (host):** the `verifier` criterion bench
  (`kernel/crates/kernel_bpf/benches/verifier.rs`) already times verification vs
  program size (`bench_scaling`). Note that running benches needs the BPF helper
  symbols the interpreter declares `extern "C"` — provided by the kernel or the
  `cfg(test)` stubs — so a standalone `cargo bench` requires host stubs; the
  state-count test above is the profile-independent, CI-checked measurement.
- **On-device cost curve (Track B):** build the kernel with the `verifier-cost`
  feature and the load path emits one marker per BPF load,
  `AXIOM VERIFIER COST prog_id=… insns=… states=… cycles=…`, where `cycles` is a
  `CNTVCT_EL0` delta around `verify_with_stats`. The `verifier_bench` userspace
  driver loads a size series (`cost_corpus::MEASUREMENT_SIZES`); capture the UART
  log and run `scripts/verifier-cost.py` to get the cost-vs-size CSV and plot
  (states with the `T(n)=(h+1)·n` overlay, cycles vs `n`). The shared shapes live
  in `kernel_bpf::cost_corpus`, whose `cost_corpus` unit tests pin the
  `states_explored ≤ n` bound at the exact measurement sizes. This is the
  authoritative (real A76, in-kernel) measurement; the host criterion curve is a
  proxy. See `docs/benchmarks.md` §12.
