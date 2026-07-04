# Call for review: break the Axiom BPF verifier

> **Status: DRAFT — not yet posted.** Maintainer TODOs before posting: decide
> the bounty section, fill in the posting date and commit hash, and confirm
> issue links render on the public repo.

Axiom is a research kernel for robotics workloads (Rust, `no_std`, runs on
Raspberry Pi 5 and x86_64/QEMU). Untrusted logic runs as eBPF-style programs
attached to kernel hooks (GPIO, PWM, IIO sensors, timers, syscalls). The only
thing standing between a loaded program and the kernel is a static verifier.

I wrote that verifier alone. Solo authorship is structurally bad for verifier
soundness — the author has the same blind spots as the implementation, and
Linux's far-more-reviewed verifier has a long CVE history in exactly this
kind of code (CVE-2021-3490, CVE-2022-23222, CVE-2022-2785). So this is a
standing challenge:

**Find a BPF program that passes verification but does an unsafe thing.**

## Concrete targets

Any one of these is a confirmed soundness bug and gets filed, credited, and
fixed before the next tagged release:

1. **Out-of-bounds access** — a verified program that reads or writes memory
   outside its stack frame, map values, or typed context region.
2. **Stack overflow** — stack depth or frame escape the verifier fails to
   catch (including through BPF-to-BPF call inlining).
3. **Loop bound violation** — control flow that executes unboundedly or past
   the profile instruction budget despite passing verification.
4. **Helper contract bypass** — a helper call whose argument constraints
   (pointer validity, size bounds, enum ranges) are not actually enforced.
5. **Arithmetic-driven corruption** — division by zero reaching the
   interpreter, or integer over/underflow that lets a bounds check pass and
   an out-of-bounds access happen.

Near-misses are also valuable: imprecision that rejects safe programs,
state-explosion inputs, or divergence between what the verifier models and
what the interpreter executes.

## What the verifier claims

For every program it accepts:

- All memory accesses stay within verified regions (stack, map values with
  per-map sizing, program-type-specific context bounds).
- Execution terminates within the profile instruction budget (100k embedded /
  1M cloud); no unbounded loops.
- No reads of uninitialized registers or stack slots.
- Every helper call matches the helper's registered signature and argument
  constraints.
- `DIV`/`MOD` by a register that can be zero is rejected.
- Programs on real-time hooks additionally pass WCET admission (a
  Pi5-calibrated cost model feeding an EDF utilization bound).

## What it trusts (attack surface you can ignore, or not)

- The interpreter executes instructions with the semantics the verifier
  models. (Divergence between the two is target #5's cousin — report it.)
- The loader normalization pass (`loader/normalize.rs`) that inlines
  BPF-to-BPF calls into a flat program *before* verification is part of the
  trusted path: if you can smuggle un-normalized structure past it, that
  counts.
- Helper implementations honor their declared contracts.
- No speculative-execution adversary — Spectre-class mitigations are **not
  implemented** (issue #89, known gap).
- Program authenticity: Ed25519 signing exists but enforcement is
  **default-off** (`allow_unsigned = true`; issue #20). Assume the attacker
  can load programs — that is exactly the assumption the verifier is built
  under.
- Execution engine: the embedded (Pi5) profile is interpreter-only; the
  cloud profile may JIT, and JIT output is not re-verified — the verifier's
  guarantees must carry the JIT too.

## Where to look

~7,650 lines of `#![no_std]` Rust, **zero `unsafe`**, in
`kernel/crates/kernel_bpf/src/verifier/`:

| Module | What it does |
|---|---|
| `core.rs` | Main verification loop: worklist over CFG, per-path abstract execution |
| `state.rs` | Abstract domain: tnums (known-bits) + signed/unsigned ranges per register |
| `alu.rs` | ALU transfer functions, 32/64-bit width handling |
| `refine.rs` | Branch refinement: narrowing register state on conditional edges |
| `pruner.rs` | State subsumption / pruning (bounded per-pc) |
| `cfg.rs` | Control-flow graph construction, jump-target validation |
| `helpers.rs` | Helper signatures and argument constraint checking |
| `caller.rs` | Privileged vs unprivileged caller policy |
| `liveness.rs` | Register liveness for pruning precision |
| `admission.rs`, `cost.rs` | WCET cost model + EDF admission bound |

Upstream of the verifier: `kernel/crates/kernel_bpf/src/loader/normalize.rs`
(subprogram inlining, jump fixup, depth/size caps). Downstream:
`kernel/crates/kernel_bpf/src/execution/interpreter.rs`.

The tnum operators follow Linux's `tnum.c`, which Agni (CAV'23) SMT-verified —
divergence from those semantics in our Rust port is a finding.

## Reproducing / testing locally

No kernel build needed — the verifier runs on the host:

```sh
git clone https://github.com/pro-utkarshM/axiomOS && cd axiomOS
cargo test -p kernel_bpf --features embedded-profile
```

Write adversarial programs as bytecode arrays against `Verifier` the same way
the existing tests in `kernel/crates/kernel_bpf/src/verifier/` do. The full
in-kernel path (QEMU boot + `sys_bpf` load) is documented in the repo, but a
host-side reproducer is enough for any soundness report.

## Context documents

- [Threat model & assurance positioning vs seL4](../THREAT_MODEL.md)
- [Verifier fragment & WCET bound](../verifier-fragment.md)
- [Security policy / how to report](../../SECURITY.md)

## Bounty

> **TBD by maintainer before posting** — options on the table: $500 for the
> first confirmed soundness finding (targets 1–5 above), or credit-only.
> Either way, every confirmed finding is credited in the fix commit and
> release notes.

## Scope notes

- One verifier: the older "streaming verifier" was retired 2026-06-13; the
  path-sensitive `Verifier` is the sole verification artifact.
- Known open gaps you don't need to rediscover: Spectre mitigations (#89),
  BTF (#90), signature enforcement on load (#20).
