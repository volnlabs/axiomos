# axiomos verifier formalization (Lean 4)

Machine-checked proofs about the abstract domain of the axiomos BPF verifier.
This is the running proof-of-concept for
[#91 — formal proof of verifier core invariants](https://github.com/pro-utkarshM/axiomOS/issues/91).

## What is proved today

`AxiomFormal/Tnum.lean` models `TnumValue` from
`kernel/crates/kernel_bpf/src/verifier/state.rs` over `BitVec 64` — a
verbatim transcription of the Rust operators (which follow Linux's
`kernel/bpf/tnum.c`) — and proves, with `bv_decide` (bit-blasting to a SAT
solver that returns an LRAT certificate checked inside Lean's kernel):

| Theorem | Statement |
|---|---|
| `add_sound` | x ∈ γ(a), y ∈ γ(b) ⟹ x+y ∈ γ(add a b), for well-formed a, b |
| `sub_sound` | same, for subtraction |
| `and_sound` | same, for bitwise AND |
| `add_wellFormed`, `sub_wellFormed`, `and_wellFormed` | each operator preserves the `value &&& mask = 0` invariant |
| `mem_const`, `mem_unknown` | constants concretize to themselves; `unknown` is ⊤ |

One finding already: `bv_decide` produces concrete counterexamples to
`add`/`sub` soundness on *malformed* tnums (a bit simultaneously known-1 and
unknown). The well-formedness invariant is load-bearing, and the
preservation lemmas are what make the soundness hypotheses compose across an
abstract execution.

## Building

```sh
# toolchain pinned by lean-toolchain (elan picks it up automatically)
cd formal && lake build
```

No dependencies — Lean core only (no mathlib), so the build is seconds, not
hours. Zero `sorry`.

## Roadmap to the #91 theorem

Ordered so each stage is independently publishable:

1. **Full tnum operator suite** — `or`, `xor`, `lsh`, `rsh`, `arshift`,
   `mul`, `intersect`, `subsumes`. All but `mul` should be single
   `bv_decide` calls like the ones here; `mul`'s loop needs induction with a
   per-iteration `bv_decide` lemma. `subsumes` correctness
   (`subsumes a b ⟹ γ(b) ⊆ γ(a)`) is what the pruner's safety rests on.
2. **Range domain** — signed/unsigned min/max from `state.rs`, soundness of
   the ALU transfer functions in `alu.rs`, and consistency of the
   tnum × range product (the reduction steps where each refines the other).
3. **Branch refinement** — `refine.rs`: conditional-edge narrowing preserves
   membership of the values that actually take the edge.
4. **The main theorem** — a small-step semantics for the BPF instruction set
   (interpreter model), an abstract-interpretation soundness statement:
   *every program accepted by `Verifier` executes without OOB access, stack
   overflow, div-by-zero, uninitialized reads, or exceeding the instruction
   budget*. Realistically: formalize the verifier's core loop as a function
   in Lean and prove it, then argue (or refinement-prove) that the Rust
   implements it.

## Prior art this builds on

- **Agni** (CAV'23) — SMT-checked Linux's tnum/range transfer functions from
  C source. Our operators are ports of the same code; stage 1 is Agni's
  result, re-established for the Rust port with checkable proof terms.
- **CertrBPF** (CAV'22/'24) — verified BPF *interpreter* + JIT for RIOT in
  Coq. Their instruction semantics is the template for stage 4's concrete
  side.
- **PREVAIL** — abstract-interpretation BPF verifier (engineering, no proof
  of its acceptance set); useful for comparing domain design decisions.

## For potential collaborators

This is a real kernel (boots on Raspberry Pi 5, programs actuate motors)
with a solo-authored, unproven, load-bearing verifier — exactly the setting
where a mechanized soundness result is both publishable (PLDI/CAV/OSDI
material per stage 2–4) and consequential. The abstract domain is small,
pure, and already transcribes cleanly (this directory took an afternoon).
If stages 2–4 interest you: co-authorship is on the table, the maintainer
is responsive, and the contact is in [SECURITY.md](../SECURITY.md).
Context documents: [threat model](../docs/security/threat-model.md),
[verifier review call](../docs/reviews/implementation/verifier-review-call.md).
