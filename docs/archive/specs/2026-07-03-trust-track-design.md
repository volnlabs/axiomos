# Trust / External Validation Track — Design

> **Archived historical record.** Retained for provenance; not a current
> implementation contract. See the [current documentation authority](../../README.md).

**Date:** 2026-07-03
**Issues:** #39 (threat model RFC), #77 (external security review), #91 (formal proof of verifier invariants)
**Branch:** `feat_verifier_hardening`

## Goal

Produce the three trust-track artifacts in sequence: a threat model that
honestly positions Axiom against seL4, a call-for-review document that makes
the verifier reviewable by outsiders, and a Lean 4 proof-of-concept that
demonstrates the verifier's core abstract domain is formalizable. All three
are documentation plus one isolated `formal/` directory — no kernel code
changes.

## Context and constraints

- Verifier is ~7.6k LoC across `kernel/crates/kernel_bpf/src/verifier/`
  (issue #77's "3700 LoC" figure is stale; docs must use measured numbers).
- #77's stated preconditions are met: #121/#122/#123 closed, #87 (BPF-to-BPF
  calls via loader normalization) is complete on this branch. #89 (Spectre)
  and #90 (BTF) remain open and are disclosed as known gaps, not gated on.
- The streaming verifier is retired (06-13); the path-sensitive `Verifier`
  is the sole verification artifact. #39's questions about the streaming
  verifier are answered "retired."
- Program signing (#20) is not wired; the threat model must say so.
- Tnum operators in `state.rs` are pure `const fn`s written against Linux's
  `tnum.c`, which Agni (CAV'23) already SMT-verified — the Lean PoC leans on
  that prior art for operator definitions.

## Deliverable 1 — #39: `docs/security/threat-model.md` + `SECURITY.md`

`docs/security/threat-model.md` sections:

1. **Asset inventory** — kernel image, BPF runtime (verifier + interpreter;
   no JIT exists), attach points (GPIO, PWM, IIO, timer, syscall), signing
   keys (not wired — #20), BPF maps, persistent state.
2. **Adversary classes** — the six from the issue: remote network attacker
   (OTA path), OTA-MITM, malicious BPF author, compromised userspace,
   physical access, supply-chain via dependencies. Each gets an
   in-scope/out-of-scope verdict with justification.
3. **Trust boundaries** — mermaid diagram: userspace↔kernel (syscall ABI),
   BPF↔kernel (verifier + helper API), bootloader↔kernel (limine handoff),
   network↔system (future; no NIC driver today).
4. **Mitigation map** — per adversary class: which code enforces the
   boundary, cited as `file:line`. Gaps become filed issues.
5. **TCB sizing** — measured tokei/wc numbers for kernel core + verifier +
   BPF runtime, compared to seL4's ~10k proven LoC. Honest statement of
   what "in the TCB" means for us (no proofs, so TCB = trusted-by-assertion).
6. **Comparison matrix Axiom vs seL4** — proof status, TCB size, isolation
   model, scheduler guarantees, verifier assurance basis.
7. **Assurance tier** — the answer to #39's core question: Axiom today is
   *engineering safety* (Rust no_std + verifier + tests + external review
   pending), with a roadmap toward high-assurance robotics; it is not and
   does not claim defense-grade.
8. **Formalization roadmap** — what a full #91 proof would cover, pointing
   at `formal/` for the running PoC.

`SECURITY.md` at repo root: disclosure contact (repo owner email), scope
(what counts as a security bug — verifier soundness first), response
expectations, no-legal-threats safe-harbor sentence. Short.

## Deliverable 2 — #77: `docs/reviews/implementation/verifier-review-call.md`

The call-for-review post, drafted for community posting (posting itself is
the maintainer's manual step, out of scope):

- What the verifier guarantees (memory safety within verified regions,
  bounded execution, stack bounds, helper argument contracts, no
  uninitialized register reads).
- What it assumes (correct interpreter, correct loader normalization,
  correct helper implementations, no speculative-execution adversary — #89).
- Abstract domain tour: `state.rs` (tnum + range), `alu.rs` (transfer
  functions), `refine.rs` (branch refinement), `pruner.rs` (subsumption),
  `normalize.rs` (BPF-to-BPF call inlining).
- ABI surface: `sys_bpf` load path, program types, helper IDs.
- The challenge, stated as five concrete targets: OOB access that passes
  verification, uncaught stack overflow, loop bound violation, helper arg
  constraint bypass, div-by-zero / overflow-driven OOB.
- Known open gaps disclosed up front: #89 (Spectre), #90 (BTF).
- Bounty: placeholder section marked "TBD by maintainer before posting"
  (decision deferred by design).
- Links: THREAT_MODEL.md, `docs/security/verifier-assurance.md`, source paths.

## Deliverable 3 — #91: `formal/` Lean 4 PoC

Isolated Lake project, `formal/`:

- `Tnum` structure over `BitVec 64` (`value`, `mask`), mirroring
  `TnumValue` in `state.rs`.
- `wellFormed t : t.value &&& t.mask = 0`.
- Concretization `γ : Tnum → Set (BitVec 64)` — the set of concrete values
  consistent with the tnum.
- Definitions of `add` and `and` transcribed from `state.rs`.
- Theorems: membership soundness for both —
  `x ∈ γ a → y ∈ γ b → (x + y) ∈ γ (Tnum.add a b)` and the analogous
  statement for `and`, plus well-formedness preservation.
- `README.md`: roadmap to the full suite (11 operators → intersect/subsumes
  → range domain → the top-level "verifier accepts ⇒ interpreter safe"
  theorem), Agni/CertrBPF prior-art pointers, explicit collaborator pitch
  per #91's recruiting strategy.
- `lake build` must succeed with zero `sorry`. No CI wiring yet — deferred
  until a formal-methods contributor exists.

## Execution order and validation

#39 → #77 → #91. Mitigation-map and abstract-domain source citations are
gathered by a read-only exploration subagent and verified against the code
before landing in the docs. Validation: mermaid renders, cited `file:line`
spot-checked, `lake build` green, docs pass a self-review for stale claims
(LoC figures, issue states) against `gh issue` reality.

## Out of scope

- Posting to communities (maintainer action).
- Bounty amount decision.
- Any verifier code changes; any CI changes.
- Full operator suite or refinement proof (#91 long tail).
