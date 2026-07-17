# BPF-to-BPF Calls via a Loader Normalization Pipeline (#87)

> **Archived historical record.** Retained for provenance; not a current
> implementation contract. See the [current documentation authority](../../current/README.md).

**Status:** design / approved-for-planning
**Branch:** `feat_verifier_hardening` (off `feat_v0.4`; merges to `dev` after `feat_v0.4`)
**Issue:** #87 — BPF-to-BPF function call verification
**Supersedes the issue's prescription:** the issue describes Linux's frame-stack
verifier model. This design deliberately does *not* mirror Linux. It optimizes
for axiomOS' research claims (bounded fragment `F`, linear verification cost,
exact static WCET) and for keeping the verifier mathematically simple.

## 1. Thesis and the core decision

axiomOS' pitch is on-device, hot-reloadable kernel extensions for real-time
systems, where **verification cost is bounded and pre-declarable as a function
of program size** (`docs/verifier-fragment.md`). The verifier proves safety over
a *bounded fragment* `F`: loop-free CFG, bounded helper set, no dynamic
allocation, `states_explored ≤ (h+1)·n`. A separate static WCET model bounds
*execution* cost via the longest path through the loop-free CFG DAG.

BPF-to-BPF calls (a PID controller's integral term, a CAN classifier's
per-frame-type function) must be supported without breaking either bound.

**Decision: handle subprogram calls as a pre-verification _normalization pass_
in the loader, not as new machinery inside the verifier.** The verifier never
reasons about call frames. It only ever sees a single, flat, loop-free program
— the same fragment `F` it already verifies.

### Pipeline

```
ELF
  → loader: relocations
  → loader: pseudo-call resolution      (classify call insns)
  → loader: subprogram graph            (boundaries + call edges)
  → loader: normalization pipeline      (recursion/depth/size checks, inline expansion, stack rebasing)
  → normalized program (flat Vec<BpfInsn> + metadata)
  → verifier: prove safety over the normalized program   (UNCHANGED)
  → WCET / scheduler admission
```

Responsibility split, enforced as an architectural boundary:

- **Loader** — transforms arbitrary input into the canonical internal
  representation. Owns *all* program transformation.
- **Verifier** — proves safety/correctness over that representation. Owns *no*
  transformation.

Both profiles (embedded and cloud) share one pipeline and one internal
representation. We do **not** create separate embedded/cloud verification paths.
Cloud is inlined too — even where a given normalization pass adds little for
cloud, a single shared path keeps the verifier uniformly frame-free.

This stage is structured as a **general normalization pipeline**, not a one-off
inliner. It is the intended future home of pseudo-call resolution (this spec),
BTF/CO-RE rewriting (#90), and other pre-verification rewrites.

## 2. Why canonicalization over Linux's frame-stack model

| Dimension | Canonicalization (this design) | Linux frame-stack | Winner |
|---|---|---|---|
| Verifier complexity | No new concepts; `verify_call` still only sees helpers. No frame stack, no slot-owner field. | Frame push/pop, per-fn CFG, frame index on every reg/slot, new join rules. | **Canon** |
| Soundness proof | Verifier proof unchanged. One isolated new obligation (§7). | Must extend soundness to a framed abstract domain. | **Canon** |
| Verification cost | `states ≤ (h+1)·N'` holds verbatim on expanded size `N'`. | `(h+1)·n·(call multiplicity)`; bound depends on call structure. | **Canon** |
| Static WCET | Flattened DAG longest-path = exact WCET incl. callee code; `cost.rs` untouched. | Must model call/return edges in the longest-path DP. | **Canon** |
| Frame isolation | Direct-access isolation enforced by rebase offset check; computed-pointer per-frame isolation deferred to #89 (memory-safe throughout). | Needs explicit slot-owner field. | **Canon** |
| Spectre (#89) | Uniform masking over flat program; BPF-to-BPF return-target speculation surface eliminated. | Speculation crosses frames; RSB return-target surface. | **Canon** |
| BTF (#90) | Resolved in the same pre-verifier stage; verifier stays BTF-agnostic. | Same staging possible, verifier more entangled. | **Canon** |
| Code-size growth | Multiplicative along call multiplicity; diamond nesting → worst-case exponential. | Shared callees verified once; no duplication. | **Linux** |

### The one place Linux is objectively superior

Inlining a call DAG with sharing is multiplicative. `f0` calls `f1` twice,
`f1` calls `f2` twice, … → `2ⁿ` expansion. Linux verifies each subprogram once
regardless of call count, so it accepts compact, heavily-shared graphs that the
canonicalizer rejects on size.

**Why this does not bite the embedded target, concretely:**

1. Target programs are tiny with shallow graphs (PID, CAN classifier, sensor
   fusion — a handful of small functions). The pathological pattern does not
   occur in robot control code.
2. **No surprise blowup.** Post-expansion size is computed *before* expanding via
   a topological DP — `size(f) = own_insns + Σ_{f→g} size(g)`. If it exceeds
   `MAX_INSN_COUNT`, reject deterministically with `ExpansionTooLarge`. Bounded
   and pre-declarable — the same spirit as the cost bound.
3. It is a deliberate, documented tradeoff: compactness-on-shared-graphs
   (irrelevant for embedded) is exchanged for an unchanged soundness proof and
   exact WCET — both central to the thesis.

## 3. Confirmed code facts the design relies on

- **Embedded profile:** `MAX_STACK_SIZE = 8 KiB`, `MAX_INSN_COUNT = 100_000`.
  Cloud: 512 KiB / 1_000_000. (`bytecode/program.rs`.)
- Linux caps call depth at 8 → `8 × 512 = 4 KiB` of frame stack. **4 KiB ≤ 8 KiB
  embedded**, so depth-bounded inlining fits with no limit changes.
- **Stack state is a sparse `BTreeMap<slot, StackSlot>`** bounds-checked against
  profile capacity (`verifier/state.rs`). Deeper frame windows reached by
  rebasing are already representable — no stack-model change.
- **Subprogram calls are detected nowhere today.** `reloc.rs` only handles
  `BPF_PSEUDO_MAP_FD`; `is_call()` checks only opcode `0x85` and ignores
  `src_reg`, so a subprog call currently misroutes into helper validation. The
  normalization pipeline is the natural owner of pseudo-call resolution.

## 4. Subprogram graph + checks

A BPF-to-BPF call is a `call` instruction (opcode `0x85`) with
`src_reg == BPF_PSEUDO_CALL (1)`; its `imm` is a signed instruction-relative
offset to the callee, relative to the next instruction. (A helper call has
`src_reg == 0` and `imm` = helper id.)

1. **Pseudo-call resolution.** Scan instructions; classify each `call` by
   `src_reg`. Helper calls are left untouched. Subprogram calls yield call edges
   `(call_site_idx → target_idx)`.
2. **Subprogram boundaries.** Entry points: instruction 0 (main) and every call
   target. A subprogram spans from its entry to its terminating `EXIT`(s).
3. **Recursion detection.** Build the call graph; any cycle → reject
   `RecursiveCall { subprog }`. (Recursion is forbidden in `F` and by Linux too.)
4. **Depth check.** Longest path in the (now acyclic) call graph; if
   `> MAX_CALL_DEPTH` (8) → reject `CallDepthExceeded`. Bounds flat-stack use to
   `depth × 512 ≤ 4 KiB`.
5. **Size pre-check.** Topological DP for post-expansion size; if
   `> MAX_INSN_COUNT` → reject `ExpansionTooLarge { got, limit }`.

## 5. Inline expansion + stack rebasing

Produce one flat `Vec<BpfInsn>`. For each call site, splice the callee body in
place of the `call`. An instance's **depth `d`** is its nesting depth along the
inline path (main = 0, its direct callees = 1, …; for diamonds, `d` = path
length from main to that instance).

Rewrite rules for an inlined body at depth `d > 0`:

- **`EXIT` → jump.** Each `EXIT` in an inlined (non-main) body becomes a `JA` to
  the return continuation (the instruction after the original call). Multiple
  `EXIT`s → multiple jumps to the same return site. The main program's `EXIT`
  stays an `EXIT` (terminates).
- **Internal relative jumps** within the spliced body remain valid unmodified —
  they are relative offsets and the body is copied contiguously.
- **Stack rebasing.** `r10` is the only source of a stack pointer (the verifier
  guarantees a stack pointer cannot be fabricated), so all stack addressing is
  either a direct `r10`-relative access or a copy of `r10` followed by
  arithmetic. Rebase both:
  - Direct `*(r10 + off)` (LDX/STX/ST) → `*(r10 + (off − d·512))`.
  - `MOV Xdst, r10` → emit `MOV Xdst, r10; ADD Xdst, −(d·512)`. Subsequent
    arithmetic on `Xdst` is already frame-relative and lands in the rebased
    window.

  After rebasing, a depth-`d` body's accesses occupy `[−(d+1)·512, −d·512)`.

  **Direct-access frame isolation (enforced).** A direct `r10`-relative
  access (`off` must be in `[−512, −1]`) that reaches outside the callee's
  own frame is rejected at load time (`StackOffsetOutOfFrame`). This covers
  all LDX/STX/ST with `r10` as the base register.

  **Computed-pointer isolation (deferred to #89).** A pointer produced by
  `MOV X, r10` followed by runtime arithmetic is rebased by the emitted
  `ADD X, −(d·512)` instruction. The flattened verifier's existing
  bounds-checking enforces memory safety on the resulting pointer, but
  per-frame isolation (preventing it from reaching the caller's window via
  arithmetic) is NOT enforced here. Full per-frame pointer masking is
  deferred to #89 (Spectre/pointer masking). Memory safety holds throughout.

- **Callee-saved R6–R9: inline verbatim, no injected save/restore.** The verifier
  never trusts that a call preserves R6–R9; it tracks the inlined body's actual
  effect. An ABI-correct subprogram (LLVM spills/reloads the R6–R9 it uses; the
  spills land in the rebased window) inlines transparently. A subprogram that
  clobbers R6–R9 verifies as clobbering them and is caught as a type error at the
  caller's next use. **Safe in all cases.** The only register-level rewrite is
  the stack rebase above.

- **Cross-frame pointer args.** A caller passing `r10`-relative pointer in R1–R5
  works automatically: the caller's pointer is rebased to the caller's window;
  the callee dereferences it there; the callee's own stack is its rebased window.

## 6. Internal representation + verifier interface

The normalized program is a flat `Vec<BpfInsn>` plus metadata:

```text
NormalizedProgram {
    insns:       Vec<BpfInsn>,           // flat, loop-free, helper-only calls
    stack_used:  usize,                  // max rebased depth × 512 (≤ MAX_STACK_SIZE)
    source_map:  Vec<(SubprogId, u32)>,  // expanded_idx → (subprog, original_idx)
}
```

The verifier already takes a flat `&[BpfInsn]` (`verify_with_config`), so its
interface barely changes: it consumes `NormalizedProgram::insns`. `source_map`
lets verifier errors and BTF line-info point back at source despite inlining.

## 7. Proof obligations

The verifier's existing soundness proof is **unchanged** — it still operates on
fragment `F`. The single new obligation is *normalization correctness*:

> Inline expansion with `EXIT → JA` rewriting, contiguous body copy, and stack
> rebasing (`off −= d·512` on direct accesses and on `r10` copies) preserves the
> operational semantics of the original program, given recursion-freedom and a
> bounded call depth, and produces a program in `F` whenever the source's
> per-subprogram bodies are in `F`.

This is a syntactic translation argument with no new abstract-domain reasoning —
the key reason this design keeps the verifier mathematically simple.

## 8. Errors

New `loader::error` variants: `RecursiveCall { subprog }`,
`CallDepthExceeded { depth, limit }`, `ExpansionTooLarge { got, limit }`,
`MalformedPseudoCall { insn_idx }` (e.g. target out of range).

## 9. Testing

- 3-function program (main + 2 leaf subprograms): normalizes + verifies; the flat
  program is loop-free and helper-only.
- Recursive variant (direct and transitive): rejected `RecursiveCall`.
- Depth-9 chain: rejected `CallDepthExceeded`.
- Diamond that exceeds `MAX_INSN_COUNT` after expansion: rejected
  `ExpansionTooLarge`, *before* expanding (size DP).
- Callee writes to a caller stack offset (original `off ≥ 0` relative to its
  frame): rejected by the existing out-of-frame check post-rebase.
- Stack-rebasing correctness: a subprogram that spills to `r10−8` reads back its
  own value; an interpreter run of the normalized program matches a reference
  run of the framed semantics for a small program (semantics-preservation check).
- Cost invariant preserved: `states_explored ≤ (h+1)·N'` and the existing
  `bounded_fragment_state_count_is_linear` style assertion holds on the
  *expanded* program.
- WCET: longest path over the flat CFG includes callee instructions on the worst
  path.

## 10. How #90 and #89 compose

- **#90 BTF/CO-RE:** lives in the same loader normalization pipeline, before the
  verifier. CO-RE relocations and typed-access rewrites are applied to the flat
  program; `source_map`/func-info offsets are recomputed for the expanded
  program. Verifier stays BTF-agnostic.
- **#89 Spectre:** masking/sanitization runs on the single flat program with no
  call-boundary special-casing; inlining also removes the BPF-to-BPF
  return-target speculation surface.

## 11. Out of scope

- BTF parsing/wiring (#90) and Spectre mitigations (#89) — separate specs on this
  branch; this spec only ensures the pipeline is the right home for them.
- Tail calls (`bpf_tail_call`) — distinct mechanism, not BPF-to-BPF calls.
- Cloud-profile loop support — orthogonal; the normalization pipeline does not
  change loop handling.
