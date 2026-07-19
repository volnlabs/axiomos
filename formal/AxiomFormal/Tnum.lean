/-
Tnum (tracked number / known-bits) abstract domain — Lean 4 model of
`TnumValue` in `kernel/crates/kernel_bpf/src/verifier/state.rs`.

A tnum represents a set of 64-bit values by a `value` (the known bits) and a
`mask` (which bits are unknown). Bit i unknown ⟹ mask[i] = 1; otherwise the
concrete bit must equal value[i].

The Rust operators follow Linux's `kernel/bpf/tnum.c`, whose semantics Agni
(CAV'23) checked by SMT against the C source. This file transcribes the Rust
implementations verbatim into `BitVec 64` and proves *membership soundness*:
if x is contained in `a` and y in `b`, then the concrete result is contained
in the abstract result. Proofs discharge by `bv_decide` (bit-blasting to a
verified SAT certificate), the same trust story as Agni's SMT queries but
with a machine-checked LRAT proof term.

Issue: #91.
-/
import Std.Tactic.BVDecide

namespace AxiomFormal

structure Tnum where
  value : BitVec 64
  mask  : BitVec 64
deriving Repr, DecidableEq

namespace Tnum

/-- Invariant maintained by every constructor in the Rust implementation:
no bit is simultaneously "known" (in `value`) and "unknown" (in `mask`). -/
def WellFormed (t : Tnum) : Prop :=
  t.value &&& t.mask = 0

/-- Concretization: `x` is a possible concrete value of `t` iff every known
bit of `t` agrees with `x`. Mirrors `TnumValue::contains` in `state.rs`
(`(self.value & !self.mask) == (n & !self.mask)`), which does not presuppose
well-formedness — neither do we. -/
def Mem (x : BitVec 64) (t : Tnum) : Prop :=
  x &&& ~~~t.mask = t.value &&& ~~~t.mask

/-- Fully known constant. `TnumValue::const_val`. -/
def const (n : BitVec 64) : Tnum := ⟨n, 0⟩

/-- Fully unknown. `TnumValue::unknown`. -/
def unknown : Tnum := ⟨0, BitVec.allOnes 64⟩

/-- `TnumValue::add` (= Linux `tnum_add`): propagate carries through known
bits; widen the mask wherever a carry chain crosses an unknown bit. -/
def add (a b : Tnum) : Tnum :=
  let sm := a.mask + b.mask
  let sv := a.value + b.value
  let sigma := sm + sv
  let chi := sigma ^^^ sv
  let mu := chi ||| a.mask ||| b.mask
  ⟨sv &&& ~~~mu, mu⟩

/-- `TnumValue::sub` (= Linux `tnum_sub`). -/
def sub (a b : Tnum) : Tnum :=
  let dv := a.value - b.value
  let alpha := dv + a.mask
  let beta := dv - b.mask
  let chi := alpha ^^^ beta
  let mu := chi ||| a.mask ||| b.mask
  ⟨dv &&& ~~~mu, mu⟩

/-- `TnumValue::and` (= Linux `tnum_and`): known-1 iff both know 1, known-0
iff either knows 0. -/
def and (a b : Tnum) : Tnum :=
  let alpha := a.value ||| a.mask
  let beta := b.value ||| b.mask
  let v := a.value &&& b.value
  ⟨v, alpha &&& beta &&& ~~~v⟩

/-! ## Soundness

Every soundness statement assumes well-formed inputs. This is not a
convenience: `bv_decide` produces concrete counterexamples to `add`/`sub`
soundness when a bit is simultaneously known-1 and unknown, so the
`WellFormed` invariant is load-bearing. The Rust implementation never
constructs a malformed tnum, and the `*_wellFormed` preservation lemmas
below discharge that obligation for each operator, so the hypotheses compose
across whole abstract executions. -/

/-- Constants concretize to themselves. -/
theorem mem_const (n : BitVec 64) : Mem n (const n) := by
  simp [Mem, const]

/-- Everything is a member of `unknown` (it is the top element). -/
theorem mem_unknown (x : BitVec 64) : Mem x unknown := by
  simp [Mem, unknown]

/-- **Soundness of `add`**: for well-formed inputs, the abstract sum
contains every concrete sum. -/
theorem add_sound {a b : Tnum} {x y : BitVec 64}
    (ha : WellFormed a) (hb : WellFormed b)
    (hx : Mem x a) (hy : Mem y b) : Mem (x + y) (add a b) := by
  obtain ⟨av, am⟩ := a
  obtain ⟨bv, bm⟩ := b
  simp only [Mem, WellFormed, add] at *
  bv_decide

/-- `add` preserves the well-formedness invariant (by construction: the
value is masked with the complement of the mask). -/
theorem add_wellFormed (a b : Tnum) : WellFormed (add a b) := by
  obtain ⟨av, am⟩ := a
  obtain ⟨bv, bm⟩ := b
  simp only [WellFormed, add]
  bv_decide

/-- **Soundness of `sub`**: for well-formed inputs, the abstract difference
contains every concrete difference. -/
theorem sub_sound {a b : Tnum} {x y : BitVec 64}
    (ha : WellFormed a) (hb : WellFormed b)
    (hx : Mem x a) (hy : Mem y b) : Mem (x - y) (sub a b) := by
  obtain ⟨av, am⟩ := a
  obtain ⟨bv, bm⟩ := b
  simp only [Mem, WellFormed, sub] at *
  bv_decide

/-- `sub` preserves well-formedness. -/
theorem sub_wellFormed (a b : Tnum) : WellFormed (sub a b) := by
  obtain ⟨av, am⟩ := a
  obtain ⟨bv, bm⟩ := b
  simp only [WellFormed, sub]
  bv_decide

/-- **Soundness of `and`**: for well-formed inputs, the abstract AND
contains every concrete AND. -/
theorem and_sound {a b : Tnum} {x y : BitVec 64}
    (ha : WellFormed a) (hb : WellFormed b)
    (hx : Mem x a) (hy : Mem y b) : Mem (x &&& y) (and a b) := by
  obtain ⟨av, am⟩ := a
  obtain ⟨bv, bm⟩ := b
  simp only [Mem, WellFormed, and] at *
  bv_decide

/-- `and` preserves well-formedness. -/
theorem and_wellFormed (a b : Tnum) : WellFormed (and a b) := by
  obtain ⟨av, am⟩ := a
  obtain ⟨bv, bm⟩ := b
  simp only [WellFormed, and]
  bv_decide

end Tnum
end AxiomFormal
