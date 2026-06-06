//! Per-instruction liveness analysis for the verifier.
//!
//! Liveness tells the verifier which registers are read at or after a
//! given program point. The downstream consumer is the state pruner in
//! [`super::pruner`]: two verifier states that disagree only on dead
//! registers are equivalent for pruning purposes, because those dead
//! values can never affect future execution.
//!
//! Without liveness the pruner has to assume every register is live
//! everywhere; subsumption then over-constrains and pruning fires far
//! less often than it should. With liveness, pruning quality scales with
//! analysis precision.
//!
//! ## Algorithm
//!
//! Standard backwards dataflow over instructions:
//!
//!   live_out[i]  =  union over successors s of live_in[s]
//!   live_in[i]   =  use[i]  ∪  (live_out[i] \ def[i])
//!
//! Iterate until no live-set changes. The fixpoint exists because
//! live-sets are bounded (11 BPF registers, monotone-growing per round).
//!
//! ## Definition tables
//!
//! For each instruction kind we record which registers it reads (`use`)
//! and which it writes (`def`):
//!
//!   ALU dst, src       → use = {src} (if reg-source), def = {dst}
//!   LDX dst, [src+off] → use = {src},                  def = {dst}
//!   STX [dst+off], src → use = {dst, src},             def = {}
//!   JMP cond src, dst  → use = {dst, src},             def = {}
//!   CALL helper        → use = {R1..R5},               def = {R0, R1..R5}
//!   EXIT               → use = {R0},                   def = {}
//!
//! The exact reg-vs-imm and class details come from `BpfInsn` helpers.
//!
//! ## Wiring status
//!
//! Analysis is implemented and tested but not yet consumed by the
//! pruner ([`super::pruner::StatePruner`]). Integration is a separate
//! change tracked under #86 so we can land the analysis in isolation
//! and measure the pruning-rate improvement on a representative
//! benchmark.

use alloc::vec;
use alloc::vec::Vec;

use super::cfg::ControlFlowGraph;
use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::OpcodeClass;
use crate::bytecode::registers::Register;

/// Bit-set over the 11 BPF registers (R0..R10).
///
/// Using a `u16` keeps the per-pc analysis state at a single machine
/// word, which is also what makes the pruner's subsumption-on-live-only
/// check (#83 follow-up) cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegSet(u16);

impl RegSet {
    pub const EMPTY: Self = Self(0);

    /// All 11 registers (R0..R10).
    pub const ALL: Self = Self((1 << Register::COUNT) - 1);

    #[inline]
    pub const fn from_reg(reg: Register) -> Self {
        Self(1 << (reg as u16))
    }

    #[inline]
    pub fn insert(&mut self, reg: Register) {
        self.0 |= 1 << (reg as u16);
    }

    #[inline]
    pub fn remove(&mut self, reg: Register) {
        self.0 &= !(1 << (reg as u16));
    }

    #[inline]
    pub const fn contains(self, reg: Register) -> bool {
        self.0 & (1 << (reg as u16)) != 0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Iterate over the registers in this set, lowest first.
    pub fn iter(self) -> impl Iterator<Item = Register> {
        (0..Register::COUNT).filter_map(move |i| {
            if self.0 & (1 << i) != 0 {
                Register::from_raw(i as u8)
            } else {
                None
            }
        })
    }
}

impl core::fmt::Display for RegSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{{")?;
        let mut first = true;
        for r in self.iter() {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{r:?}")?;
        }
        write!(f, "}}")
    }
}

/// Per-instruction use and def sets.
#[derive(Debug, Clone, Copy, Default)]
struct UseDef {
    uses: RegSet,
    defs: RegSet,
}

/// Compute use/def for a single instruction.
fn use_def(insn: &BpfInsn) -> UseDef {
    let mut ud = UseDef::default();

    if insn.is_exit() {
        // EXIT reads R0 (the return value), defines nothing.
        ud.uses.insert(Register::R0);
        return ud;
    }

    if insn.is_call() {
        // Helper calls read R1..R5 as args; define R0 (return) and may
        // clobber R1..R5 by convention. Treating R1..R5 as defs is the
        // conservative thing for liveness — they're effectively killed.
        for &r in &[
            Register::R1,
            Register::R2,
            Register::R3,
            Register::R4,
            Register::R5,
        ] {
            ud.uses.insert(r);
            ud.defs.insert(r);
        }
        ud.defs.insert(Register::R0);
        return ud;
    }

    let dst = insn.dst();
    let src = insn.src();

    match insn.class() {
        Some(OpcodeClass::Alu32 | OpcodeClass::Alu64) => {
            if let Some(dst) = dst {
                ud.defs.insert(dst);
                // Reg-reg ALU also reads dst (e.g. `dst += src` reads dst).
                ud.uses.insert(dst);
            }
            if let (crate::bytecode::opcode::SourceType::Reg, Some(src)) = (insn.source_type(), src)
            {
                ud.uses.insert(src);
            }
        }
        Some(OpcodeClass::Jmp | OpcodeClass::Jmp32) => {
            // Conditional/unconditional jump compares dst to either src
            // or imm. Reads dst (and src when reg-source); defines
            // nothing.
            if let Some(dst) = dst {
                ud.uses.insert(dst);
            }
            if let (crate::bytecode::opcode::SourceType::Reg, Some(src)) = (insn.source_type(), src)
            {
                ud.uses.insert(src);
            }
        }
        Some(OpcodeClass::Ld) => {
            // LD_IMM (and wide load): defines dst, uses nothing.
            if let Some(dst) = dst {
                ud.defs.insert(dst);
            }
        }
        Some(OpcodeClass::Ldx) => {
            // LDX dst, [src+off]: reads src, defines dst.
            if let Some(dst) = dst {
                ud.defs.insert(dst);
            }
            if let Some(src) = src {
                ud.uses.insert(src);
            }
        }
        Some(OpcodeClass::St) => {
            // ST [dst+off], imm: reads dst, defines nothing.
            if let Some(dst) = dst {
                ud.uses.insert(dst);
            }
        }
        Some(OpcodeClass::Stx) => {
            // STX [dst+off], src: reads dst and src, defines nothing.
            if let Some(dst) = dst {
                ud.uses.insert(dst);
            }
            if let Some(src) = src {
                ud.uses.insert(src);
            }
        }
        None => {
            // Unknown opcode. Conservative: assume it could read or write
            // anything. Liveness must over-approximate, so mark every reg
            // as used.
            ud.uses = RegSet::ALL;
        }
    }

    ud
}

/// Live-in / live-out sets per instruction.
#[derive(Debug, Clone)]
pub struct Liveness {
    /// Live registers at the entry of instruction i.
    live_in: Vec<RegSet>,
    /// Live registers at the exit of instruction i (i.e. live-in of
    /// successors).
    live_out: Vec<RegSet>,
}

impl Liveness {
    /// Run liveness analysis over `insns` using the CFG `cfg`. Returns
    /// a `Liveness` keyed by instruction index.
    pub fn analyze(insns: &[BpfInsn], cfg: &ControlFlowGraph) -> Self {
        let n = insns.len();
        let mut live_in = vec![RegSet::EMPTY; n];
        let mut live_out = vec![RegSet::EMPTY; n];

        if n == 0 {
            return Self { live_in, live_out };
        }

        // Pre-compute use/def for every instruction. Skips repeated work
        // in the fixpoint loop.
        let ud: Vec<UseDef> = insns.iter().map(use_def).collect();

        // Backwards fixpoint. Bounded: each live-set is monotone over
        // RegSet (only grows), and RegSet has at most 11 elements.
        let mut changed = true;
        while changed {
            changed = false;
            for i in (0..n).rev() {
                // live_out[i] = ⋃ live_in[succ]
                let mut new_out = RegSet::EMPTY;
                for succ in cfg.successors(i) {
                    new_out = new_out.union(live_in[succ]);
                }
                // Exit instructions have no CFG successors but still
                // "use" R0 implicitly (via use_def). The set of users
                // is captured in live_in[i] via ud[i].uses, so the
                // exit case is handled below without a special arm.

                // live_in[i] = use[i] ∪ (live_out[i] \ def[i])
                let new_in = ud[i].uses.union(new_out.difference(ud[i].defs));

                if new_out != live_out[i] {
                    live_out[i] = new_out;
                    changed = true;
                }
                if new_in != live_in[i] {
                    live_in[i] = new_in;
                    changed = true;
                }
            }
        }

        Self { live_in, live_out }
    }

    /// Registers live at the entry of instruction `pc`.
    #[inline]
    pub fn live_in(&self, pc: usize) -> RegSet {
        self.live_in.get(pc).copied().unwrap_or(RegSet::EMPTY)
    }

    /// Registers live at the exit of instruction `pc` (i.e. live-in of
    /// the next pc that executes).
    #[inline]
    pub fn live_out(&self, pc: usize) -> RegSet {
        self.live_out.get(pc).copied().unwrap_or(RegSet::EMPTY)
    }

    /// Iterate over `(pc, live_in)` pairs in instruction order.
    pub fn iter(&self) -> impl Iterator<Item = (usize, RegSet)> + '_ {
        self.live_in.iter().copied().enumerate()
    }

    /// Total number of instructions analysed.
    #[inline]
    pub fn len(&self) -> usize {
        self.live_in.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.live_in.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(insns: &[BpfInsn]) -> Liveness {
        let cfg = ControlFlowGraph::build(insns);
        Liveness::analyze(insns, &cfg)
    }

    #[test]
    fn empty_program() {
        let l = run(&[]);
        assert!(l.is_empty());
    }

    #[test]
    fn r0_live_at_exit() {
        // mov64_imm r0, 0
        // exit
        let insns = vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
        let l = run(&insns);
        // exit reads R0.
        assert!(l.live_in(1).contains(Register::R0));
    }

    #[test]
    fn dead_register_after_overwrite() {
        // mov64_imm r1, 100   ; r1 written, never read
        // mov64_imm r0, 0
        // exit                ; uses R0
        let insns = vec![
            BpfInsn::mov64_imm(1, 100),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let l = run(&insns);
        // R1 is dead immediately after the mov; live_out of insn 0 must
        // not include R1.
        assert!(!l.live_out(0).contains(Register::R1));
        // R0 becomes live at insn 1 (its def) and is read at exit.
        assert!(l.live_out(1).contains(Register::R0));
    }

    #[test]
    fn live_through_arithmetic_chain() {
        // r0 = 1
        // r0 += 2
        // r0 += 3
        // exit
        let insns = vec![
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::add64_imm(0, 2),
            BpfInsn::add64_imm(0, 3),
            BpfInsn::exit(),
        ];
        let l = run(&insns);
        // R0 is live at every program point after its first def.
        for pc in 1..=3 {
            assert!(
                l.live_in(pc).contains(Register::R0),
                "R0 should be live at pc={pc}"
            );
        }
    }

    #[test]
    fn regset_basic_ops() {
        let mut s = RegSet::EMPTY;
        assert!(s.is_empty());

        s.insert(Register::R3);
        assert!(s.contains(Register::R3));
        assert!(!s.contains(Register::R4));
        assert_eq!(s.count(), 1);

        let t = RegSet::from_reg(Register::R4);
        let u = s.union(t);
        assert_eq!(u.count(), 2);
        assert!(u.contains(Register::R3));
        assert!(u.contains(Register::R4));

        let d = u.difference(RegSet::from_reg(Register::R3));
        assert!(!d.contains(Register::R3));
        assert!(d.contains(Register::R4));

        let i = u.intersection(t);
        assert!(i.contains(Register::R4));
        assert!(!i.contains(Register::R3));
    }

    #[test]
    fn regset_iter_lowest_first() {
        let mut s = RegSet::EMPTY;
        s.insert(Register::R5);
        s.insert(Register::R0);
        s.insert(Register::R3);
        let regs: Vec<Register> = s.iter().collect();
        assert_eq!(regs, vec![Register::R0, Register::R3, Register::R5]);
    }
}
