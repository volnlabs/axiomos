//! State pruning for the path-sensitive verifier.
//!
//! The full path-sensitive verifier explores program states forward
//! through the CFG, re-exploring a basic block once per distinct entry
//! state. Without pruning, a program with N conditional branches has up
//! to 2^N reachable state shapes and verification time blows up
//! exponentially. State pruning collapses redundant exploration: if
//! we've already explored a state at this pc that is at least as
//! general as the one we're about to explore, skip it.
//!
//! This module provides the bookkeeping (`StatePruner`) and the
//! subsumption check (`StateSubsumes`) that decides whether one state
//! covers another. The verifier core consumes this through
//! `pruner.check_or_record(pc, &state)`. The decision is:
//!
//!   * `Prune` — a previously-explored state at this pc subsumes the
//!     current one; do not re-explore.
//!   * `Continue` — no prior state subsumes; record the current state
//!     and keep exploring.
//!
//! Reference: Linux `kernel/bpf/verifier.c` `is_state_visited` /
//! `regsafe`. The shape and semantics mirror that work; the
//! implementation is Rust-native and integrates with our existing
//! `RegState` / `VerifierState` types from `verifier::state`.
//!
//! ## Wiring status
//!
//! The pruner is implemented and tested but not yet consumed by
//! `core::Verifier::verify_safety`. The integration is intentionally a
//! separate change so we can validate the pruner in isolation first.
//! Tracked in #83.

use alloc::vec::Vec;

use super::liveness::RegSet;
use super::state::{RegState, RegType, VerifierState};
use crate::bytecode::registers::Register;

/// Result of consulting the pruner before re-exploring a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneDecision {
    /// No previously-recorded state at this pc subsumes the current
    /// one. The pruner has recorded the current state; the caller
    /// should continue exploration.
    Continue,

    /// A previously-explored state subsumes the current one. The
    /// caller should skip this branch.
    Prune,
}

/// Trait for "state `self` is at least as general as state `other`."
///
/// Lifted out of [`RegState`] / [`VerifierState`] so the verifier
/// core and tests can both consult it without going through the
/// pruner machinery. Implementations must be sound — if `a.subsumes(b)`
/// returns true then every concrete value that satisfies `b` must also
/// satisfy `a`. False negatives are permitted (lose precision); false
/// positives are not (unsoundly prune real bugs).
pub trait StateSubsumes<Rhs = Self> {
    fn subsumes(&self, other: &Rhs) -> bool;
}

impl StateSubsumes for RegState {
    fn subsumes(&self, other: &Self) -> bool {
        // Different types are not comparable. `NotInit` is special — if we
        // previously had it uninit, anything more specific is "more
        // initialised" and we should NOT prune (we'd be claiming a state
        // that observes a value is covered by a state that doesn't, which
        // is unsound).
        if self.reg_type != other.reg_type {
            return false;
        }

        match self.reg_type {
            RegType::NotInit => true,

            RegType::Scalar => {
                let lhs = self.scalar_value.as_ref();
                let rhs = other.scalar_value.as_ref();
                match (lhs, rhs) {
                    (None, _) => true, // We had "unknown scalar"; anything fits.
                    (Some(_), None) => false,
                    (Some(a), Some(b)) => {
                        // Interval check: our range must cover theirs.
                        let interval_ok = a.min <= b.min && a.max >= b.max;
                        // tnum check: our tnum must subsume theirs.
                        let tnum_ok = a.tnum.subsumes(&b.tnum);
                        interval_ok && tnum_ok
                    }
                }
            }

            // Pointer types: same type plus same offset is required for
            // subsumption. We also require the nullness flag and tracked
            // region size to match — pruning a non-null state against a
            // maybe-null one (or across different region sizes) could skip a
            // dereference check, so keep them equal. A real implementation
            // would track range on pointer arithmetic and allow our range to
            // cover theirs; for now this is sound but conservative.
            _ => {
                self.ptr_offset == other.ptr_offset
                    && self.map_id == other.map_id
                    && self.maybe_null == other.maybe_null
                    && self.mem_range == other.mem_range
            }
        }
    }
}

impl StateSubsumes for VerifierState {
    fn subsumes(&self, other: &Self) -> bool {
        // Default subsumption considers every register live. Use
        // `subsumes_with_liveness` to ignore dead-register differences.
        self.subsumes_with_liveness(other, RegSet::ALL)
    }
}

impl VerifierState {
    /// Subsumption check that ignores registers not in `live`.
    ///
    /// Two verifier states that disagree only on dead registers are
    /// equivalent for pruning purposes — those dead values can never
    /// affect future execution by definition, so claiming subsumption on
    /// only-live-register agreement is sound.
    ///
    /// Pass `RegSet::ALL` to ignore liveness (equivalent to the original
    /// [`StateSubsumes`] impl).
    pub fn subsumes_with_liveness(&self, other: &Self, live: RegSet) -> bool {
        // Every live register's state in `self` must subsume the
        // corresponding register in `other`. Dead registers are skipped
        // outright.
        for r in 0..Register::COUNT {
            let reg = match Register::from_raw(r as u8) {
                Some(reg) => reg,
                None => continue,
            };
            if !live.contains(reg) {
                continue;
            }
            if !self.regs[r].subsumes(&other.regs[r]) {
                return false;
            }
        }
        // Stack subsumption: still equality. Stack contents are not
        // covered by register liveness — a dead register doesn't mean
        // dead stack slots. Conservative stack-range refinement is
        // tracked as a follow-up on #83.
        if self.stack.max_depth() != other.stack.max_depth() {
            return false;
        }
        for offset in -(self.stack.max_depth() as i64)..0 {
            if self.stack.get(offset) != other.stack.get(offset) {
                return false;
            }
        }
        true
    }
}

/// Records explored states keyed by program counter so we can avoid
/// re-exploring redundant ones. Memory consumption is bounded by
/// `(distinct states) × (RegState cost)`; on a real program the verifier
/// is expected to converge to a small set of state shapes per pc.
///
/// For now this is keyed only by pc — multiple states at the same pc
/// are kept in a small per-pc list and the pruner walks them. Linux's
/// verifier uses a more elaborate hash + bucket structure; we'll move
/// to that if profile data shows the linear walk dominating.
#[derive(Debug, Default)]
pub struct StatePruner {
    /// For each pc, the set of states we've already explored.
    by_pc: alloc::collections::BTreeMap<usize, Vec<VerifierState>>,
    /// Running total of recorded states (kept incrementally so the budget
    /// check is O(1) rather than summing `by_pc` every instruction).
    count: usize,
    /// Maximum number of states to record before the verifier gives up and
    /// rejects the program. Bounds the verifier's memory: each recorded
    /// `VerifierState` carries a full stack image (up to the profile stack
    /// size), so without a cap a loop whose states never subsume can allocate
    /// gigabytes and OOM. See [`Self::DEFAULT_MAX_STATES`].
    max_states: usize,
}

impl StatePruner {
    /// Default recorded-state budget. Sized so the worst case stays well under
    /// typical CI / runtime memory: a cloud-profile state is ~1 MiB (a
    /// 512 KiB-slot stack image), so 1024 states ≈ 1 GiB. The bounded
    /// (loop-free) embedded fragment never approaches this; it matters only
    /// for loop-bearing cloud programs. The forthcoming worklist verifier will
    /// shrink per-state cost (shared/CoW stacks) and can then raise this.
    pub const DEFAULT_MAX_STATES: usize = 1024;

    pub fn new() -> Self {
        Self {
            by_pc: alloc::collections::BTreeMap::new(),
            count: 0,
            max_states: Self::DEFAULT_MAX_STATES,
        }
    }

    /// True once the recorded-state budget is reached; the verifier should
    /// then reject the program rather than record more states.
    pub fn at_capacity(&self) -> bool {
        self.count >= self.max_states
    }

    /// The configured recorded-state budget.
    pub fn max_states(&self) -> usize {
        self.max_states
    }

    /// Override the budget. Test-only so a unit test can hit the cap without
    /// allocating a gigabyte of states.
    #[cfg(test)]
    pub fn set_max_states(&mut self, max: usize) {
        self.max_states = max;
    }

    /// Consult the pruner with the current `state` at program counter
    /// `pc`. If any previously-recorded state at this pc subsumes the
    /// current one, return [`PruneDecision::Prune`]. Otherwise record
    /// the current state and return [`PruneDecision::Continue`].
    pub fn check_or_record(&mut self, pc: usize, state: &VerifierState) -> PruneDecision {
        self.check_or_record_with_liveness(pc, state, RegSet::ALL)
    }

    /// Liveness-aware variant of [`check_or_record`].
    ///
    /// Subsumption ignores registers not in `live`. Two states that
    /// disagree only on dead registers are equivalent for pruning, which
    /// is the central reason wiring liveness into the pruner improves
    /// pruning rate on real programs.
    pub fn check_or_record_with_liveness(
        &mut self,
        pc: usize,
        state: &VerifierState,
        live: RegSet,
    ) -> PruneDecision {
        let entries = self.by_pc.entry(pc).or_default();
        for prior in entries.iter() {
            if prior.subsumes_with_liveness(state, live) {
                return PruneDecision::Prune;
            }
        }
        entries.push(state.clone());
        self.count += 1;
        PruneDecision::Continue
    }

    /// Drop all recorded state. Useful between independent program
    /// verifications when the pruner is held in a long-lived context.
    pub fn clear(&mut self) {
        self.by_pc.clear();
        self.count = 0;
    }

    /// Total number of recorded states across all pcs. Diagnostic only.
    pub fn recorded(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::registers::Register;
    use crate::verifier::state::{ScalarValue, TnumValue};

    fn entry_state() -> VerifierState {
        VerifierState::new_entry(512)
    }

    #[test]
    fn empty_pruner_records_first_state() {
        let mut pruner = StatePruner::new();
        let s = entry_state();
        assert_eq!(pruner.check_or_record(0, &s), PruneDecision::Continue);
        assert_eq!(pruner.recorded(), 1);
    }

    #[test]
    fn identical_state_is_pruned() {
        let mut pruner = StatePruner::new();
        let s = entry_state();
        pruner.check_or_record(0, &s);
        assert_eq!(pruner.check_or_record(0, &s), PruneDecision::Prune);
    }

    #[test]
    fn different_pc_is_not_pruned() {
        let mut pruner = StatePruner::new();
        let s = entry_state();
        pruner.check_or_record(0, &s);
        // Same state at a different pc — explore separately.
        assert_eq!(pruner.check_or_record(1, &s), PruneDecision::Continue);
    }

    #[test]
    fn unknown_scalar_subsumes_constant_at_same_pc() {
        let mut pruner = StatePruner::new();

        // First exploration arrives with r0 = unknown scalar
        let mut s_general = entry_state();
        s_general.regs[Register::R0 as usize] = RegState::scalar(Some(ScalarValue::unknown()));
        pruner.check_or_record(0, &s_general);

        // Second exploration arrives at the same pc with r0 = constant 7.
        // The previously-seen unknown state is more general; prune.
        let mut s_specific = entry_state();
        s_specific.regs[Register::R0 as usize] = RegState::scalar(Some(ScalarValue::constant(7)));
        assert_eq!(pruner.check_or_record(0, &s_specific), PruneDecision::Prune);
    }

    #[test]
    fn constant_does_not_subsume_unknown() {
        let mut pruner = StatePruner::new();

        let mut s_specific = entry_state();
        s_specific.regs[Register::R0 as usize] = RegState::scalar(Some(ScalarValue::constant(7)));
        pruner.check_or_record(0, &s_specific);

        let mut s_general = entry_state();
        s_general.regs[Register::R0 as usize] = RegState::scalar(Some(ScalarValue::unknown()));
        assert_eq!(
            pruner.check_or_record(0, &s_general),
            PruneDecision::Continue
        );
    }

    #[test]
    fn different_reg_types_do_not_subsume() {
        let r_scalar = RegState::scalar(Some(ScalarValue::unknown()));
        let r_stack = RegState::stack_ptr(-8);
        assert!(!r_scalar.subsumes(&r_stack));
        assert!(!r_stack.subsumes(&r_scalar));
    }

    #[test]
    fn tnum_subsumption_lifts_to_regstate() {
        // r0_a: low 8 bits unknown, rest known zero, range [0, 255]
        let mut sv_a = ScalarValue::unknown();
        sv_a.min = 0;
        sv_a.max = 255;
        sv_a.tnum = TnumValue {
            value: 0,
            mask: 0xff,
        };

        // r0_b: known constant 42, which fits in r0_a's tnum + interval
        let sv_b = ScalarValue::constant(42);

        let a = RegState::scalar(Some(sv_a));
        let b = RegState::scalar(Some(sv_b));

        assert!(
            a.subsumes(&b),
            "wider tnum + interval should subsume a contained constant"
        );
        assert!(!b.subsumes(&a), "constant cannot subsume wider tnum");
    }

    #[test]
    fn recorded_count_grows_only_on_continue() {
        let mut pruner = StatePruner::new();
        let s = entry_state();

        pruner.check_or_record(0, &s); // Continue
        pruner.check_or_record(0, &s); // Prune
        pruner.check_or_record(1, &s); // Continue (different pc)
        pruner.check_or_record(1, &s); // Prune

        assert_eq!(pruner.recorded(), 2);
    }

    #[test]
    fn pruner_enforces_state_budget() {
        let mut pruner = StatePruner::new();
        pruner.set_max_states(2);
        assert!(!pruner.at_capacity());

        let s = entry_state();
        pruner.check_or_record(0, &s); // count 1
        assert!(!pruner.at_capacity());
        pruner.check_or_record(1, &s); // count 2 → at budget
        assert!(pruner.at_capacity());
        assert_eq!(pruner.recorded(), 2);

        // clear() resets the budget tracking.
        pruner.clear();
        assert!(!pruner.at_capacity());
        assert_eq!(pruner.recorded(), 0);
    }
}
