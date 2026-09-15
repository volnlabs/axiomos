//! Fallible verifier buffer accounting. Counts element storage, including old
//! and replacement buffers during growth, not allocator metadata/fragmentation.
//! `try_reserve_exact` uses the requested layout with Rust's global allocator;
//! allocator rounding and linked-list heap bookkeeping need separate headroom.
use alloc::vec::Vec;
use core::cell::Cell;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

use super::error::{VerifyError, VerifyResult};

/// Caller-owned storage allowance shared by a single verification operation.
/// Scratch refunds automatically. Successful output buffers remain charged:
/// after dropping or transferring those artifacts, release their charge using
/// [`Self::release_output`]. Inputs and allocator overhead are not included.
#[derive(Debug)]
pub struct VerificationBudget {
    limit: usize,
    used: Cell<usize>,
    peak: Cell<usize>,
    #[cfg(test)]
    attempts: Cell<usize>,
    #[cfg(test)]
    fail_at: Cell<Option<usize>>,
}
impl VerificationBudget {
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            used: Cell::new(0),
            peak: Cell::new(0),
            #[cfg(test)]
            attempts: Cell::new(0),
            #[cfg(test)]
            fail_at: Cell::new(None),
        }
    }
    pub fn used(&self) -> usize {
        self.used.get()
    }
    pub fn high_water(&self) -> usize {
        self.peak.get()
    }
    pub fn limit(&self) -> usize {
        self.limit
    }
    /// Release output storage after its ownership leaves this allowance.
    /// Requires exclusive access so scratch buffers cannot be refunded early.
    pub fn release_output(&mut self, bytes: usize) -> VerifyResult<()> {
        let used = self
            .used
            .get()
            .checked_sub(bytes)
            .ok_or(VerifyError::ResourceExhausted)?;
        self.used.set(used);
        Ok(())
    }
    fn charge(&self, bytes: usize) -> VerifyResult<()> {
        let used = self
            .used
            .get()
            .checked_add(bytes)
            .filter(|&n| n <= self.limit)
            .ok_or(VerifyError::ResourceExhausted)?;
        self.used.set(used);
        self.peak.set(self.peak.get().max(used));
        Ok(())
    }
    pub(super) fn refund(&self, bytes: usize) {
        self.used.set(self.used.get() - bytes);
    }
}

/// No allocating operations are exposed through Deref (only a slice).
#[derive(Debug)]
pub(super) struct BudgetVec<'a, T> {
    data: Vec<T>,
    budget: Option<&'a VerificationBudget>,
}
impl<'a, T> BudgetVec<'a, T> {
    pub fn new(budget: Option<&'a VerificationBudget>) -> Self {
        Self {
            data: Vec::new(),
            budget,
        }
    }
    pub fn budget(&self) -> Option<&'a VerificationBudget> {
        self.budget
    }
    pub fn reserve(&mut self, capacity: usize) -> VerifyResult<()> {
        if capacity <= self.data.capacity() {
            return Ok(());
        }
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or(VerifyError::ResourceExhausted)?;
        if let Some(b) = self.budget {
            b.charge(bytes)?;
        }
        let mut replacement = Vec::new();
        // Inject after charging, through the same refund branch as allocator
        // failure; this tests cleanup of admitted but failed reservations.
        #[cfg(test)]
        let injected = self.budget.is_some_and(|b| {
            let attempt = b.attempts.get();
            b.attempts.set(attempt + 1);
            b.fail_at.get() == Some(attempt)
        });
        #[cfg(not(test))]
        let injected = false;
        if injected || replacement.try_reserve_exact(capacity).is_err() {
            if let Some(b) = self.budget {
                b.refund(bytes);
            }
            return Err(VerifyError::ResourceExhausted);
        }
        // Global Vec allocates the requested element layout. Do not silently
        // accept a different capacity if that implementation ever changes.
        if size_of::<T>() != 0 && replacement.capacity() != capacity {
            drop(replacement);
            if let Some(b) = self.budget {
                b.refund(bytes);
            }
            return Err(VerifyError::ResourceExhausted);
        }
        replacement.append(&mut self.data); // reserved above; moves, never clones
        let old = core::mem::replace(&mut self.data, replacement);
        let old_bytes = old.capacity().saturating_mul(size_of::<T>());
        drop(old);
        if let Some(b) = self.budget {
            b.refund(old_bytes);
        }
        Ok(())
    }
    pub fn push(&mut self, value: T) -> VerifyResult<()> {
        if self.data.len() == self.data.capacity() {
            let capacity = self
                .data
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or(VerifyError::ResourceExhausted)?;
            self.reserve(capacity)?;
        }
        self.data.push(value);
        Ok(())
    }
    pub fn insert(&mut self, index: usize, value: T) -> VerifyResult<()> {
        self.reserve(
            self.data
                .len()
                .checked_add(1)
                .ok_or(VerifyError::ResourceExhausted)?,
        )?;
        self.data.insert(index, value);
        Ok(())
    }
    pub fn pop(&mut self) -> Option<T> {
        self.data.pop()
    }
    pub fn remove(&mut self, index: usize) -> T {
        self.data.remove(index)
    }
    pub fn clear(&mut self) {
        self.data.clear();
    }
    pub fn dedup(&mut self)
    where
        T: PartialEq,
    {
        self.data.dedup();
    }
    pub fn into_output(mut self) -> Vec<T> {
        self.budget = None;
        core::mem::take(&mut self.data)
    }
    pub fn filled(
        budget: Option<&'a VerificationBudget>,
        len: usize,
        value: T,
    ) -> VerifyResult<Self>
    where
        T: Copy,
    {
        let mut result = Self::new(budget);
        result.reserve(len)?;
        result.data.resize(len, value);
        Ok(result)
    }
    pub fn copy_from(budget: Option<&'a VerificationBudget>, source: &[T]) -> VerifyResult<Self>
    where
        T: Copy,
    {
        let mut result = Self::new(budget);
        result.reserve(source.len())?;
        result.data.extend_from_slice(source);
        Ok(result)
    }
}
impl<T: Clone> Clone for BudgetVec<'_, T> {
    /// Legacy convenience only; bounded verification uses explicit try_clone.
    fn clone(&self) -> Self {
        let mut result = Self::new(self.budget);
        result
            .reserve(self.len())
            .expect("legacy verifier allocation");
        for item in self.iter() {
            result.data.push(item.clone());
        }
        result
    }
}
impl<T> Default for BudgetVec<'_, T> {
    fn default() -> Self {
        Self::new(None)
    }
}
impl<T> Deref for BudgetVec<'_, T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.data
    }
}
impl<T> DerefMut for BudgetVec<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.data
    }
}
impl<T> Drop for BudgetVec<'_, T> {
    fn drop(&mut self) {
        let bytes = self.data.capacity().saturating_mul(size_of::<T>());
        let data = core::mem::take(&mut self.data);
        drop(data);
        if let Some(b) = self.budget {
            b.refund(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bytecode::{BpfInsn, BpfProgType};
    use crate::profile::ActiveProfile;
    use crate::verifier::{HelperId, Verifier, VerifyConfig};

    fn program() -> [BpfInsn; 18] {
        [
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0), // stack exists before branch clone
            BpfInsn::call(HelperId::GetPrandomU32 as i32),
            BpfInsn::jeq_imm(0, 0, 7),
            BpfInsn::mov64_imm(1, 7),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapDeleteElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(1, 11),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapDeleteElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }

    #[test]
    fn bounded_all_reservations_fail_cleanly_including_final_code() {
        let insns = program();
        let mut budget = VerificationBudget::new(2 * 1024 * 1024);
        let (code, stats) = Verifier::<ActiveProfile>::verify_with_stats_bounded(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig::default(),
            &budget,
        )
        .unwrap();
        assert_eq!(code.instructions(), insns);
        assert_eq!(code.stack_size(), 8);
        assert_eq!(stats.referenced_map_handles, [7, 11]);
        let outputs = insns.len() * size_of::<BpfInsn>()
            + stats.referenced_map_handles.capacity() * size_of::<u32>();
        assert_eq!(budget.used(), outputs);
        let attempts = budget.attempts.get();
        let peak = budget.high_water();
        std::eprintln!(
            "bounded representative: reservations={attempts}, high_water={peak}, output_bytes={outputs}"
        );
        assert!(attempts > 30);
        drop((code, stats));
        budget.release_output(outputs).unwrap();
        assert_eq!(budget.used(), 0);
        for fail in 0..attempts {
            let budget = VerificationBudget::new(2 * 1024 * 1024);
            budget.fail_at.set(Some(fail));
            let result = Verifier::<ActiveProfile>::verify_with_stats_bounded(
                BpfProgType::SocketFilter,
                &insns,
                VerifyConfig::default(),
                &budget,
            );
            assert!(
                matches!(result, Err(VerifyError::ResourceExhausted)),
                "reservation {fail}: {result:?}"
            );
            assert_eq!(budget.used(), 0, "reservation {fail} leaked charges");
            assert!(budget.high_water() <= budget.limit());
        }
        for limit in [0, peak - 1, peak] {
            let budget = VerificationBudget::new(limit);
            let result = Verifier::<ActiveProfile>::verify_with_stats_bounded(
                BpfProgType::SocketFilter,
                &insns,
                VerifyConfig::default(),
                &budget,
            );
            assert_eq!(result.is_ok(), limit == peak);
            if result.is_err() {
                assert_eq!(budget.used(), 0);
            }
            assert!(budget.high_water() <= limit);
        }
    }

    #[test]
    fn bounded_back_edge_reservations_refund() {
        use super::super::cfg::BudgetControlFlowGraph;
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::jeq_imm(0, 0, -1),
            BpfInsn::exit(),
        ];
        let budget = VerificationBudget::new(4096);
        let cfg = BudgetControlFlowGraph::try_build(&insns, Some(&budget)).unwrap();
        assert!(cfg.has_loops());
        let attempts = budget.attempts.get();
        drop(cfg);
        assert_eq!(budget.used(), 0);
        for fail in 0..attempts {
            let budget = VerificationBudget::new(4096);
            budget.fail_at.set(Some(fail));
            assert!(matches!(
                BudgetControlFlowGraph::try_build(&insns, Some(&budget)),
                Err(VerifyError::ResourceExhausted)
            ));
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn bounded_growth_charges_both_buffers_and_overflow_is_rejected() {
        let budget = VerificationBudget::new(5 * size_of::<u64>());
        let mut values = BudgetVec::new(Some(&budget));
        values.push(7u64).unwrap(); // capacity 1
        values.push(9u64).unwrap(); // capacity 3, peak 1 + 3
        assert_eq!(budget.high_water(), 4 * size_of::<u64>());
        assert_eq!(budget.used(), 3 * size_of::<u64>());
        assert_eq!(values.reserve(4), Err(VerifyError::ResourceExhausted));
        assert_eq!(&*values, [7, 9]);
        assert_eq!(
            values.reserve(usize::MAX),
            Err(VerifyError::ResourceExhausted)
        );
        drop(values);
        assert_eq!(budget.used(), 0);
        let budget = VerificationBudget::new(usize::MAX);
        budget.charge(usize::MAX).unwrap();
        assert_eq!(budget.charge(1), Err(VerifyError::ResourceExhausted));
        budget.refund(usize::MAX);
    }

    #[test]
    fn bounded_stack_copy_failure_and_pruner_eviction_refund() {
        use super::super::pruner::BudgetStatePruner as StatePruner;
        use super::super::state::BudgetVerifierState as VerifierState;
        use crate::verifier::{RegSet, StackSlot};
        let budget = VerificationBudget::new(128 * 1024);
        {
            let mut state = VerifierState::new_entry(512).with_budget(Some(&budget));
            assert!(state.stack.try_set(-8, StackSlot::Zero).unwrap());
            let used = budget.used();
            budget.fail_at.set(Some(budget.attempts.get()));
            assert!(matches!(
                state.try_clone(),
                Err(VerifyError::ResourceExhausted)
            ));
            assert_eq!(budget.used(), used);
            budget.fail_at.set(None);
            let mut pruner = StatePruner::new().with_budget(Some(&budget));
            pruner.set_max_states_per_pc(1);
            pruner.try_check_or_record(0, &state, RegSet::ALL).unwrap();
            let retained = budget.used();
            state.stack.try_set(-8, StackSlot::Scalar).unwrap();
            pruner.try_check_or_record(0, &state, RegSet::ALL).unwrap();
            assert_eq!(pruner.recorded(), 2);
            assert_eq!(pruner.per_pc_len(0), 1);
            assert_eq!(budget.used(), retained);
            assert!(state.stack.try_set(-8, StackSlot::Invalid).unwrap());
            assert_eq!(state.stack.get(-8), Some(StackSlot::Invalid));
            assert_eq!(state.stack.max_depth(), 8);
        }
        assert_eq!(budget.used(), 0);
    }
}
