//! Per-hook WCET admission ledger (Track C brick 4, #43).
//!
//! Attaching a program to a hook commits the hook to paying that program's
//! worst-case execution cost on every fire. The ledger tracks the summed WCET
//! committed per hook and rejects an attach that would exceed the hook's
//! capacity — load-time *schedulability* admission, not just safety.
//!
//! Capacity is in the cost model's relative cycle units (pending A76
//! calibration, like `WCET_CYCLE_BUDGET`). v1 is a per-hook capacity sum —
//! the utilization form `Σ WCETᵢ·freqᵢ ≤ U` needs calibrated cycle↔time and
//! per-hook fire frequencies, and lands after calibration.

use alloc::collections::BTreeMap;
use core::fmt;

/// An attach was refused because the hook's WCET capacity would be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionError {
    /// The hook (attach type) the program was being attached to.
    pub hook: u32,
    /// WCET cycle units already committed on this hook.
    pub used: u64,
    /// WCET cycle units the rejected program would have added.
    pub requested: u64,
    /// The per-hook capacity.
    pub capacity: u64,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hook {} WCET admission rejected: used {} + requested {} exceeds capacity {}",
            self.hook, self.used, self.requested, self.capacity
        )
    }
}

/// Tracks the summed per-hook WCET committed by attached programs and
/// rejects attaches that would exceed the per-hook capacity.
#[derive(Debug, Clone)]
pub struct AdmissionLedger {
    /// Per-hook capacity, in cost-model cycle units.
    capacity: u64,
    /// hook → committed WCET cycle units.
    used: BTreeMap<u32, u64>,
}

impl AdmissionLedger {
    /// Create a ledger where every hook has `capacity` cycle units.
    pub const fn new(capacity: u64) -> Self {
        Self {
            capacity,
            used: BTreeMap::new(),
        }
    }

    /// Commit `wcet` cycle units on `hook`, or reject without consuming
    /// capacity if it does not fit.
    pub fn admit(&mut self, hook: u32, wcet: u64) -> Result<(), AdmissionError> {
        let used = self.used(hook);
        if used.saturating_add(wcet) > self.capacity {
            return Err(AdmissionError {
                hook,
                used,
                requested: wcet,
                capacity: self.capacity,
            });
        }
        *self.used.entry(hook).or_insert(0) = used + wcet;
        Ok(())
    }

    /// Return `wcet` cycle units to `hook` (detach). Saturates at zero rather
    /// than underflowing if callers over-release.
    pub fn release(&mut self, hook: u32, wcet: u64) {
        if let Some(u) = self.used.get_mut(&hook) {
            *u = u.saturating_sub(wcet);
        }
    }

    /// WCET cycle units currently committed on `hook`.
    pub fn used(&self, hook: u32) -> u64 {
        self.used.get(&hook).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_until_capacity_then_rejects() {
        let mut ledger = AdmissionLedger::new(100);

        ledger.admit(1, 60).expect("first program fits");
        ledger.admit(1, 40).expect("exactly at capacity fits");

        let err = ledger.admit(1, 1).expect_err("over capacity must reject");
        assert_eq!(
            err,
            AdmissionError {
                hook: 1,
                used: 100,
                requested: 1,
                capacity: 100
            }
        );
        // A rejected admit must not consume capacity.
        assert_eq!(ledger.used(1), 100);
    }

    #[test]
    fn hooks_have_independent_budgets() {
        let mut ledger = AdmissionLedger::new(100);
        ledger.admit(1, 100).expect("hook 1 full");
        ledger.admit(2, 100).expect("hook 2 has its own capacity");
        assert_eq!(ledger.used(1), 100);
        assert_eq!(ledger.used(2), 100);
    }

    #[test]
    fn release_frees_capacity() {
        let mut ledger = AdmissionLedger::new(100);
        ledger.admit(1, 80).unwrap();
        ledger.admit(1, 80).expect_err("does not fit");
        ledger.release(1, 80);
        assert_eq!(ledger.used(1), 0);
        ledger.admit(1, 80).expect("fits after release");
    }

    #[test]
    fn release_saturates_at_zero() {
        let mut ledger = AdmissionLedger::new(100);
        ledger.admit(1, 10).unwrap();
        // Releasing more than was admitted clamps instead of underflowing.
        ledger.release(1, 50);
        assert_eq!(ledger.used(1), 0);
    }
}
