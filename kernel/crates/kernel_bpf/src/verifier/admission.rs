//! Utilization-form admission ledger (Track C, #43).
//!
//! Attaching a program to a hook commits the processor to running it on every
//! fire. The ledger tracks the summed *utilization* of all admitted programs —
//! `Σ WCETᵢ·freqᵢ`, the EDF schedulability quantity — and rejects an attach
//! that would push it past the profile's budget. This is load-time
//! *schedulability* admission, not just safety.
//!
//! Each program contributes `wcet_cycles × CYCLE_UNIT_NS × freq_hz` nanoseconds
//! of CPU per wall-clock second: its static worst-case cycle bound
//! ([`crate::verifier::VerifyStats::wcet_cycles`]) converted to nanoseconds via
//! the calibrated [`crate::profile::PhysicalProfile::CYCLE_UNIT_NS`], times the
//! hook's fire rate. The budget is `U × 1e9` ns/s — half a core on the embedded
//! profile, unbounded on cloud. For EDF on one core the exact schedulability
//! test is `Σ utilization ≤ 1`; the budget encodes the chosen safety fraction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

/// A reservation or utilization failure while committing an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentCommitError {
    Admission(AdmissionError),
    Reservation,
}

/// Program ids published per attach type.
///
/// New hook keys are inserted only after their program vector has reserved
/// capacity, so a recoverable reservation failure cannot leave an empty hook
/// visible to readers.
#[derive(Debug)]
pub struct AttachmentTable {
    hooks: BTreeMap<u32, Vec<u32>>,
}

impl AttachmentTable {
    pub const fn new() -> Self {
        Self {
            hooks: BTreeMap::new(),
        }
    }

    pub fn get(&self, attach_type: &u32) -> Option<&Vec<u32>> {
        self.hooks.get(attach_type)
    }

    pub fn get_mut(&mut self, attach_type: &u32) -> Option<&mut Vec<u32>> {
        self.hooks.get_mut(attach_type)
    }

    pub fn contains(&self, attach_type: u32, prog_id: u32) -> bool {
        self.hooks
            .get(&attach_type)
            .is_some_and(|programs| programs.contains(&prog_id))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u32, &Vec<u32>)> {
        self.hooks.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&u32, &mut Vec<u32>)> {
        self.hooks.iter_mut()
    }

    pub fn values(&self) -> impl Iterator<Item = &Vec<u32>> {
        self.hooks.values()
    }

    pub fn retain(&mut self, f: impl FnMut(&u32, &mut Vec<u32>) -> bool) {
        self.hooks.retain(f);
    }

    fn try_insert_with(
        &mut self,
        attach_type: u32,
        prog_id: u32,
        reserve: impl FnOnce(&mut Vec<u32>) -> Result<(), ()>,
    ) -> Result<(), ()> {
        if let Some(programs) = self.hooks.get_mut(&attach_type) {
            reserve(programs)?;
            programs.push(prog_id);
            return Ok(());
        }

        let mut programs = Vec::new();
        reserve(&mut programs)?;
        programs.push(prog_id);
        self.hooks.insert(attach_type, programs);
        Ok(())
    }
}

impl Default for AttachmentTable {
    fn default() -> Self {
        Self::new()
    }
}

/// An attach was refused because the utilization budget would be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionError {
    /// The hook (attach type) the program was being attached to.
    pub hook: u32,
    /// Utilization already committed, in nanoseconds of CPU per second.
    pub committed_ns_per_s: u64,
    /// Utilization the rejected program would have added, in ns/s.
    pub requested_ns_per_s: u64,
    /// The total utilization budget, in ns/s (`U × 1e9`).
    pub budget_ns_per_s: u64,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hook {} utilization admission rejected: committed {} + requested {} ns/s exceeds budget {} ns/s",
            self.hook, self.committed_ns_per_s, self.requested_ns_per_s, self.budget_ns_per_s
        )
    }
}

/// Tracks summed processor utilization (`Σ WCETᵢ·freqᵢ`, in ns of CPU per
/// second) across all admitted attachments and rejects an attach that would
/// exceed the budget.
#[derive(Debug, Clone)]
pub struct AdmissionLedger {
    /// Total utilization budget, in ns/s (`U × 1e9`).
    budget_ns_per_s: u64,
    /// Calibrated nanoseconds per WCET cycle unit (profile `CYCLE_UNIT_NS`).
    cycle_unit_ns: u64,
    /// Utilization currently committed, in ns/s.
    committed_ns_per_s: u64,
    /// (hook, prog) → that attachment's utilization contribution, in ns/s, so a
    /// detach returns exactly what its attach committed.
    per_attachment: BTreeMap<(u32, u32), u64>,
}

impl AdmissionLedger {
    /// Create a ledger with `budget_ns_per_s` of CPU utilization and the
    /// profile's `cycle_unit_ns` cycle↔time calibration.
    pub const fn new(budget_ns_per_s: u64, cycle_unit_ns: u64) -> Self {
        Self {
            budget_ns_per_s,
            cycle_unit_ns,
            committed_ns_per_s: 0,
            per_attachment: BTreeMap::new(),
        }
    }

    /// Utilization a program of `wcet_cycles` firing at `freq_hz` would add, in
    /// ns of CPU per second: `wcet_cycles × cycle_unit_ns × freq_hz`.
    pub fn contribution(&self, wcet_cycles: u64, freq_hz: u64) -> u64 {
        wcet_cycles
            .saturating_mul(self.cycle_unit_ns)
            .saturating_mul(freq_hz)
    }

    /// Admit a program of `wcet_cycles` attached to `hook` (prog id `prog`)
    /// firing at `freq_hz`, or reject without committing if it would exceed the
    /// utilization budget. Re-admitting an already-admitted `(hook, prog)` is a
    /// no-op success.
    pub fn admit(
        &mut self,
        hook: u32,
        prog: u32,
        wcet_cycles: u64,
        freq_hz: u64,
    ) -> Result<(), AdmissionError> {
        if self.per_attachment.contains_key(&(hook, prog)) {
            return Ok(());
        }
        let requested = self.contribution(wcet_cycles, freq_hz);
        if self.committed_ns_per_s.saturating_add(requested) > self.budget_ns_per_s {
            return Err(AdmissionError {
                hook,
                committed_ns_per_s: self.committed_ns_per_s,
                requested_ns_per_s: requested,
                budget_ns_per_s: self.budget_ns_per_s,
            });
        }
        self.committed_ns_per_s += requested;
        self.per_attachment.insert((hook, prog), requested);
        Ok(())
    }

    /// Release the utilization committed by `(hook, prog)` (detach). A no-op if
    /// the attachment was never admitted.
    pub fn release(&mut self, hook: u32, prog: u32) {
        if let Some(contribution) = self.per_attachment.remove(&(hook, prog)) {
            self.committed_ns_per_s = self.committed_ns_per_s.saturating_sub(contribution);
        }
    }

    /// Whether `(hook, prog)` currently consumes an admission slot.
    pub fn contains(&self, hook: u32, prog: u32) -> bool {
        self.per_attachment.contains_key(&(hook, prog))
    }

    /// Utilization currently committed across all attachments, in ns/s.
    pub fn committed_ns_per_s(&self) -> u64 {
        self.committed_ns_per_s
    }

    /// The total utilization budget, in ns/s.
    pub fn budget_ns_per_s(&self) -> u64 {
        self.budget_ns_per_s
    }
}

/// Commit one attachment as a reservation-before-publication transaction.
pub fn commit_attachment(
    attachments: &mut AttachmentTable,
    admission: &mut AdmissionLedger,
    hook: u32,
    prog: u32,
    wcet_cycles: u64,
    freq_hz: u64,
) -> Result<(), AttachmentCommitError> {
    commit_attachment_with_reservation(
        attachments,
        admission,
        hook,
        prog,
        wcet_cycles,
        freq_hz,
        |programs| programs.try_reserve(1).map_err(|_| ()),
    )
}

fn commit_attachment_with_reservation(
    attachments: &mut AttachmentTable,
    admission: &mut AdmissionLedger,
    hook: u32,
    prog: u32,
    wcet_cycles: u64,
    freq_hz: u64,
    reserve: impl FnOnce(&mut Vec<u32>) -> Result<(), ()>,
) -> Result<(), AttachmentCommitError> {
    if attachments.contains(hook, prog) {
        return admission
            .admit(hook, prog, wcet_cycles, freq_hz)
            .map_err(AttachmentCommitError::Admission);
    }
    admission
        .admit(hook, prog, wcet_cycles, freq_hz)
        .map_err(AttachmentCommitError::Admission)?;
    if attachments.try_insert_with(hook, prog, reserve).is_err() {
        admission.release(hook, prog);
        return Err(AttachmentCommitError::Reservation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1 ns/unit keeps the arithmetic readable: contribution == wcet × freq.
    const UNIT_NS: u64 = 1;

    #[test]
    fn admits_until_utilization_budget_then_rejects() {
        // Budget 1000 ns/s; each program: wcet 100 units × 1 ns × freq.
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);

        ledger.admit(1, 0, 100, 6).expect("600 ns/s fits"); // 100*1*6
        ledger
            .admit(1, 1, 100, 4)
            .expect("+400 = exactly 1000 fits"); // 100*1*4

        let err = ledger
            .admit(1, 2, 1, 1)
            .expect_err("over budget must reject");
        assert_eq!(
            err,
            AdmissionError {
                hook: 1,
                committed_ns_per_s: 1000,
                requested_ns_per_s: 1,
                budget_ns_per_s: 1000,
            }
        );
        // A rejected admit must not consume budget.
        assert_eq!(ledger.committed_ns_per_s(), 1000);
    }

    #[test]
    fn utilization_sums_across_hooks_one_core() {
        // Unlike the old per-hook ledger, the budget is global (one core), so
        // load on different hooks competes for the same utilization budget.
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);
        ledger.admit(1, 0, 100, 5).expect("hook 1: 500 ns/s");
        ledger
            .admit(2, 1, 100, 5)
            .expect("hook 2: +500 = 1000 fits");
        ledger
            .admit(3, 2, 1, 1)
            .expect_err("no utilization left on any hook");
    }

    #[test]
    fn release_frees_utilization() {
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);
        ledger.admit(1, 0, 100, 8).unwrap(); // 800 ns/s
        ledger
            .admit(1, 1, 100, 8)
            .expect_err("second 800 does not fit");
        ledger.release(1, 0);
        assert_eq!(ledger.committed_ns_per_s(), 0);
        ledger.admit(1, 1, 100, 8).expect("fits after release");
    }

    #[test]
    fn new_hook_reservation_failure_rolls_back_admission_and_key() {
        let mut attachments = AttachmentTable::new();
        let mut admission = AdmissionLedger::new(1000, UNIT_NS);

        assert_eq!(
            commit_attachment_with_reservation(
                &mut attachments,
                &mut admission,
                7,
                41,
                10,
                5,
                |_| Err(())
            ),
            Err(AttachmentCommitError::Reservation)
        );
        assert!(attachments.get(&7).is_none());
        assert!(!admission.contains(7, 41));
        assert_eq!(admission.committed_ns_per_s(), 0);

        commit_attachment(&mut attachments, &mut admission, 7, 41, 10, 5)
            .expect("retry after reservation failure");
        assert_eq!(attachments.get(&7).unwrap().as_slice(), &[41]);
        assert!(admission.contains(7, 41));
        assert_eq!(admission.committed_ns_per_s(), 50);
    }

    #[test]
    fn existing_hook_reservation_failure_preserves_published_programs() {
        let mut attachments = AttachmentTable::new();
        let mut admission = AdmissionLedger::new(1000, UNIT_NS);
        commit_attachment(&mut attachments, &mut admission, 7, 41, 10, 5)
            .expect("publish first attachment");

        assert_eq!(
            commit_attachment_with_reservation(
                &mut attachments,
                &mut admission,
                7,
                42,
                20,
                5,
                |_| Err(())
            ),
            Err(AttachmentCommitError::Reservation)
        );
        assert_eq!(attachments.get(&7).unwrap().as_slice(), &[41]);
        assert!(admission.contains(7, 41));
        assert!(!admission.contains(7, 42));
        assert_eq!(admission.committed_ns_per_s(), 50);

        commit_attachment(&mut attachments, &mut admission, 7, 42, 20, 5)
            .expect("retry extends existing hook");
        assert_eq!(attachments.get(&7).unwrap().as_slice(), &[41, 42]);
        assert!(admission.contains(7, 42));
        assert_eq!(admission.committed_ns_per_s(), 150);
    }

    #[test]
    fn repeated_commit_does_not_reserve_publish_or_charge_twice() {
        let mut attachments = AttachmentTable::new();
        let mut admission = AdmissionLedger::new(1000, UNIT_NS);
        commit_attachment(&mut attachments, &mut admission, 7, 41, 10, 5)
            .expect("publish first attachment");

        commit_attachment_with_reservation(&mut attachments, &mut admission, 7, 41, 10, 5, |_| {
            panic!("idempotent commit must not reserve again")
        })
        .expect("repeated commit is an idempotent success");

        assert_eq!(attachments.get(&7).unwrap().as_slice(), &[41]);
        assert!(admission.contains(7, 41));
        assert_eq!(admission.committed_ns_per_s(), 50);
    }

    #[test]
    fn re_admitting_same_attachment_does_not_double_count() {
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);
        ledger.admit(1, 0, 100, 5).unwrap();
        ledger.admit(1, 0, 100, 5).expect("idempotent");
        assert_eq!(ledger.committed_ns_per_s(), 500);
    }

    #[test]
    fn cycle_unit_scales_contribution() {
        // 6 ns/unit: a 100-unit program at 10 Hz costs 100*6*10 = 6000 ns/s.
        let ledger = AdmissionLedger::new(u64::MAX, 6);
        assert_eq!(ledger.contribution(100, 10), 6000);
    }
}
