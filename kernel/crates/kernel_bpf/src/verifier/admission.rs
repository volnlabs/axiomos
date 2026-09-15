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
//! modeled [`crate::profile::PhysicalProfile::CYCLE_UNIT_NS`], times the
//! hook's fire rate. The budget is `U × 1e9` ns/s — half a core on the embedded
//! profile, unbounded on cloud. For EDF on one core the exact schedulability
//! test is `Σ utilization ≤ 1`; the budget encodes the chosen safety fraction.
//! The managed controller has one fixed reservation at 100 Hz, independent of
//! hook fanout. These arithmetic checks do not qualify interpreter timing.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

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

/// Failure to reserve or settle the single managed controller contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedAdmissionError {
    Busy,
    Stale,
    Overflow,
    Budget {
        reserved_ns_per_s: u64,
        requested_ns_per_s: u64,
        budget_ns_per_s: u64,
    },
}

/// Process-local monotonic receipt identity; values are not stable across boots.
static MANAGED_RESERVATION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_managed_reservation_id(counter: &AtomicU64) -> Result<u64, ManagedAdmissionError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            last.checked_add(1)
        })
        .map(|last| last + 1)
        .map_err(|_| ManagedAdmissionError::Overflow)
}

/// Worker-owned reservation. Losing it holds capacity; it never refunds on
/// Drop. The installation records its scalar cost before boundary publication.
#[derive(Debug)]
#[must_use]
pub struct ManagedAdmissionReservation {
    id: u64,
    contribution: u64,
}

impl ManagedAdmissionReservation {
    pub const fn contribution_ns_per_s(&self) -> u64 {
        self.contribution
    }
}

/// Tracks summed processor utilization (`Σ WCETᵢ·freqᵢ`, in ns of CPU per
/// second) across all admitted attachments and rejects an attach that would
/// exceed the budget.
#[derive(Debug)]
pub struct AdmissionLedger {
    /// Total utilization budget, in ns/s (`U × 1e9`).
    budget_ns_per_s: u64,
    /// Modeled nanoseconds per WCET cycle unit (profile `CYCLE_UNIT_NS`).
    cycle_unit_ns: u64,
    /// Utilization currently committed, in ns/s.
    committed_ns_per_s: u64,
    /// (hook, prog) → that attachment's utilization contribution, in ns/s, so a
    /// detach returns exactly what its attach committed.
    per_attachment: BTreeMap<(u32, u32), u64>,
    /// Worker-settled managed charge. The slot's installation receipt remains
    /// authoritative while a boundary result awaits worker settlement.
    managed_ns_per_s: u64,
    /// (reservation ID, replacement contribution). Both controllers execute
    /// exclusively, so capacity holds max(old, replacement), never their sum.
    pending_managed: Option<(u64, u64)>,
}

impl AdmissionLedger {
    /// Create a ledger with `budget_ns_per_s` of CPU utilization and the
    /// profile's modeled `cycle_unit_ns` duration.
    pub const fn new(budget_ns_per_s: u64, cycle_unit_ns: u64) -> Self {
        Self {
            budget_ns_per_s,
            cycle_unit_ns,
            committed_ns_per_s: 0,
            per_attachment: BTreeMap::new(),
            managed_ns_per_s: 0,
            pending_managed: None,
        }
    }

    /// Utilization a program of `wcet_cycles` firing at `freq_hz` would add, in
    /// ns of CPU per second: `wcet_cycles × cycle_unit_ns × freq_hz`.
    pub fn contribution(&self, wcet_cycles: u64, freq_hz: u64) -> u64 {
        wcet_cycles
            .saturating_mul(self.cycle_unit_ns)
            .saturating_mul(freq_hz)
    }

    /// Reserve a replacement at the fixed 100 Hz managed rate, without changing
    /// the settled active charge or allocating. Pass zero for deactivation.
    /// A later legacy attach also sees this reservation and cannot steal it.
    pub fn prepare_managed(
        &mut self,
        wcet_cycles: u64,
    ) -> Result<ManagedAdmissionReservation, ManagedAdmissionError> {
        if self.pending_managed.is_some() {
            return Err(ManagedAdmissionError::Busy);
        }
        let contribution = wcet_cycles
            .checked_mul(self.cycle_unit_ns)
            .and_then(|ns| ns.checked_mul(100))
            .ok_or(ManagedAdmissionError::Overflow)?;
        let reserved = self
            .committed_ns_per_s
            .checked_add(self.managed_ns_per_s.max(contribution))
            .ok_or(ManagedAdmissionError::Overflow)?;
        if reserved > self.budget_ns_per_s {
            return Err(ManagedAdmissionError::Budget {
                reserved_ns_per_s: self.reserved_ns_per_s(),
                requested_ns_per_s: contribution,
                budget_ns_per_s: self.budget_ns_per_s,
            });
        }
        let id = next_managed_reservation_id(&MANAGED_RESERVATION_COUNTER)?;
        self.pending_managed = Some((id, contribution));
        Ok(ManagedAdmissionReservation { id, contribution })
    }

    /// Worker settlement after the authoritative slot outcome is known.
    /// `committed` applies the new charge; cancellation preserves the old one.
    /// No ledger mutation is needed in the timer's publication path: capacity
    /// stays conservative until this receipt is consumed by the worker.
    pub fn finish_managed(
        &mut self,
        reservation: ManagedAdmissionReservation,
        committed: bool,
    ) -> Result<(), ManagedAdmissionError> {
        if self.pending_managed != Some((reservation.id, reservation.contribution)) {
            return Err(ManagedAdmissionError::Stale);
        }
        if committed {
            self.managed_ns_per_s = reservation.contribution;
        }
        self.pending_managed = None;
        Ok(())
    }

    /// Capacity unavailable to new attachments, including a pending managed
    /// replacement. All successful reservations have checked this sum.
    pub fn reserved_ns_per_s(&self) -> u64 {
        self.committed_ns_per_s
            + self
                .managed_ns_per_s
                .max(self.pending_managed.map_or(0, |(_, cost)| cost))
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
        let reserved = self.reserved_ns_per_s();
        if reserved
            .checked_add(requested)
            .is_none_or(|total| total > self.budget_ns_per_s)
        {
            return Err(AdmissionError {
                hook,
                committed_ns_per_s: reserved,
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

    /// Legacy attachments plus the last worker-settled managed charge, in
    /// ns/s. Use `reserved_ns_per_s` when deciding whether capacity is free.
    pub fn committed_ns_per_s(&self) -> u64 {
        self.committed_ns_per_s + self.managed_ns_per_s
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
    fn managed_replacement_reserves_the_larger_exclusive_cost() {
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);
        ledger.admit(1, 1, 100, 1).unwrap();
        let first = ledger.prepare_managed(6).unwrap();
        assert_eq!(first.contribution_ns_per_s(), 600);
        assert_eq!(ledger.committed_ns_per_s(), 100);
        assert_eq!(ledger.reserved_ns_per_s(), 700);
        ledger.finish_managed(first, true).unwrap();

        let replacement = ledger.prepare_managed(9).unwrap();
        assert_eq!(ledger.committed_ns_per_s(), 700);
        assert_eq!(ledger.reserved_ns_per_s(), 1000);
        assert!(ledger.admit(2, 2, 1, 1).is_err());
        assert!(matches!(
            ledger.prepare_managed(1),
            Err(ManagedAdmissionError::Busy)
        ));
        ledger.finish_managed(replacement, false).unwrap();
        assert_eq!(ledger.committed_ns_per_s(), 700);
        assert_eq!(ledger.reserved_ns_per_s(), 700);

        let cheaper = ledger.prepare_managed(2).unwrap();
        assert_eq!(ledger.reserved_ns_per_s(), 700);
        ledger.finish_managed(cheaper, true).unwrap();
        assert_eq!(ledger.committed_ns_per_s(), 300);
        assert_eq!(ledger.reserved_ns_per_s(), 300);
        let deactivate = ledger.prepare_managed(0).unwrap();
        assert_eq!(ledger.reserved_ns_per_s(), 300);
        ledger.finish_managed(deactivate, true).unwrap();
        assert_eq!(ledger.committed_ns_per_s(), 100);
        ledger.release(1, 1);
        assert_eq!(ledger.reserved_ns_per_s(), 0);
    }

    #[test]
    fn managed_rejection_preserves_charge_and_checks_exhaustion() {
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);
        let first = ledger.prepare_managed(6).unwrap();
        ledger.finish_managed(first, true).unwrap();
        assert!(matches!(
            ledger.prepare_managed(11),
            Err(ManagedAdmissionError::Budget { .. })
        ));
        assert_eq!(ledger.committed_ns_per_s(), 600);
        assert_eq!(ledger.reserved_ns_per_s(), 600);
        let exhausted_counter = AtomicU64::new(u64::MAX);
        assert!(matches!(
            next_managed_reservation_id(&exhausted_counter),
            Err(ManagedAdmissionError::Overflow)
        ));
        assert_eq!(ledger.reserved_ns_per_s(), 600);

        let mut huge = AdmissionLedger::new(u64::MAX, 1);
        assert!(matches!(
            huge.prepare_managed(u64::MAX),
            Err(ManagedAdmissionError::Overflow)
        ));
        huge.admit(1, 1, u64::MAX, 1).unwrap();
        assert!(huge.admit(1, 2, 1, 1).is_err());
        assert!(matches!(
            huge.prepare_managed(1),
            Err(ManagedAdmissionError::Overflow)
        ));
        assert_eq!(huge.reserved_ns_per_s(), u64::MAX);
    }

    #[test]
    fn managed_receipt_is_checked_and_lost_receipt_holds_capacity() {
        let mut ledger = AdmissionLedger::new(1000, UNIT_NS);
        {
            let ticket = ledger.prepare_managed(5).unwrap();
            let stale = ManagedAdmissionReservation {
                id: ticket.id + 1,
                contribution: 500,
            };
            assert_eq!(
                ledger.finish_managed(stale, true),
                Err(ManagedAdmissionError::Stale)
            );
            assert_eq!(ledger.committed_ns_per_s(), 0);
            assert_eq!(ledger.reserved_ns_per_s(), 500);
        }
        assert!(matches!(
            ledger.prepare_managed(1),
            Err(ManagedAdmissionError::Busy)
        ));
        assert!(ledger.admit(1, 1, 501, 1).is_err());
    }

    #[test]
    fn managed_receipt_from_another_ledger_is_stale() {
        let mut first = AdmissionLedger::new(1000, UNIT_NS);
        let mut second = AdmissionLedger::new(1000, UNIT_NS);
        let wrong_receipt = first.prepare_managed(5).unwrap();
        let right_receipt = second.prepare_managed(5).unwrap();

        assert_eq!(
            second.finish_managed(wrong_receipt, false),
            Err(ManagedAdmissionError::Stale)
        );
        assert_eq!(second.reserved_ns_per_s(), 500);
        second.finish_managed(right_receipt, false).unwrap();
        assert_eq!(second.reserved_ns_per_s(), 0);
    }

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
