//! Exclusive fixed-slot ownership. Kernel-private until authority and correlated
//! physical handoff are wired. CPU0 access and worker custody remain separate.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use kernel_abi::ManagedControlContextV1;
use kernel_bpf::execution::{BpfError, ManagedInvocationResult};
use kernel_bpf::verifier::admission::{ManagedAdmissionError, ManagedAdmissionReservation};
use kernel_bpf::verifier::BehaviorArtifact;
use kernel_time::periodic::PeriodicRelease;
use shrike_link::handoff::{Handoff, HandoffError, SafeReceipt};
use shrike_link::tx::TxState;

use super::managed::{
    BehaviorInstance, InstancePreparation, ManagedInstanceFinishError, ManagedReclamation,
    PreparedInstance, ReclamationReceipt,
};
use super::BpfManager;

/// One slot, separate from manager storage. Combined paths always lock this
/// first, with local IRQs masked; the release boundary only uses try_lock.
pub(super) static CONTROL_SLOT: spin::Mutex<ControlSlot> = spin::Mutex::new(ControlSlot::new());
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Trusted stop writers never take the slot lock (they may already hold the
/// actuator lock). The next CPU0 slot boundary consumes this before publication.
pub(crate) fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::Release);
}

fn apply_requested_stop(slot: &mut ControlSlot, requested: &AtomicBool) {
    if requested.swap(false, Ordering::AcqRel) {
        slot.stop();
    }
}

pub(crate) fn qualified_topology() -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
    {
        crate::mcore::context::online_cpu_mask() == 1
            && crate::mcore::context::ExecutionContext::try_load()
                .is_some_and(|context| context.cpu_id() == 0)
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime")))]
    {
        false
    }
}

/// Kernel-private management entry. Boot initialization does not require a CPU
/// context; accepting lifecycle work does. Physical eligibility stays pending.
pub(crate) fn request_installation(
    expected_last_id: u64,
    expected_generation: u64,
    target: super::preparation::LifecycleTarget,
) -> Result<u64, kernel_abi::Errno> {
    let result = crate::mcore::context::with_interrupts_masked(|| {
        if !qualified_topology() {
            return Err(kernel_abi::ENOTSUP);
        }
        let mut slot = CONTROL_SLOT.lock();
        apply_requested_stop(&mut slot, &STOP_REQUESTED);
        let mut manager = crate::BPF_MANAGER.get().ok_or(kernel_abi::ENODEV)?.lock();
        manager.request_installation(&mut slot, expected_last_id, expected_generation, target)
    });
    if result.is_ok() {
        super::preparation::wake();
    }
    result
}

pub(crate) fn query_installation(
    id: u64,
) -> Result<kernel_abi::ManagedOperationV1, kernel_abi::Errno> {
    crate::mcore::context::with_interrupts_masked(|| {
        if !qualified_topology() {
            return Err(kernel_abi::ENOTSUP);
        }
        let mut slot = CONTROL_SLOT.lock();
        apply_requested_stop(&mut slot, &STOP_REQUESTED);
        let manager = crate::BPF_MANAGER.get().ok_or(kernel_abi::ENODEV)?.lock();
        manager.query_installation(&slot, id)
    })
}

pub(crate) fn cancel_installation(
    id: u64,
    expected_generation: u64,
    target: super::preparation::LifecycleTarget,
) -> Result<(), kernel_abi::Errno> {
    let result = crate::mcore::context::with_interrupts_masked(|| {
        if !qualified_topology() {
            return Err(kernel_abi::ENOTSUP);
        }
        let mut slot = CONTROL_SLOT.lock();
        apply_requested_stop(&mut slot, &STOP_REQUESTED);
        let mut manager = crate::BPF_MANAGER.get().ok_or(kernel_abi::ENODEV)?.lock();
        manager.cancel_installation(&mut slot, id, expected_generation, target)
    });
    if result.is_ok() {
        super::preparation::wake();
    }
    result
}

/// CPU0 boundary access: no manager, allocation, waiting or physical
/// safety assertion. Failure requires the caller to keep its sink inhibited.
/// The callback must remain bounded and must not retain instance references.
pub(crate) fn try_release_boundary<R>(
    boundary: impl FnOnce(&mut ControlSlot) -> R,
) -> Result<R, BpfError> {
    crate::mcore::context::with_interrupts_masked(|| {
        if !qualified_topology() {
            return Err(BpfError::PermissionDenied);
        }
        let mut slot = CONTROL_SLOT.try_lock().ok_or(BpfError::ObjectBusy)?;
        apply_requested_stop(&mut slot, &STOP_REQUESTED);
        // Ownership persists through inhibition. Only acknowledged safe
        // deactivation may release it; that production path is not enabled yet.
        if slot.active.is_some() || slot.pending.is_some_and(|pending| pending.handoff) {
            crate::actuation::set_managed_motor_pair_owner(true);
        }
        let result = boundary(&mut slot);
        if slot.active.is_some() || slot.pending.is_some_and(|pending| pending.handoff) {
            crate::actuation::set_managed_motor_pair_owner(true);
        }
        if slot.retire.is_some()
            || slot
                .pending
                .is_some_and(|pending| pending.cancelled || pending.handoff)
        {
            // READY has exactly one permanent waiter. Under qualified CPU0 IRQ
            // masking no publisher can race this bounded wake operation.
            super::preparation::wake();
        }
        Ok(result)
    })
}

struct ArtifactRef {
    handle: u32,
    code: Arc<BehaviorArtifact>,
}

struct Installation {
    generation: u64,
    instance_id: u64,
    active_charge_ns_per_s: u64,
    instance: Arc<BehaviorInstance>,
    // Prepared before publication, later moved into Previous.
    artifact: ArtifactRef,
}

#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    expected: u64,
    generation: u64,
    candidate: bool,
    cancelled: bool,
    handoff: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotSnapshot {
    pub generation: u64,
    pub active: Option<u32>,
    pub active_charge_ns_per_s: Option<u64>,
    pub previous: Option<u32>,
    pub pending: Option<u64>,
    pub inhibited: bool,
    pub retiring: bool,
}

/// Separately owned from BPF_MANAGER. Exclusive borrowing prevents an invocation
/// from spanning publication; the global CPU0 wrapper enforces IRQ scope.
/// Resident upload custody is the preparation state's single candidate handle;
/// begin() borrows that role while its fresh instance is built by the worker.
pub(crate) struct ControlSlot {
    active: Option<Installation>,
    previous: Option<ArtifactRef>,
    staged: Option<Installation>,
    pending: Option<Pending>,
    admission: Option<ManagedAdmissionReservation>,
    retire: Option<RetireBatch>,
    retiring: Option<u64>,
    generation: u64,
    inhibited: bool,
    pub(super) last_control_release: u64,
}

pub(crate) struct InstallationPreparation {
    pending: Pending,
    artifact: ArtifactRef,
    instance: InstancePreparation,
    active_charge_ns_per_s: u64,
}

pub(crate) struct BuiltInstallation {
    pending: Pending,
    artifact: ArtifactRef,
    instance: PreparedInstance,
    active_charge_ns_per_s: u64,
}

impl InstallationPreparation {
    pub(super) fn instance_id(&self) -> u64 {
        self.pending.id
    }

    pub(super) fn cancel(self) -> BuiltInstallation {
        BuiltInstallation {
            pending: self.pending,
            artifact: self.artifact,
            instance: self.instance.cancel(),
            active_charge_ns_per_s: self.active_charge_ns_per_s,
        }
    }

    pub(crate) fn build(self) -> BuiltInstallation {
        BuiltInstallation {
            pending: self.pending,
            artifact: self.artifact,
            instance: self.instance.build(),
            active_charge_ns_per_s: self.active_charge_ns_per_s,
        }
    }

    #[cfg(test)]
    fn fail(self) -> BuiltInstallation {
        BuiltInstallation {
            pending: self.pending,
            artifact: self.artifact,
            instance: self.instance.cancel(),
            active_charge_ns_per_s: self.active_charge_ns_per_s,
        }
    }
}

impl ControlSlot {
    pub(crate) const fn new() -> Self {
        Self {
            active: None,
            previous: None,
            staged: None,
            pending: None,
            admission: None,
            retire: None,
            retiring: None,
            generation: 0,
            inhibited: true,
            last_control_release: 0,
        }
    }

    pub(crate) fn snapshot(&self) -> SlotSnapshot {
        SlotSnapshot {
            generation: self.generation,
            active: self.active.as_ref().map(|a| a.artifact.handle),
            active_charge_ns_per_s: self.active.as_ref().map(|a| a.active_charge_ns_per_s),
            previous: self.previous.as_ref().map(|a| a.handle),
            pending: self.pending.map(|p| p.id),
            inhibited: self.inhibited,
            retiring: self.retiring.is_some(),
        }
    }

    pub(super) fn operation_phase(&self, id: u64) -> Option<u32> {
        use kernel_abi::*;
        let pending = self.pending.filter(|pending| pending.id == id)?;
        Some(if pending.cancelled {
            MANAGED_OPERATION_CLEANUP
        } else if pending.handoff {
            MANAGED_OPERATION_HANDOFF
        } else if self.staged.is_some() {
            MANAGED_OPERATION_STAGED
        } else {
            MANAGED_OPERATION_PREPARING
        })
    }

    pub(super) fn abort_cancelled(&mut self) {
        if self.pending.is_some_and(|pending| pending.cancelled) && self.staged.is_some() {
            self.abort_staged()
                .expect("cancelled staged installation retains retirement capacity");
        }
    }

    /// `previous = Some(exact_handle)` requests rollback; None selects the one
    /// authenticated resident candidate. Every accepted path allocates new state.
    pub(crate) fn begin(
        &mut self,
        manager: &mut BpfManager,
        expected: u64,
        previous: Option<u32>,
    ) -> Result<InstallationPreparation, BpfError> {
        if expected != self.generation {
            return Err(BpfError::NotLoaded);
        }
        if self.pending.is_some() || self.retiring.is_some() || manager.managed_slot_busy {
            return Err(BpfError::ObjectBusy);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(BpfError::ResourceLimit)?;
        let handle = match previous {
            Some(handle) if self.previous.as_ref().map(|a| a.handle) == Some(handle) => handle,
            Some(_) => return Err(BpfError::NotLoaded),
            None => manager.preparation.candidate.ok_or(BpfError::NotLoaded)?,
        };
        let artifact = ArtifactRef {
            handle,
            code: manager.managed_artifact(handle)?.clone(),
        };
        let admission = manager
            .admission
            .prepare_managed(artifact.code.wcet_cycles())
            .map_err(map_admission_error)?;
        let active_charge_ns_per_s = admission.contribution_ns_per_s();
        let instance = match manager.begin_managed_instance(handle) {
            Ok(instance) => instance,
            Err(error) => {
                manager
                    .admission
                    .finish_managed(admission, false)
                    .map_err(map_admission_error)?;
                return Err(error);
            }
        };
        let pending = Pending {
            id: instance.id(),
            expected,
            generation,
            candidate: previous.is_none(),
            cancelled: false,
            handoff: false,
        };
        self.pending = Some(pending);
        self.admission = Some(admission);
        manager.managed_slot_busy = true;
        Ok(InstallationPreparation {
            pending,
            artifact,
            instance,
            active_charge_ns_per_s,
        })
    }

    /// Manager registration may fail, but rejected ownership always moves into
    /// the reserved batch. Worker cleanup must run even when this returns Err.
    pub(crate) fn finish_build(
        &mut self,
        manager: &mut BpfManager,
        built: BuiltInstallation,
    ) -> Result<(), BpfError> {
        // Tokens cannot be fabricated outside this module. A pending token is
        // never cleared by cancellation/stop while the worker owns its build.
        let pending = self
            .pending
            .as_ref()
            .expect("accepted build retains slot custody");
        assert_eq!(pending.id, built.pending.id);
        let cancelled = pending.cancelled;
        match manager.finish_managed_instance(built.instance) {
            Ok(instance) => {
                let installation = Installation {
                    generation: built.pending.generation,
                    instance_id: built.pending.id,
                    active_charge_ns_per_s: built.active_charge_ns_per_s,
                    instance,
                    artifact: built.artifact,
                };
                self.staged = Some(installation);
                if cancelled {
                    self.abort_staged()?;
                    Err(BpfError::ObjectBusy)
                } else {
                    Ok(())
                }
            }
            Err(failure) => {
                let error = failure.error();
                self.pending = None;
                self.retiring = Some(built.pending.id);
                self.retire = Some(RetireBatch {
                    id: built.pending.id,
                    admission: self
                        .admission
                        .take()
                        .expect("accepted build retains admission custody"),
                    committed: false,
                    instance: None,
                    artifact: Some(built.artifact),
                    evict_artifact: false,
                    failed: Some(failure),
                    consumed_candidate: None,
                });
                Err(error)
            }
        }
    }

    pub(crate) fn cancel(&mut self, id: u64) -> Result<(), BpfError> {
        let pending = self
            .pending
            .as_mut()
            .filter(|p| p.id == id)
            .ok_or(BpfError::NotLoaded)?;
        pending.cancelled = true;
        Ok(())
    }

    pub(crate) fn stop(&mut self) {
        self.inhibited = true;
        if let Some(pending) = &mut self.pending {
            pending.cancelled = true;
        }
    }

    /// Internal entry into trusted safe mode, after the old invocation returns.
    /// This does not assert sink safety or grant publication eligibility.
    pub(crate) fn enter_handoff(&mut self, id: u64) -> Result<(), BpfError> {
        let pending = self
            .pending
            .as_mut()
            .filter(|p| p.id == id)
            .ok_or(BpfError::NotLoaded)?;
        if pending.cancelled || self.staged.is_none() {
            return Err(BpfError::ObjectBusy);
        }
        pending.handoff = true;
        self.inhibited = true;
        Ok(())
    }

    /// Consume transport eligibility at the exclusive CPU0 release boundary.
    /// Receipt construction requires a matching post-transmission SafeAck.
    fn commit_validated_handoff(&mut self, receipt: SafeReceipt) -> Result<u64, BpfError> {
        let id = receipt.operation();
        let pending = self
            .pending
            .filter(|p| p.id == id)
            .ok_or(BpfError::NotLoaded)?;
        if pending.expected != self.generation {
            return Err(BpfError::NotLoaded);
        }
        if pending.cancelled || !pending.handoff || self.retiring.is_some() || self.staged.is_none()
        {
            return Err(BpfError::ObjectBusy);
        }
        // All checks precede mutation. Only owned Option/scalar moves follow.
        let next = self.staged.take().unwrap();
        let evict_artifact = self.previous.as_ref().is_some_and(|a| {
            a.handle != next.artifact.handle
                && self.active.as_ref().map(|old| old.artifact.handle) != Some(a.handle)
        });
        let consumed_candidate = pending.candidate.then_some(next.artifact.handle);
        let artifact = self.previous.take();
        let displaced = self.active.take();
        let instance = displaced.map(|old| {
            self.previous = Some(old.artifact);
            (old.instance_id, old.instance)
        });
        self.active = Some(next);
        self.generation = self.active.as_ref().unwrap().generation;
        self.pending = None;
        self.inhibited = false;
        self.retiring = Some(id);
        self.retire = Some(RetireBatch {
            id,
            admission: self
                .admission
                .take()
                .expect("accepted build retains admission custody"),
            committed: true,
            instance,
            artifact,
            evict_artifact,
            failed: None,
            consumed_candidate,
        });
        Ok(self.generation)
    }

    /// The production timer and host tests share this complete publication path.
    /// Caller holds the slot and link under CPU0 IRQ masking. It must check stop
    /// first; any error requires the trusted stop path after releasing the link.
    pub(crate) fn handoff_boundary(
        &mut self,
        release: PeriodicRelease,
        frequency: u64,
        handoff: &mut Handoff,
        tx: &mut TxState,
        motor_sequence: &mut u8,
    ) -> Result<Option<u64>, HandoffError> {
        let result = (|| {
            if release.sequence <= self.last_control_release
                || release.scheduled > release.actual
                || release.actual >= release.deadline
                || release.missed_before != 0
            {
                return Err(HandoffError::InvalidRelease);
            }
            handoff.check(release.actual)?;
            if let Some(operation) = handoff.operation() {
                if !self.pending.is_some_and(|pending| {
                    pending.id == operation && pending.handoff && !pending.cancelled
                }) {
                    return Err(HandoffError::Stale);
                }
                if let Some(receipt) = handoff.take_ready(release.scheduled, release.actual)? {
                    return self
                        .commit_validated_handoff(receipt)
                        .map(Some)
                        .map_err(|_| HandoffError::Stale);
                }
            } else if let Some(pending) = self.pending.filter(|pending| !pending.cancelled) {
                if pending.handoff {
                    return Err(HandoffError::NotEstablished);
                }
                if self.staged.is_some() {
                    // Reject unrepresentable 80 ms rather than round a timeout.
                    let timeout = frequency
                        .checked_mul(80)
                        .filter(|ticks| *ticks != 0 && ticks % 1000 == 0)
                        .ok_or(HandoffError::InvalidTimeout)?
                        / 1000;
                    self.enter_handoff(pending.id)
                        .map_err(|_| HandoffError::Busy)?;
                    let sequence = motor_sequence.wrapping_add(1);
                    handoff.begin_on_transport(
                        pending.id,
                        sequence,
                        release.actual,
                        timeout,
                        tx,
                    )?;
                    *motor_sequence = sequence;
                }
            }
            Ok(None)
        })();
        if result.is_err() {
            self.stop();
            handoff.disarm();
            tx.clear_motor();
            tx.cancel_unsent();
        }
        result
    }

    /// Existing ownership/admission tests exercise the real receipt checks while
    /// supplying a deterministic, host-only peer acknowledgement.
    #[cfg(test)]
    pub(super) fn commit_test_handoff(&mut self, id: u64) -> Result<u64, BpfError> {
        use shrike_link::Msg;
        let mut handoff = Handoff::new();
        let offer = handoff.offer_after_drain().unwrap();
        handoff.started(offer).unwrap();
        handoff.sent(0).unwrap();
        handoff
            .on_reply(Msg::SessionReady { session: 1 }, 0)
            .unwrap();
        let key = handoff.begin(id, 1, 0, 80).unwrap();
        handoff.started(handoff.outbound().unwrap()).unwrap();
        handoff.sent(0).unwrap();
        handoff
            .on_reply(
                Msg::SafeAck {
                    session: key.session,
                    correlation: key.correlation,
                    sequence: key.sequence,
                },
                0,
            )
            .unwrap();
        self.commit_validated_handoff(handoff.take_ready(0, 0).unwrap().unwrap())
    }

    /// Worker discards a staged cancellation/failure without destroying state.
    pub(crate) fn abort_staged(&mut self) -> Result<(), BpfError> {
        let pending = self.pending.ok_or(BpfError::NotLoaded)?;
        if self.retiring.is_some() || self.staged.is_none() {
            return Err(BpfError::ObjectBusy);
        }
        let staged = self.staged.take().unwrap();
        self.pending = None;
        self.retiring = Some(pending.id);
        self.retire = Some(RetireBatch {
            id: pending.id,
            admission: self
                .admission
                .take()
                .expect("accepted build retains admission custody"),
            committed: false,
            instance: Some((staged.instance_id, staged.instance)),
            artifact: Some(staged.artifact),
            evict_artifact: false,
            failed: None,
            consumed_candidate: None,
        });
        Ok(())
    }

    /// Synchronous borrow; no instance/Arc escapes into the timer caller.
    pub(crate) fn execute(
        &self,
        context: &ManagedControlContextV1,
    ) -> Result<ManagedInvocationResult, BpfError> {
        if self.inhibited {
            return Err(BpfError::ObjectBusy);
        }
        self.active
            .as_ref()
            .ok_or(BpfError::NotLoaded)?
            .instance
            .execute(context)
    }

    pub(crate) fn take_retirement(&mut self) -> Option<RetireBatch> {
        self.retire.take()
    }

    pub(crate) fn finish_retirement(
        &mut self,
        manager: &mut BpfManager,
        receipt: Retired,
    ) -> Result<(), BpfError> {
        if self.retiring != Some(receipt.id) || self.retire.is_some() {
            return Err(BpfError::NotLoaded);
        }
        if let Some(handle) = receipt.consumed_candidate {
            if manager.preparation.candidate != Some(handle) {
                return Err(BpfError::NotLoaded);
            }
        }
        manager
            .admission
            .finish_managed(receipt.admission, receipt.committed)
            .map_err(map_admission_error)?;
        if receipt.consumed_candidate.is_some() {
            manager.preparation.candidate = None;
        }
        manager.managed_slot_busy = false;
        self.retiring = None;
        Ok(())
    }
}

/// The single batch owns both displaced state and evicted Previous until taken
/// by the worker. Even an empty first-activation batch needs a completion receipt.
pub(crate) struct RetireBatch {
    id: u64,
    admission: ManagedAdmissionReservation,
    committed: bool,
    instance: Option<(u64, Arc<BehaviorInstance>)>,
    artifact: Option<ArtifactRef>,
    evict_artifact: bool,
    failed: Option<ManagedInstanceFinishError>,
    consumed_candidate: Option<u32>,
}

pub(crate) struct Retirement {
    id: u64,
    admission: ManagedAdmissionReservation,
    committed: bool,
    instance: Option<u64>,
    artifact: Option<u32>,
    failed: Option<super::managed::FailedInstanceReceipt>,
    consumed_candidate: Option<u32>,
    releasing: bool,
}

pub(crate) struct Retired {
    id: u64,
    admission: ManagedAdmissionReservation,
    committed: bool,
    consumed_candidate: Option<u32>,
}

impl RetireBatch {
    /// Worker-only with no slot/manager lock: substantial ownership is still in
    /// manager tables, and failed construction is dropped before its refund.
    pub(crate) fn release_references(self) -> Retirement {
        let instance = self.instance.map(|(id, instance)| {
            drop(instance);
            id
        });
        let artifact = self.artifact.and_then(|artifact| {
            let handle = artifact.handle;
            drop(artifact.code);
            self.evict_artifact.then_some(handle)
        });
        Retirement {
            id: self.id,
            admission: self.admission,
            committed: self.committed,
            instance,
            artifact,
            failed: self.failed.and_then(ManagedInstanceFinishError::release),
            consumed_candidate: self.consumed_candidate,
            releasing: false,
        }
    }
}

impl Retirement {
    pub(super) fn permits_instance(&self, id: u64) -> bool {
        !self.releasing && self.instance == Some(id)
    }

    pub(super) fn permits_artifact(&self, handle: u32) -> bool {
        !self.releasing && self.instance.is_none() && self.artifact == Some(handle)
    }

    /// Bounded worker attempt. Busy retains exact outstanding IDs and charges;
    /// no second extraction is possible until the first release is refunded.
    pub(super) fn begin_release(
        &mut self,
        manager: &mut BpfManager,
    ) -> Result<Option<ManagedReclamation>, BpfError> {
        if self.releasing {
            return Err(BpfError::ObjectBusy);
        }
        if let Some(receipt) = self.failed.take() {
            // A rejected/misrouted receipt must keep this batch unavailable.
            self.releasing = true;
            manager.finish_failed_managed_instance(receipt)?;
            self.releasing = false;
        }
        let release = if let Some(id) = self.instance {
            manager.begin_retiring_instance(self, id)?
        } else if let Some(handle) = self.artifact {
            manager.begin_retiring_artifact(self, handle)?
        } else {
            return Ok(None);
        };
        self.releasing = true;
        Ok(Some(release))
    }

    pub(super) fn finish_release(
        &mut self,
        manager: &mut BpfManager,
        receipt: ReclamationReceipt,
    ) -> Result<(), BpfError> {
        if !self.releasing {
            return Err(BpfError::NotLoaded);
        }
        manager.finish_managed_reclamation(receipt)?;
        if self.instance.is_some() {
            self.instance = None;
        } else {
            self.artifact = None;
        }
        self.releasing = false;
        Ok(())
    }

    pub(crate) fn complete(self) -> Result<Retired, Self> {
        if self.releasing
            || self.instance.is_some()
            || self.artifact.is_some()
            || self.failed.is_some()
        {
            return Err(self);
        }
        Ok(Retired {
            id: self.id,
            admission: self.admission,
            committed: self.committed,
            consumed_candidate: self.consumed_candidate,
        })
    }
}

fn map_admission_error(error: ManagedAdmissionError) -> BpfError {
    match error {
        ManagedAdmissionError::Busy => BpfError::ObjectBusy,
        ManagedAdmissionError::Stale => BpfError::NotLoaded,
        ManagedAdmissionError::Budget { .. } => BpfError::AdmissionRejected,
        ManagedAdmissionError::Overflow => BpfError::ResourceLimit,
    }
}

#[cfg(test)]
#[path = "installation_tests.rs"]
mod tests;
