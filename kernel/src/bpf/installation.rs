//! Exclusive fixed-slot ownership. Kernel-private until authority and correlated
//! physical handoff are wired. No timer/global-lock protocol here.
use alloc::sync::Arc;

use kernel_abi::ManagedControlContextV1;
use kernel_bpf::execution::{BpfError, ManagedInvocationResult};
use kernel_bpf::verifier::admission::{ManagedAdmissionError, ManagedAdmissionReservation};
use kernel_bpf::verifier::BehaviorArtifact;

use super::managed::{
    BehaviorInstance, InstancePreparation, ManagedInstanceFinishError, ManagedReclamation,
    PreparedInstance, ReclamationReceipt,
};
use super::BpfManager;

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
/// from spanning publication; the eventual CPU0 owner must enforce IRQ scope.
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

    /// Only for the future validated handoff caller. No public safety boolean.
    /// Modeled admission is reserved; authority, correlated sink acknowledgement,
    /// CPU0/global worker ownership and calibrated physical timing eligibility
    /// remain unresolved. Production has no caller; tests supply this boundary.
    pub(crate) fn commit_validated_handoff(&mut self, id: u64) -> Result<u64, BpfError> {
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
            manager.begin_managed_instance_reclamation_for(id)?
        } else if let Some(handle) = self.artifact {
            manager.begin_managed_artifact_reclamation(handle)?
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
