//! One bounded upload and accepted upload/lifecycle operation on one worker.
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_abi::*;
use kernel_bpf::execution::BpfError;
use kernel_bpf::signing::managed::{
    ArtifactIdentity, BundleError, EFFECT_MOTOR_PAIR, MAX_BUNDLE_BYTES,
};
use kernel_bpf::signing::SignatureVerifier;
use kernel_bpf::verifier::{BehaviorArtifact, VerificationBudget, VerifyError};

use super::installation::{ControlSlot, InstallationPreparation, RetireBatch, Retirement};
use super::managed::ManagedReclamation;
use super::{managed_allocation as charge, BpfManager};

const WORKSPACE_BYTES: usize = 512 * 1024;

fn retain_identity(operation: &mut ManagedOperationV1, identity: ArtifactIdentity) {
    operation.behavior_id = identity.behavior_id;
    operation.revision = identity.revision;
    operation.bundle_digest = *identity.bundle_digest.as_bytes();
    operation.payload_digest = *identity.payload_digest.as_bytes();
    operation.signer_fingerprint = *identity.signer_fingerprint.as_bytes();
    operation.signer_public_key = identity.signer_public_key;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Uploading,
    Queued,
    Preparing,
    Finishing,
    Lifecycle,
}

pub(super) struct PreparationState {
    buffer: Option<Vec<u8>>,
    phase: Phase,
    last_id: u64,
    owner: u64,
    active: ManagedOperationV1,
    receipts: [Option<ManagedOperationV1>; MANAGED_TERMINAL_RECEIPTS],
    receipt_next: usize,
    workspace: usize,
    cancelled: bool,
    pub(super) candidate: Option<u32>,
    installation: Option<InstallationPreparation>,
    lifecycle: Option<Lifecycle>,
}

impl PreparationState {
    pub(super) fn upload_accepted(&self) -> bool {
        matches!(
            self.phase,
            Phase::Queued | Phase::Preparing | Phase::Finishing
        )
    }

    pub(super) fn new() -> Self {
        Self {
            buffer: None,
            phase: Phase::Idle,
            last_id: 0,
            owner: 0,
            active: ManagedOperationV1::default(),
            receipts: [None; MANAGED_TERMINAL_RECEIPTS],
            receipt_next: 0,
            workspace: 0,
            cancelled: false,
            candidate: None,
            installation: None,
            lifecycle: None,
        }
    }

    fn complete(&mut self) {
        self.receipts[self.receipt_next] = Some(self.active);
        self.receipt_next = (self.receipt_next + 1) % MANAGED_TERMINAL_RECEIPTS;
        self.phase = Phase::Idle;
        self.lifecycle = None;
    }

    pub(super) fn cancel_upload_owner(&mut self, owner: u64) {
        if self.phase == Phase::Uploading && self.owner == owner {
            self.active.phase = MANAGED_OPERATION_CANCELLED;
            self.active.error = i32::from(ECANCELED) as u32;
            self.complete();
        }
    }
}

/// The upload operation ID and the instance cleanup ID are independent counters.
#[derive(Clone, Copy)]
struct Lifecycle {
    instance_id: u64,
    generation: u64,
    target: LifecycleTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleTarget {
    Candidate(u32),
    Previous(u32),
    Deactivate(u32),
}

impl LifecycleTarget {
    fn handle(self) -> u32 {
        match self {
            Self::Candidate(handle) | Self::Previous(handle) | Self::Deactivate(handle) => handle,
        }
    }
}

pub(super) struct Work {
    id: u64,
    total: usize,
    buffer: Vec<u8>,
    trust: Arc<SignatureVerifier>,
}

pub(super) struct PreparedWork {
    id: u64,
    buffer: Vec<u8>,
    artifact: Option<Arc<BehaviorArtifact>>,
    identity: Option<ArtifactIdentity>,
    error: Option<Errno>,
    peak: usize,
}

fn resource_error(error: BpfError) -> Errno {
    match error {
        BpfError::ObjectBusy => EBUSY,
        BpfError::NotLoaded => ESTALE,
        BpfError::PermissionDenied => EPERM,
        _ => ENOMEM,
    }
}

impl Work {
    /// All hashing, verification, wrapper allocation and scratch destruction
    /// happen here with no manager lock and with interrupts enabled.
    pub(super) fn prepare(self) -> PreparedWork {
        let mut result = PreparedWork {
            id: self.id,
            buffer: self.buffer,
            artifact: None,
            identity: None,
            error: None,
            peak: 0,
        };
        let prepare = (|| {
            let header = charge::arc::<BehaviorArtifact>().map_err(resource_error)?;
            let mut budget =
                VerificationBudget::with_allocator_policy(WORKSPACE_BYTES - header, 16, 8)
                    .map_err(|_| ENOMEM)?;
            let bundle = self
                .trust
                .authenticate_managed(&result.buffer[..self.total])
                .map_err(|error| match error {
                    BundleError::Malformed => EINVAL,
                    BundleError::Unsupported => ENOTSUP,
                    BundleError::Capacity => ENOMEM,
                    BundleError::Authentication(_) => EACCES,
                })?;
            result.identity = Some(bundle.identity());
            // The boot-provisioned trust roots may request only this fixed slot's
            // wheel-pair effect. BEHAVIOR_ADMIN never supplies an effect ceiling.
            let artifact = BehaviorArtifact::prepare(
                &bundle,
                EFFECT_MOTOR_PAIR,
                EFFECT_MOTOR_PAIR,
                &mut budget,
            );
            result.peak = budget.high_water();
            let artifact = artifact.map_err(|error| match error {
                VerifyError::ResourceExhausted => ENOMEM,
                _ => ENOEXEC,
            })?;
            let output = artifact.output_charge();
            let runtime = Arc::try_new(artifact).map_err(|_| ENOMEM);
            budget.release_output(output).map_err(|_| ENOMEM)?;
            result.artifact = Some(runtime?);
            result.peak = result.peak.max(output + header);
            Ok(())
        })();
        result.error = prepare.err();
        result
    }
}

impl BpfManager {
    /// Boot-only before starting the permanent worker. The fixed upload backing
    /// stays charged even when idle; chunks never allocate or resize it.
    pub fn enable_managed_preparation(&mut self) -> Result<(), BpfError> {
        if self.preparation.phase != Phase::Idle {
            return Err(BpfError::ObjectBusy);
        }
        if self.preparation.buffer.is_some() {
            return Ok(());
        }
        self.prepare_managed_storage()?;
        let bytes = charge::buffer(MAX_BUNDLE_BYTES)?;
        let total = self
            .program_bytes
            .checked_add(bytes)
            .ok_or(BpfError::ResourceLimit)?;
        if total > self.limits.max_program_bytes {
            return Err(BpfError::ResourceLimit);
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(MAX_BUNDLE_BYTES)
            .map_err(|_| BpfError::OutOfMemory)?;
        if buffer.capacity() != MAX_BUNDLE_BYTES {
            return Err(BpfError::ResourceLimit);
        }
        buffer.resize(MAX_BUNDLE_BYTES, 0);
        self.preparation.buffer = Some(buffer);
        self.program_bytes = total;
        Ok(())
    }

    pub fn managed_upload_begin(
        &mut self,
        owner: u64,
        expected_last_id: u64,
        total: u32,
    ) -> Result<u64, Errno> {
        let state = &mut self.preparation;
        if state.candidate.is_some() || self.managed_slot_busy || self.managed_reclamation.is_some()
        {
            return Err(EBUSY);
        }
        if state.phase != Phase::Idle {
            return Err(EBUSY);
        }
        if state.buffer.is_none() {
            return Err(ENODEV);
        }
        if expected_last_id != state.last_id {
            return Err(ESTALE);
        }
        if total == 0 || total as usize > MAX_BUNDLE_BYTES {
            return Err(EINVAL);
        }
        let id = state
            .last_id
            .checked_add(1)
            .filter(|id| *id <= isize::MAX as u64)
            .ok_or(EOVERFLOW)?;
        state.active = ManagedOperationV1 {
            version: MANAGED_ADMIN_VERSION,
            size: core::mem::size_of::<ManagedOperationV1>() as u32,
            id,
            phase: MANAGED_OPERATION_UPLOADING,
            total_bytes: total,
            ..Default::default()
        };
        state.last_id = id;
        state.owner = owner;
        state.cancelled = false;
        state.phase = Phase::Uploading;
        Ok(id)
    }

    pub fn managed_upload_chunk(
        &mut self,
        owner: u64,
        id: u64,
        offset: u32,
        bytes: &[u8],
    ) -> Result<u32, Errno> {
        let state = &mut self.preparation;
        if state.phase != Phase::Uploading || state.active.id != id {
            return Err(ESTALE);
        }
        if state.owner != owner {
            return Err(EPERM);
        }
        if bytes.is_empty() || bytes.len() > MANAGED_UPLOAD_CHUNK_BYTES {
            return Err(EINVAL);
        }
        let end = (offset as usize)
            .checked_add(bytes.len())
            .filter(|end| *end <= state.active.total_bytes as usize)
            .ok_or(EINVAL)?;
        let received = state.active.received_bytes as usize;
        let buffer = state.buffer.as_mut().ok_or(ENODEV)?;
        if (offset as usize) < received {
            return if end <= received && buffer[offset as usize..end] == *bytes {
                Ok(received as u32)
            } else {
                Err(EINVAL)
            };
        }
        if offset as usize != received {
            return Err(EINVAL);
        }
        buffer[received..end].copy_from_slice(bytes);
        state.active.received_bytes = end as u32;
        Ok(end as u32)
    }

    pub fn managed_upload_finalize(&mut self, owner: u64, id: u64) -> Result<u64, Errno> {
        let state = &mut self.preparation;
        if state.active.id != id || id == 0 {
            return Err(ESTALE);
        }
        if state.phase == Phase::Lifecycle {
            return Err(ENOTSUP);
        }
        if state.phase != Phase::Uploading {
            // A lost finalize response is recovered by query or an exact retry.
            return if state.phase != Phase::Idle {
                Ok(id)
            } else {
                Err(EALREADY)
            };
        }
        if state.owner != owner {
            return Err(EPERM);
        }
        if state.active.received_bytes != state.active.total_bytes {
            return Err(EINVAL);
        }
        // Authentication has not established whether this upload is a duplicate.
        // Reserve room for its transient artifact before the worker can build it.
        if self
            .programs
            .iter()
            .flatten()
            .filter(|entry| matches!(entry.program, super::ProgramObject::Managed(_)))
            .count()
            >= 3
        {
            return Err(ENOMEM);
        }
        if state.candidate.is_some()
            || self.managed_slot_busy
            || self.managed_reclamation.is_some()
            || self.managed_instance_preparation.is_some()
            || self.managed_instances.iter().flatten().count() >= 2
        {
            return Err(EBUSY);
        }
        let total = self
            .program_bytes
            .checked_add(WORKSPACE_BYTES)
            .filter(|total| *total <= self.limits.max_program_bytes)
            .ok_or(ENOMEM)?;
        self.program_bytes = total;
        state.workspace = WORKSPACE_BYTES;
        state.active.phase = MANAGED_OPERATION_QUEUED;
        state.phase = Phase::Queued;
        Ok(id)
    }

    /// Bounded acceptance: scalar receipt, table reservation and reference clones.
    /// The preallocated worker slot takes custody before the caller can exit.
    pub(crate) fn request_installation(
        &mut self,
        slot: &mut ControlSlot,
        expected_last_id: u64,
        expected_generation: u64,
        target: LifecycleTarget,
    ) -> Result<u64, Errno> {
        if expected_last_id != self.preparation.last_id
            || expected_generation != slot.snapshot().generation
        {
            return Err(ESTALE);
        }
        let snapshot = slot.snapshot();
        let exact = match target {
            LifecycleTarget::Candidate(handle) => self.preparation.candidate == Some(handle),
            LifecycleTarget::Previous(handle) => snapshot.previous == Some(handle),
            LifecycleTarget::Deactivate(handle) => snapshot.active == Some(handle),
        };
        if !exact {
            return Err(ESTALE);
        }
        if self.preparation.phase != Phase::Idle {
            return Err(EBUSY);
        }
        let id = self
            .preparation
            .last_id
            .checked_add(1)
            .filter(|id| *id <= isize::MAX as u64)
            .ok_or(EOVERFLOW)?;
        let generation = expected_generation.checked_add(1).ok_or(EOVERFLOW)?;
        self.next_managed_preparation
            .checked_add(1)
            .ok_or(EOVERFLOW)?;
        let identity = self
            .managed_artifact(target.handle())
            .map_err(resource_error)?
            .identity();
        let (instance_id, preparation) = match target {
            LifecycleTarget::Deactivate(handle) => (
                slot.begin_deactivation(self, expected_generation, handle)
                    .map_err(resource_error)?,
                None,
            ),
            LifecycleTarget::Candidate(_) | LifecycleTarget::Previous(_) => {
                let previous = match target {
                    LifecycleTarget::Previous(handle) => Some(handle),
                    _ => None,
                };
                let preparation = slot
                    .begin(self, expected_generation, previous)
                    .map_err(resource_error)?;
                (preparation.instance_id(), Some(preparation))
            }
        };
        let lifecycle = Lifecycle {
            instance_id,
            generation,
            target,
        };
        let state = &mut self.preparation;
        state.active = ManagedOperationV1 {
            version: MANAGED_ADMIN_VERSION,
            size: core::mem::size_of::<ManagedOperationV1>() as u32,
            id,
            phase: if preparation.is_some() {
                MANAGED_OPERATION_QUEUED
            } else {
                MANAGED_OPERATION_STAGED
            },
            artifact_handle: target.handle(),
            ..Default::default()
        };
        retain_identity(&mut state.active, identity);
        state.last_id = id;
        state.owner = 0;
        state.cancelled = false;
        state.lifecycle = Some(lifecycle);
        state.installation = preparation;
        state.phase = Phase::Lifecycle;
        Ok(id)
    }

    pub(crate) fn query_installation(
        &self,
        slot: &ControlSlot,
        id: u64,
    ) -> Result<ManagedOperationV1, Errno> {
        let mut operation = self.managed_operation_query(id)?;
        if let Some(lifecycle) = self
            .preparation
            .lifecycle
            .filter(|_| operation.id == self.preparation.active.id)
        {
            if slot.snapshot().generation == lifecycle.generation {
                operation.phase = MANAGED_OPERATION_COMMITTED;
            } else if let Some(phase) =
                slot.operation_phase(lifecycle.instance_id).filter(|phase| {
                    *phase == MANAGED_OPERATION_CLEANUP
                        || self.preparation.installation.is_none()
                        || self.preparation.cancelled
                })
            {
                operation.phase = phase;
                if phase == MANAGED_OPERATION_CLEANUP {
                    operation.error = i32::from(
                        slot.operation_error(lifecycle.instance_id)
                            .unwrap_or(ECANCELED),
                    ) as u32;
                }
            }
        }
        Ok(operation)
    }

    pub(crate) fn managed_slot_query(&self, slot: &ControlSlot) -> ManagedSlotV1 {
        let snapshot = slot.snapshot();
        let lifecycle = self.preparation.lifecycle;
        let mut flags = 0;
        for (present, flag) in [
            (snapshot.active.is_some(), MANAGED_SLOT_HAS_ACTIVE),
            (snapshot.previous.is_some(), MANAGED_SLOT_HAS_PREVIOUS),
            (
                self.preparation.candidate.is_some(),
                MANAGED_SLOT_HAS_CANDIDATE,
            ),
            (lifecycle.is_some(), MANAGED_SLOT_HAS_PENDING),
            (snapshot.inhibited, MANAGED_SLOT_INHIBITED),
            (snapshot.retiring, MANAGED_SLOT_RETIRING),
        ] {
            if present {
                flags |= flag;
            }
        }
        ManagedSlotV1 {
            version: MANAGED_ADMIN_VERSION,
            size: core::mem::size_of::<ManagedSlotV1>() as u32,
            last_id: self.preparation.last_id,
            generation: snapshot.generation,
            pending_id: lifecycle.map_or(0, |_| self.preparation.active.id),
            active_charge_ns_per_s: snapshot.active_charge_ns_per_s.unwrap_or(0),
            active_artifact: snapshot.active.unwrap_or(0),
            previous_artifact: snapshot.previous.unwrap_or(0),
            candidate_artifact: self.preparation.candidate.unwrap_or(0),
            flags,
            pending_target_kind: lifecycle.map_or(0, |operation| match operation.target {
                LifecycleTarget::Candidate(_) => MANAGED_TARGET_CANDIDATE,
                LifecycleTarget::Previous(_) => MANAGED_TARGET_PREVIOUS,
                LifecycleTarget::Deactivate(_) => MANAGED_TARGET_DEACTIVATE,
            }),
            reserved: 0,
        }
    }

    pub(crate) fn cancel_installation(
        &mut self,
        slot: &mut ControlSlot,
        id: u64,
        expected_generation: u64,
        target: LifecycleTarget,
    ) -> Result<(), Errno> {
        if id == 0 || self.preparation.active.id != id {
            return Err(ESTALE);
        }
        let lifecycle = self.preparation.lifecycle.ok_or(EALREADY)?;
        if lifecycle.target != target || lifecycle.generation - 1 != expected_generation {
            return Err(ESTALE);
        }
        if slot.snapshot().generation == lifecycle.generation {
            return Err(EALREADY);
        }
        if self.preparation.cancelled {
            return Ok(());
        }
        slot.cancel(lifecycle.instance_id).map_err(resource_error)?;
        let error = slot
            .operation_error(lifecycle.instance_id)
            .unwrap_or(ECANCELED);
        self.preparation.cancelled = error == ECANCELED;
        self.preparation.active.phase = MANAGED_OPERATION_CLEANUP;
        self.preparation.active.error = i32::from(error) as u32;
        Ok(())
    }

    pub fn managed_operation_query(&self, id: u64) -> Result<ManagedOperationV1, Errno> {
        let state = &self.preparation;
        let id = if id == 0 { state.last_id } else { id };
        if state.phase != Phase::Idle && state.active.id == id {
            return Ok(state.active);
        }
        if id == 0 {
            return Ok(ManagedOperationV1 {
                version: MANAGED_ADMIN_VERSION,
                size: core::mem::size_of::<ManagedOperationV1>() as u32,
                ..Default::default()
            });
        }
        state
            .receipts
            .iter()
            .flatten()
            .find(|receipt| receipt.id == id)
            .copied()
            .ok_or(ESTALE)
    }

    pub fn managed_operation_cancel(&mut self, owner: u64, id: u64) -> Result<(), Errno> {
        let state = &mut self.preparation;
        if id == 0 || state.active.id != id {
            return Err(ESTALE);
        }
        match state.phase {
            Phase::Uploading => {
                if state.owner != owner {
                    return Err(EPERM);
                }
                state.cancel_upload_owner(owner);
            }
            Phase::Queued | Phase::Preparing => state.cancelled = true,
            // Lifecycle cancellation also needs the slot lock and exact target.
            Phase::Lifecycle => return Err(ENOTSUP),
            Phase::Idle | Phase::Finishing => return Err(EALREADY),
        }
        Ok(())
    }

    pub(super) fn take_managed_work(&mut self) -> Option<Work> {
        let state = &mut self.preparation;
        if state.phase != Phase::Queued {
            return None;
        }
        let buffer = state.buffer.take()?;
        state.phase = Phase::Preparing;
        state.active.phase = MANAGED_OPERATION_PREPARING;
        Some(Work {
            id: state.active.id,
            total: state.active.total_bytes as usize,
            buffer,
            trust: self.signature_verifier.clone(),
        })
    }

    /// Short worker commit. A second reference in `work` keeps rejected code
    /// alive until the worker drops it outside this lock. Workspace is refunded
    /// only by finish_managed_work after that actual drop.
    pub(super) fn commit_managed_work(&mut self, work: &PreparedWork) -> Result<(), Errno> {
        if self.preparation.phase != Phase::Preparing || self.preparation.active.id != work.id {
            return Err(ESTALE);
        }
        let result = if self.preparation.cancelled {
            Err(ECANCELED)
        } else if let Some(error) = work.error {
            Err(error)
        } else {
            let artifact = work.artifact.as_ref().ok_or(ENOEXEC)?;
            let reserved = self.preparation.workspace;
            let base = self.program_bytes - reserved;
            self.program_bytes = base;
            let result = self
                .register_managed_shared(artifact.clone())
                .map_err(resource_error);
            let transferred = self.program_bytes - base;
            self.preparation.workspace -= transferred;
            self.program_bytes += self.preparation.workspace;
            result
        };
        let state = &mut self.preparation;
        state.phase = Phase::Finishing;
        state.active.workspace_peak = work.peak as u64;
        if let Some(identity) = work.identity {
            retain_identity(&mut state.active, identity);
        }
        match result {
            Ok(handle) => {
                state.candidate = Some(handle);
                state.active.artifact_handle = handle;
                state.active.phase = MANAGED_OPERATION_RESIDENT;
            }
            Err(error) => {
                state.active.error = i32::from(error) as u32;
                state.active.phase = if error == ECANCELED {
                    MANAGED_OPERATION_CANCELLED
                } else {
                    MANAGED_OPERATION_FAILED
                };
            }
        }
        Ok(())
    }

    pub(super) fn finish_managed_work(&mut self, id: u64, buffer: Vec<u8>) -> Result<(), Errno> {
        let state = &mut self.preparation;
        if state.phase != Phase::Finishing || state.active.id != id || state.buffer.is_some() {
            return Err(ESTALE);
        }
        state.buffer = Some(buffer);
        self.program_bytes -= state.workspace;
        state.workspace = 0;
        state.complete();
        Ok(())
    }
}

/// Fixed custody owned by the one permanent task, including reader-Busy retries.
#[derive(Default)]
pub(super) struct WorkerState {
    retirement: Option<Retirement>,
}

pub(super) enum WorkerAction {
    Upload(Work),
    Install(InstallationPreparation, bool),
    Retire(RetireBatch),
    Release(ManagedReclamation),
    Wait,
    Retry,
}

impl WorkerState {
    /// Called with slot-before-manager locks and IRQs masked. Only moves owners.
    pub(super) fn take(
        &mut self,
        slot: &mut ControlSlot,
        manager: &mut BpfManager,
    ) -> WorkerAction {
        if let Some(work) = manager.take_managed_work() {
            return WorkerAction::Upload(work);
        }
        if let Some(lifecycle) = manager.preparation.lifecycle {
            if slot.operation_phase(lifecycle.instance_id) == Some(MANAGED_OPERATION_CLEANUP) {
                let error = slot
                    .operation_error(lifecycle.instance_id)
                    .unwrap_or(ECANCELED);
                manager.preparation.cancelled = error == ECANCELED;
                manager.preparation.active.phase = MANAGED_OPERATION_CLEANUP;
                manager.preparation.active.error = i32::from(error) as u32;
            }
        }
        if let Some(preparation) = manager.preparation.installation.take() {
            let abandon = slot.operation_error(preparation.instance_id()).is_some();
            if !abandon {
                manager.preparation.active.phase = MANAGED_OPERATION_PREPARING;
            }
            return WorkerAction::Install(preparation, abandon);
        }
        if manager.preparation.lifecycle.is_some() {
            slot.abort_cancelled();
            let operation = manager
                .query_installation(slot, manager.preparation.active.id)
                .unwrap();
            manager.preparation.active.phase = operation.phase;
        }
        if let Some(batch) = slot.take_retirement() {
            assert!(self.retirement.is_none());
            return WorkerAction::Retire(batch);
        }
        if let Some(retirement) = &mut self.retirement {
            match retirement.begin_release(manager) {
                Ok(Some(release)) => return WorkerAction::Release(release),
                Err(BpfError::ObjectBusy) => return WorkerAction::Retry,
                Err(error) => {
                    panic!("accepted retirement must retain its exact reservation: {error:?}")
                }
                Ok(None) => {}
            }
            let retirement = self.retirement.take().unwrap();
            let receipt = retirement
                .complete()
                .ok()
                .expect("no outstanding retirement member");
            slot.finish_retirement(manager, receipt)
                .expect("worker settles reserved admission after actual release");
            let state = &mut manager.preparation;
            if let Some(lifecycle) = state.lifecycle {
                state.active.phase = if slot.snapshot().generation == lifecycle.generation {
                    MANAGED_OPERATION_COMMITTED
                } else if state.cancelled {
                    MANAGED_OPERATION_CANCELLED
                } else {
                    MANAGED_OPERATION_FAILED
                };
                state.complete();
            }
        }
        WorkerAction::Wait
    }

    /// Shared by the real task and host tests. Allocations/destruction occur
    /// before entering these short registration/refund critical sections.
    pub(super) fn perform(
        &mut self,
        action: WorkerAction,
        slot: &spin::Mutex<ControlSlot>,
        manager: &spin::Mutex<BpfManager>,
    ) {
        use crate::mcore::context::with_interrupts_masked;
        match action {
            WorkerAction::Upload(work) => {
                let mut prepared = work.prepare();
                with_interrupts_masked(|| manager.lock().commit_managed_work(&prepared))
                    .expect("single accepted upload retains its ID");
                drop(prepared.artifact.take());
                with_interrupts_masked(|| {
                    manager
                        .lock()
                        .finish_managed_work(prepared.id, prepared.buffer)
                })
                .expect("worker returns its sole upload backing");
            }
            WorkerAction::Install(preparation, cancelled) => {
                let built = if cancelled {
                    preparation.cancel()
                } else {
                    preparation.build()
                };
                with_interrupts_masked(|| {
                    let mut slot = slot.lock();
                    let mut manager = manager.lock();
                    if let Some(error) =
                        slot.operation_error(manager.preparation.lifecycle.unwrap().instance_id)
                    {
                        manager.preparation.cancelled = error == ECANCELED;
                        manager.preparation.active.error = i32::from(error) as u32;
                    }
                    let result = slot.finish_build(&mut manager, built);
                    manager.preparation.active.phase = if result.is_ok() {
                        MANAGED_OPERATION_STAGED
                    } else {
                        MANAGED_OPERATION_CLEANUP
                    };
                    if let Err(error) = result {
                        if manager.preparation.active.error == 0 {
                            manager.preparation.active.error =
                                i32::from(if manager.preparation.cancelled {
                                    ECANCELED
                                } else {
                                    resource_error(error)
                                }) as u32;
                        }
                    }
                });
            }
            WorkerAction::Retire(batch) => {
                assert!(self.retirement.is_none());
                self.retirement = Some(batch.release_references());
            }
            WorkerAction::Release(release) => {
                let receipt = release.release();
                with_interrupts_masked(|| {
                    self.retirement
                        .as_mut()
                        .unwrap()
                        .finish_release(&mut manager.lock(), receipt)
                })
                .expect("worker refunds only its released batch member");
            }
            WorkerAction::Wait | WorkerAction::Retry => unreachable!("scheduler handles waiting"),
        }
    }
}

#[cfg(feature = "managed-runtime")]
mod worker {
    use alloc::boxed::Box;
    use alloc::sync::Arc;

    use conquer_once::spin::OnceCell;

    use crate::mcore::context::with_interrupts_masked;
    use crate::mcore::mtask::process::Process;
    use crate::mcore::mtask::scheduler::run_queue::RunQueues;
    use crate::mcore::mtask::scheduler::wait::{TaskWait, WaitChannel};
    use crate::mcore::mtask::task::Task;
    use crate::BPF_MANAGER;

    static READY: OnceCell<Arc<WaitChannel>> = OnceCell::uninit();

    /// Boot construction only, after scheduler initialization. Candidate
    /// preparation reuses this permanent task and its wait queue.
    pub(crate) fn init() {
        READY.init_once(|| Arc::new(WaitChannel::new()));
        let task = Task::create_new(Process::root(), run, core::ptr::null_mut())
            .expect("managed preparation worker boot allocation");
        RunQueues::enqueue(Box::pin(task));
    }

    pub(crate) fn wake() {
        if let Some(channel) = READY.get() {
            channel.wake_all();
        }
    }

    extern "C" fn run(_: *mut core::ffi::c_void) {
        use super::{WorkerAction, WorkerState};
        use crate::bpf::installation::CONTROL_SLOT;
        use crate::mcore::context::ExecutionContext;
        let manager = BPF_MANAGER.get().expect("managed worker after BPF init");
        let channel = READY.get().expect("managed worker channel initialized");
        let mut worker = WorkerState::default();
        loop {
            let action = with_interrupts_masked(|| {
                let mut slot = CONTROL_SLOT.lock();
                let mut manager = manager.lock();
                let action = worker.take(&mut slot, &mut manager);
                if matches!(action, WorkerAction::Wait) {
                    TaskWait::block_current(channel, || {
                        drop(manager);
                        drop(slot);
                    });
                }
                action
            });
            match action {
                WorkerAction::Wait => {}
                WorkerAction::Retry => {
                    // Reader/Weak release has no notification contract. Retain
                    // the exact batch and retry using the existing sleep queue.
                    let deadline = crate::time::get_monotonic_time_ns().saturating_add(1_000_000);
                    let context = ExecutionContext::load();
                    let switched = context.with_interrupts_masked(|| {
                        context.with_current_task(|task| task.begin_sleep(deadline));
                        // SAFETY: all slot/manager locks were released; IRQs are masked.
                        let switched = unsafe { context.reschedule() };
                        if !switched {
                            context.with_current_task(Task::abort_sleep_before_switch);
                        }
                        switched
                    });
                    if !switched {
                        // No runnable peer: yield to the next interrupt instead
                        // of repeatedly inspecting the same retained reader.
                        #[cfg(target_arch = "x86_64")]
                        x86_64::instructions::hlt();
                        #[cfg(target_arch = "aarch64")]
                        <crate::arch::aarch64::Aarch64 as crate::arch::traits::Architecture>::wait_for_interrupt();
                    }
                }
                action => worker.perform(action, &CONTROL_SLOT, manager),
            }
        }
    }
}

#[cfg(feature = "managed-runtime")]
pub(crate) use worker::{init, wake};

#[cfg(not(feature = "managed-runtime"))]
pub(crate) fn wake() {}

#[cfg(test)]
#[path = "preparation_tests.rs"]
mod tests;
