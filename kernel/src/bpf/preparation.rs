//! One bounded upload and accepted worker operation. No activation or actuation.
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_abi::*;
use kernel_bpf::execution::BpfError;
use kernel_bpf::signing::managed::{
    ArtifactIdentity, BundleError, EFFECT_MOTOR_PAIR, MAX_BUNDLE_BYTES,
};
use kernel_bpf::signing::SignatureVerifier;
use kernel_bpf::verifier::{BehaviorArtifact, VerificationBudget, VerifyError};

use super::{managed_allocation as charge, BpfManager};

const WORKSPACE_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Uploading,
    Queued,
    Preparing,
    Finishing,
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
}

impl PreparationState {
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
        }
    }

    fn complete(&mut self) {
        self.receipts[self.receipt_next] = Some(self.active);
        self.receipt_next = (self.receipt_next + 1) % MANAGED_TERMINAL_RECEIPTS;
        self.phase = Phase::Idle;
    }

    pub(super) fn cancel_upload_owner(&mut self, owner: u64) {
        if self.phase == Phase::Uploading && self.owner == owner {
            self.active.phase = MANAGED_OPERATION_CANCELLED;
            self.active.error = i32::from(ECANCELED) as u32;
            self.complete();
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
        if self.managed_instance_preparation.is_some()
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
            state.active.behavior_id = identity.behavior_id;
            state.active.revision = identity.revision;
            state.active.bundle_digest = *identity.bundle_digest.as_bytes();
            state.active.payload_digest = *identity.payload_digest.as_bytes();
            state.active.signer_fingerprint = *identity.signer_fingerprint.as_bytes();
            state.active.signer_public_key = identity.signer_public_key;
        }
        match result {
            Ok(handle) => {
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
        let manager = BPF_MANAGER.get().expect("managed worker after BPF init");
        let channel = READY.get().expect("managed worker channel initialized");
        loop {
            let work = with_interrupts_masked(|| {
                let mut manager = manager.lock();
                if let Some(work) = manager.take_managed_work() {
                    return Some(work);
                }
                TaskWait::block_current(channel, || drop(manager));
                None
            });
            let Some(work) = work else {
                continue;
            };
            let mut prepared = work.prepare();
            with_interrupts_masked(|| manager.lock().commit_managed_work(&prepared))
                .expect("single accepted preparation retains its ID");
            // Reject/dedup may own the last code reference. Drop with IRQs
            // enabled before refunding the operation's remaining allowance.
            drop(prepared.artifact.take());
            with_interrupts_masked(|| {
                manager
                    .lock()
                    .finish_managed_work(prepared.id, prepared.buffer)
            })
            .expect("worker returns its sole upload backing");
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
