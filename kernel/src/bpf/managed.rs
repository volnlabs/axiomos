//! Kernel-owned artifacts and fresh instances; publication is a separate step.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use kernel_abi::ManagedControlContextV1;
#[cfg(test)]
use kernel_bpf::execution::BpfContext;
use kernel_bpf::execution::{BpfError, Interpreter, ManagedInvocationResult};
use kernel_bpf::maps::ArrayMap;
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::{BehaviorArtifact, LoadCaller, MapPerm};

use super::{
    handles, managed_allocation as charge, BpfLoadAuthorization, BpfManager, MapAccess, MapEntry,
    MapGrants, MapRuntime, ObjectOwner, ProgramEntry, ProgramMapRuntime, ProgramObject,
    ENVELOPE_MAP_ID,
};

/// One fresh controller state. Retained artifacts contain no instance or map.
/// No public constructor can substitute different sizes or permissions for the
/// contract against which this code was verified.
pub struct BehaviorInstance {
    artifact: Arc<BehaviorArtifact>,
    maps: [Option<ProgramMapRuntime>; 2],
}

impl BehaviorInstance {
    pub fn artifact(&self) -> &BehaviorArtifact {
        &self.artifact
    }

    /// Capture a request through the existing CPU-local map leases and stack.
    /// The caller evaluates/submits it only after successful return. This does
    /// not implement scheduling, admission, publication or physical actuation.
    pub fn execute(
        &self,
        context: &ManagedControlContextV1,
    ) -> Result<ManagedInvocationResult, BpfError> {
        super::with_bpf_runtime(&self.maps, |stack| {
            Interpreter::<ActiveProfile>::new().execute_managed_with_stack(
                self.artifact.program(),
                context,
                stack,
            )
        })?
    }
}

pub(super) struct InstanceEntry {
    id: u64,
    instance: Arc<BehaviorInstance>,
    private_map_id: Option<u32>,
    charged_bytes: usize,
}

/// One accepted state preparation, charged while its worker is building.
/// Dropping work without finishing deliberately leaves the reservation busy;
/// the worker must always report success/failure through `finish_managed_instance`.
pub struct InstancePreparation {
    id: u64,
    artifact: Arc<BehaviorArtifact>,
    envelope: Option<ProgramMapRuntime>,
}

pub struct PreparedInstance {
    id: u64,
    result: Result<Arc<BehaviorInstance>, BpfError>,
}

pub(super) struct InstanceReservation {
    id: u64,
    slot: usize,
    instance_bytes: usize,
    pub(super) map_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReclamationKind {
    Instance {
        instance_bytes: usize,
        map_bytes: usize,
    },
    Artifact {
        program_bytes: usize,
    },
}

pub(super) struct ReclamationReservation {
    id: u64,
    kind: ReclamationKind,
}

enum ReclaimedObject {
    Instance {
        instance: InstanceEntry,
        map: Option<MapEntry>,
    },
    Artifact(ProgramEntry),
}

/// Substantial managed ownership extracted under the manager lock. Consume it
/// outside that lock to obtain the exact accounting receipt.
pub(super) struct ManagedReclamation {
    id: u64,
    kind: ReclamationKind,
    object: ReclaimedObject,
}

pub(super) struct ReclamationReceipt {
    id: u64,
    kind: ReclamationKind,
}

pub(super) struct FailedInstanceReceipt {
    id: u64,
}

impl ManagedReclamation {
    pub(super) fn release(self) -> ReclamationReceipt {
        let Self { id, kind, object } = self;
        match object {
            ReclaimedObject::Instance { instance, map } => {
                drop(instance);
                drop(map);
            }
            ReclaimedObject::Artifact(artifact) => drop(artifact),
        }
        ReclamationReceipt { id, kind }
    }
}

pub(super) struct ManagedInstanceFinishError {
    error: BpfError,
    rejected: Option<Arc<BehaviorInstance>>,
    reservation_id: Option<u64>,
}

impl core::fmt::Debug for ManagedInstanceFinishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ManagedInstanceFinishError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl ManagedInstanceFinishError {
    pub(super) const fn error(&self) -> BpfError {
        self.error
    }

    /// Drop a rejected completed instance outside `BPF_MANAGER`, then return
    /// the opaque reservation token needed for the short accounting refund.
    pub(super) fn release(self) -> Option<FailedInstanceReceipt> {
        drop(self.rejected);
        self.reservation_id.map(|id| FailedInstanceReceipt { id })
    }
}

impl InstancePreparation {
    pub(super) fn id(&self) -> u64 {
        self.id
    }

    /// Consumes the permit exactly once, outside BPF_MANAGER and with IRQs
    /// enabled. Failure drops all candidate allocations before reporting it.
    pub fn build(self) -> PreparedInstance {
        self.build_with(|| Ok(()))
    }

    fn build_with(self, mut allocation: impl FnMut() -> Result<(), BpfError>) -> PreparedInstance {
        let result = (|| {
            let private = if let Some(array) = self.artifact.contract().private_array() {
                allocation()?;
                let map =
                    ArrayMap::<ActiveProfile>::with_entries(array.value_size, array.max_entries)
                        .map_err(|_| BpfError::OutOfMemory)?;
                if Some(map.storage_bytes())
                    != ArrayMap::<ActiveProfile>::allocation_size(
                        array.value_size,
                        array.max_entries,
                    )
                {
                    return Err(BpfError::ResourceLimit);
                }
                allocation()?;
                let boxed = Box::try_new(map).map_err(|_| BpfError::OutOfMemory)?;
                allocation()?;
                let runtime =
                    Arc::try_new(MapRuntime::new(boxed)).map_err(|_| BpfError::OutOfMemory)?;
                Some(ProgramMapRuntime {
                    generation: 0,
                    perm: MapPerm::ReadWrite,
                    runtime,
                })
            } else {
                None
            };
            allocation()?;
            Arc::try_new(BehaviorInstance {
                artifact: self.artifact,
                maps: [self.envelope, private],
            })
            .map_err(|_| BpfError::OutOfMemory)
        })();
        PreparedInstance {
            id: self.id,
            result,
        }
    }

    /// Cancel before building, dropping references before the refund is applied.
    pub fn cancel(self) -> PreparedInstance {
        PreparedInstance {
            id: self.id,
            result: Err(BpfError::ObjectBusy),
        }
    }
}

fn sum(a: usize, b: usize) -> Result<usize, BpfError> {
    a.checked_add(b).ok_or(BpfError::ResourceLimit)
}

fn table_charge<T>(capacity: usize) -> Result<usize, BpfError> {
    charge::buffer(
        capacity
            .checked_mul(size_of::<T>())
            .ok_or(BpfError::ResourceLimit)?,
    )
}

fn empty_table<T>(capacity: usize) -> Result<Vec<T>, BpfError> {
    let mut table = Vec::new();
    table
        .try_reserve_exact(capacity)
        .map_err(|_| BpfError::OutOfMemory)?;
    if table.capacity() != capacity {
        return Err(BpfError::ResourceLimit);
    }
    Ok(table)
}

impl BpfManager {
    /// Worker/boot preparation before managed execution: reserve the existing
    /// handle tables once, including their charge. No objects are published on
    /// failure and no table allocation is needed by later managed registration.
    pub fn prepare_managed_storage(&mut self) -> Result<(), BpfError> {
        if self.managed_tables.is_some() {
            return Ok(());
        }
        let pc = self.limits.max_program_slots;
        let mc = self.limits.max_map_slots;
        if self.programs.len() > pc || self.maps.len() > mc {
            return Err(BpfError::ResourceLimit);
        }
        let p = sum(
            table_charge::<Option<ProgramEntry>>(pc)?,
            table_charge::<u32>(pc)?,
        )?;
        let m = sum(
            table_charge::<Option<MapEntry>>(mc)?,
            table_charge::<u32>(mc)?,
        )?;
        let old_p = sum(
            table_charge::<Option<ProgramEntry>>(self.programs.capacity())?,
            table_charge::<u32>(self.program_generations.capacity())?,
        )?;
        let old_m = sum(
            table_charge::<Option<MapEntry>>(self.maps.capacity())?,
            table_charge::<u32>(self.map_generations.capacity())?,
        )?;
        // Old and replacement buffers coexist until the final infallible move.
        if sum(sum(self.program_bytes, p)?, old_p)? > self.limits.max_program_bytes
            || sum(sum(self.map_bytes, m)?, old_m)? > self.limits.max_map_bytes
        {
            return Err(BpfError::ResourceLimit);
        }
        let mut programs = empty_table(pc)?;
        let mut program_generations = empty_table(pc)?;
        let mut maps = empty_table(mc)?;
        let mut map_generations = empty_table(mc)?;
        programs.append(&mut self.programs);
        program_generations.append(&mut self.program_generations);
        maps.append(&mut self.maps);
        map_generations.append(&mut self.map_generations);
        self.programs = programs;
        self.program_generations = program_generations;
        self.maps = maps;
        self.map_generations = map_generations;
        self.program_bytes += p;
        self.map_bytes += m;
        self.managed_tables = Some((p, m));
        Ok(())
    }

    /// Accept verified/authenticated code into the existing program table.
    /// The preparation worker must reserve its upload/workspace allowance before
    /// constructing `artifact`. Save `artifact.output_charge()` before the move;
    /// release that output charge from the originating VerificationBudget after
    /// EVERY return, including deduplication and rejection. Success transfers
    /// code into this manager's charge; all other outcomes drop the input code.
    /// This method does not grant control-slot authority or admit execution.
    #[cfg(test)]
    pub(super) fn register_managed_artifact(
        &mut self,
        artifact: BehaviorArtifact,
    ) -> Result<u32, BpfError> {
        if self.managed_reclamation.is_some() {
            return Err(BpfError::ObjectBusy);
        }
        self.prepare_managed_storage()?;
        let runtime = Arc::try_new(artifact).map_err(|_| BpfError::OutOfMemory)?;
        self.register_managed_shared(runtime)
    }

    /// Worker commit: wrapper and handle tables already exist. The worker keeps
    /// another reference so rejection/deduplication cannot destroy code here.
    pub(super) fn register_managed_shared(
        &mut self,
        runtime: Arc<BehaviorArtifact>,
    ) -> Result<u32, BpfError> {
        if self.managed_reclamation.is_some() {
            return Err(BpfError::ObjectBusy);
        }
        if self.managed_tables.is_none() {
            return Err(BpfError::ResourceLimit);
        }
        let artifact = runtime.as_ref();
        let identity = artifact.identity();
        let mut count = 0;
        for (slot, entry) in self.programs.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            let ProgramObject::Managed(existing) = &entry.program else {
                continue;
            };
            count += 1;
            if existing.identity() == identity && existing.contract() == artifact.contract() {
                return Ok(handles::encode(slot, self.program_generations[slot]));
            }
        }
        let bytes = sum(
            charge::buffer(artifact.code_bytes())?,
            charge::arc::<BehaviorArtifact>()?,
        )?;
        let total = sum(self.program_bytes, bytes)?;
        if count >= 3
            || self.live_programs >= self.limits.max_live_programs
            || bytes > self.limits.max_single_program_bytes
            || total > self.limits.max_program_bytes
        {
            return Err(BpfError::ResourceLimit);
        }
        let wcet_cycles = artifact.wcet_cycles();
        let id = handles::insert(
            &mut self.programs,
            &mut self.program_generations,
            self.limits.max_program_slots,
            ProgramEntry {
                program: ProgramObject::Managed(runtime),
                wcet_cycles,
                charged_bytes: bytes,
                owner: ObjectOwner::KernelManaged,
                authorization: BpfLoadAuthorization::new(
                    LoadCaller::Unprivileged,
                    false,
                    MapAccess::NONE,
                ),
            },
        )?;
        self.live_programs += 1;
        self.program_bytes = total;
        Ok(id)
    }

    pub fn managed_artifact(&self, id: u32) -> Result<&Arc<BehaviorArtifact>, BpfError> {
        match &self.program_entry(id).ok_or(BpfError::NotLoaded)?.program {
            ProgramObject::Managed(artifact) => Ok(artifact),
            ProgramObject::Legacy(_) => Err(BpfError::PermissionDenied),
        }
    }

    /// Reserve one of two instances and its global bytes before the worker
    /// allocates. Legacy operations also see these charges and the reserved map
    /// slot. The numeric ID is private to this bounded preparation transaction.
    pub fn begin_managed_instance(
        &mut self,
        artifact_id: u32,
    ) -> Result<InstancePreparation, BpfError> {
        if self.managed_slot_busy
            || self.managed_instance_preparation.is_some()
            || self.managed_reclamation.is_some()
            || self.preparation.accepted()
        {
            return Err(BpfError::ObjectBusy);
        }
        let slot = self
            .managed_instances
            .iter()
            .position(Option::is_none)
            .ok_or(BpfError::ObjectBusy)?;
        let id = self
            .next_managed_preparation
            .checked_add(1)
            .ok_or(BpfError::ResourceLimit)?;
        let artifact = self.managed_artifact(artifact_id)?.clone();
        let contract = artifact.contract();
        let instance_bytes = charge::arc::<BehaviorInstance>()?;
        let program_total = sum(self.program_bytes, instance_bytes)?;
        if program_total > self.limits.max_program_bytes {
            return Err(BpfError::ResourceLimit);
        }
        let map_bytes = if let Some(array) = contract.private_array() {
            let payload = array.payload_bytes().map_err(|_| BpfError::ResourceLimit)? as usize;
            let bytes = sum(
                sum(
                    charge::buffer(payload)?,
                    charge::boxed::<ArrayMap<ActiveProfile>>()?,
                )?,
                charge::arc::<MapRuntime>()?,
            )?;
            let has_slot = self.maps.len() < self.limits.max_map_slots
                || self
                    .maps
                    .iter()
                    .enumerate()
                    .any(|(i, e)| e.is_none() && handles::can_reuse(self.map_generations[i]));
            if self.live_maps >= self.limits.max_live_maps
                || !has_slot
                || bytes > self.limits.max_single_map_bytes
                || sum(self.map_bytes, bytes)? > self.limits.max_map_bytes
            {
                return Err(BpfError::ResourceLimit);
            }
            bytes
        } else {
            0
        };
        let envelope = if contract.envelope() {
            let entry = self.map_entry(ENVELOPE_MAP_ID).ok_or(BpfError::NotLoaded)?;
            let def = entry.runtime.map.def();
            if entry.owner != ObjectOwner::Reserved
                || entry.perm != MapPerm::ReadOnly
                || def.key_size != 4
                || def.value_size as usize != size_of::<kernel_bpf::actuation::EnvelopeEntry>()
            {
                return Err(BpfError::PermissionDenied);
            }
            Some(ProgramMapRuntime {
                generation: 0,
                perm: MapPerm::ReadOnly,
                runtime: entry.runtime.clone(),
            })
        } else {
            None
        };
        self.program_bytes = program_total;
        self.map_bytes += map_bytes;
        self.next_managed_preparation = id;
        self.managed_instance_preparation = Some(InstanceReservation {
            id,
            slot,
            instance_bytes,
            map_bytes,
        });
        Ok(InstancePreparation {
            id,
            artifact,
            envelope,
        })
    }

    /// Commit prepared state or refund a failed/cancelled build. The successful
    /// path only moves preallocated objects, with all rejection before mutation.
    /// This is instance registration; installation publication remains separate.
    pub(super) fn finish_managed_instance(
        &mut self,
        prepared: PreparedInstance,
    ) -> Result<Arc<BehaviorInstance>, ManagedInstanceFinishError> {
        let PreparedInstance {
            id: prepared_id,
            result,
        } = prepared;
        let Some(reservation) = self
            .managed_instance_preparation
            .as_ref()
            .filter(|r| r.id == prepared_id)
        else {
            return Err(ManagedInstanceFinishError {
                error: BpfError::NotLoaded,
                rejected: result.ok(),
                reservation_id: None,
            });
        };
        let reservation_id = reservation.id;
        let instance = match result {
            Ok(instance) => instance,
            Err(error) => {
                self.program_bytes -= reservation.instance_bytes;
                self.map_bytes -= reservation.map_bytes;
                self.managed_instance_preparation = None;
                return Err(ManagedInstanceFinishError {
                    error,
                    rejected: None,
                    reservation_id: None,
                });
            }
        };
        let private_map_id = if let Some(private) = &instance.maps[1] {
            let has_slot = self.maps.len() < self.limits.max_map_slots
                || self.maps.iter().enumerate().any(|(slot, entry)| {
                    entry.is_none() && handles::can_reuse(self.map_generations[slot])
                });
            if !has_slot {
                return Err(ManagedInstanceFinishError {
                    error: BpfError::ResourceLimit,
                    rejected: Some(instance),
                    reservation_id: Some(reservation_id),
                });
            }
            let insertion = handles::insert(
                &mut self.maps,
                &mut self.map_generations,
                self.limits.max_map_slots,
                MapEntry {
                    runtime: private.runtime.clone(),
                    perm: MapPerm::ReadWrite,
                    charged_bytes: reservation.map_bytes,
                    owner: ObjectOwner::KernelManaged,
                    grants: MapGrants::new(),
                },
            );
            match insertion {
                Ok(id) => Some(id),
                Err(error) => {
                    return Err(ManagedInstanceFinishError {
                        error,
                        rejected: Some(instance),
                        reservation_id: Some(reservation_id),
                    });
                }
            }
        } else {
            None
        };
        self.managed_instances[reservation.slot] = Some(InstanceEntry {
            id: prepared_id,
            instance: instance.clone(),
            private_map_id,
            charged_bytes: reservation.instance_bytes,
        });
        self.live_maps += usize::from(private_map_id.is_some());
        self.managed_instance_preparation = None;
        Ok(instance)
    }

    pub(super) fn finish_failed_managed_instance(
        &mut self,
        receipt: FailedInstanceReceipt,
    ) -> Result<(), BpfError> {
        let reservation = self
            .managed_instance_preparation
            .as_ref()
            .filter(|reservation| reservation.id == receipt.id)
            .ok_or(BpfError::NotLoaded)?;
        self.program_bytes -= reservation.instance_bytes;
        self.map_bytes -= reservation.map_bytes;
        self.managed_instance_preparation = None;
        Ok(())
    }

    #[cfg(test)]
    fn create_managed_instance(
        &mut self,
        artifact_id: u32,
    ) -> Result<Arc<BehaviorInstance>, BpfError> {
        let prepared = self.begin_managed_instance(artifact_id)?.build();
        match self.finish_managed_instance(prepared) {
            Ok(instance) => Ok(instance),
            Err(failure) => {
                let error = failure.error();
                if let Some(receipt) = failure.release() {
                    self.finish_failed_managed_instance(receipt)?;
                }
                Err(error)
            }
        }
    }

    fn next_reclamation_id(&self) -> Result<u64, BpfError> {
        if self.managed_reclamation.is_some()
            || self.managed_instance_preparation.is_some()
            || self.preparation.accepted()
        {
            return Err(BpfError::ObjectBusy);
        }
        self.next_managed_reclamation
            .checked_add(1)
            .ok_or(BpfError::ResourceLimit)
    }

    fn reserve_reclamation(&mut self, id: u64, kind: ReclamationKind) {
        self.next_managed_reclamation = id;
        self.managed_reclamation = Some(ReclamationReservation { id, kind });
    }

    /// Extract one quiescent instance and its private map under the manager
    /// lock. Destruction and accounting release are separate worker steps.
    pub(super) fn begin_managed_instance_reclamation(
        &mut self,
    ) -> Result<ManagedReclamation, BpfError> {
        let id = self
            .managed_instances
            .iter_mut()
            .find_map(|entry| {
                let entry = entry.as_mut()?;
                Arc::get_mut(&mut entry.instance).map(|_| entry.id)
            })
            .ok_or(BpfError::ObjectBusy)?;
        self.begin_managed_instance_reclamation_for(id)
    }

    /// Exact batch member; never reclaim a different available instance.
    pub(super) fn begin_managed_instance_reclamation_for(
        &mut self,
        id: u64,
    ) -> Result<ManagedReclamation, BpfError> {
        let reclamation_id = self.next_reclamation_id()?;
        let slot = self
            .managed_instances
            .iter_mut()
            .position(|entry| {
                entry.as_mut().is_some_and(|entry| {
                    entry.id == id && Arc::get_mut(&mut entry.instance).is_some()
                })
            })
            .ok_or(BpfError::ObjectBusy)?;

        let private_map_id = self.managed_instances[slot]
            .as_ref()
            .expect("selected instance exists")
            .private_map_id;
        let map_slot = if let Some(map_id) = private_map_id {
            let map_slot =
                handles::decode(&self.map_generations, map_id).ok_or(BpfError::NotLoaded)?;
            {
                let entry = self.managed_instances[slot]
                    .as_ref()
                    .expect("selected instance exists");
                let binding = entry.instance.maps[1].as_ref().ok_or(BpfError::NotLoaded)?;
                let map = self.maps[map_slot].as_ref().ok_or(BpfError::NotLoaded)?;
                if map.owner != ObjectOwner::KernelManaged
                    || !Arc::ptr_eq(&binding.runtime, &map.runtime)
                    || map
                        .runtime
                        .leased
                        .load(core::sync::atomic::Ordering::Acquire)
                {
                    return Err(BpfError::ObjectBusy);
                }
            }
            let instance = Arc::get_mut(
                &mut self.managed_instances[slot]
                    .as_mut()
                    .expect("selected instance exists")
                    .instance,
            )
            .expect("selected instance stayed unique");
            let binding = instance.maps[1].take().ok_or(BpfError::NotLoaded)?;
            let map = self.maps[map_slot]
                .as_mut()
                .expect("private map was validated before detaching binding");
            let generation = binding.generation;
            let perm = binding.perm;
            // This cannot free the map: its table entry retains a strong owner.
            drop(binding);
            if Arc::get_mut(&mut map.runtime).is_none() {
                instance.maps[1] = Some(ProgramMapRuntime {
                    generation,
                    perm,
                    runtime: map.runtime.clone(),
                });
                return Err(BpfError::ObjectBusy);
            }
            Some(map_slot)
        } else {
            None
        };

        let instance = self.managed_instances[slot]
            .take()
            .expect("selected instance exists");
        let map = map_slot.map(|slot| self.maps[slot].take().expect("private map was checked"));
        let kind = ReclamationKind::Instance {
            instance_bytes: instance.charged_bytes,
            map_bytes: map.as_ref().map_or(0, |map| map.charged_bytes),
        };
        self.reserve_reclamation(reclamation_id, kind);
        Ok(ManagedReclamation {
            id: reclamation_id,
            kind,
            object: ReclaimedObject::Instance { instance, map },
        })
    }

    /// Extract one uniquely owned artifact. Active/staged/previous and Weak
    /// references make it busy; the returned object is dropped by the worker.
    pub(super) fn begin_managed_artifact_reclamation(
        &mut self,
        artifact_id: u32,
    ) -> Result<ManagedReclamation, BpfError> {
        let reclamation_id = self.next_reclamation_id()?;
        if self.preparation.candidate == Some(artifact_id) {
            return Err(BpfError::ObjectBusy);
        }
        let slot = self.program_slot(artifact_id).ok_or(BpfError::NotLoaded)?;
        let entry = self.programs[slot].as_mut().ok_or(BpfError::NotLoaded)?;
        let ProgramObject::Managed(artifact) = &mut entry.program else {
            return Err(BpfError::PermissionDenied);
        };
        if Arc::get_mut(artifact).is_none() {
            return Err(BpfError::ObjectBusy);
        }
        let artifact = self.programs[slot].take().expect("artifact was checked");
        let kind = ReclamationKind::Artifact {
            program_bytes: artifact.charged_bytes,
        };
        self.reserve_reclamation(reclamation_id, kind);
        Ok(ManagedReclamation {
            id: reclamation_id,
            kind,
            object: ReclaimedObject::Artifact(artifact),
        })
    }

    pub(super) fn finish_managed_reclamation(
        &mut self,
        receipt: ReclamationReceipt,
    ) -> Result<(), BpfError> {
        let reservation = self
            .managed_reclamation
            .as_ref()
            .filter(|reservation| reservation.id == receipt.id && reservation.kind == receipt.kind)
            .ok_or(BpfError::NotLoaded)?;
        match reservation.kind {
            ReclamationKind::Instance {
                instance_bytes,
                map_bytes,
            } => {
                self.program_bytes -= instance_bytes;
                self.map_bytes -= map_bytes;
                self.live_maps -= usize::from(map_bytes != 0);
            }
            ReclamationKind::Artifact { program_bytes } => {
                self.program_bytes -= program_bytes;
                self.live_programs -= 1;
            }
        }
        self.managed_reclamation = None;
        Ok(())
    }

    #[cfg(test)]
    pub fn reclaim_managed_instances(&mut self) -> usize {
        let mut reclaimed = 0;
        while let Ok(reclamation) = self.begin_managed_instance_reclamation() {
            let receipt = reclamation.release();
            self.finish_managed_reclamation(receipt)
                .expect("matching reclamation receipt");
            reclaimed += 1;
        }
        reclaimed
    }

    #[cfg(test)]
    pub fn retire_managed_artifact(&mut self, id: u32) -> Result<(), BpfError> {
        let reclamation = self.begin_managed_artifact_reclamation(id)?;
        let receipt = reclamation.release();
        self.finish_managed_reclamation(receipt)
    }
}

#[cfg(test)]
#[path = "managed_tests.rs"]
pub(super) mod tests;
