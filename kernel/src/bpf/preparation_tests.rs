use alloc::sync::Arc;
use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::signing::managed::{signing_hash, Manifest, PrivateArray, MANIFEST_SIZE};
use kernel_bpf::signing::{SignatureVerifier, TrustedKey};
use zerocopy::IntoBytes;

use super::*;

fn signed_bundle(revision: u64, program: &[BpfInsn]) -> (Vec<u8>, Arc<SignatureVerifier>) {
    let key = SigningKey::from_bytes(&[41; 32]);
    let payload = program.as_bytes();
    let manifest = Manifest {
        behavior_id: [9; 16],
        revision,
        envelope: false,
        effects: 0,
        private_array: Some(PrivateArray {
            value_size: 8,
            max_entries: 1,
        }),
    };
    let mut header = manifest
        .unsigned_header(payload, key.verifying_key().as_bytes())
        .unwrap();
    let signature = key.sign(signing_hash(&header).as_bytes());
    header[MANIFEST_SIZE..].copy_from_slice(&signature.to_bytes());
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(payload);
    let trust = SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(
        key.verifying_key().as_bytes(),
    )
    .unwrap()])
    .unwrap();
    (bytes, Arc::new(trust))
}

fn manager_with_upload(trust: Arc<SignatureVerifier>) -> BpfManager {
    let mut manager = BpfManager::new();
    manager.signature_verifier = trust;
    manager.enable_managed_preparation().unwrap();
    manager
}

fn upload(manager: &mut BpfManager, owner: u64, expected: u64, bytes: &[u8]) -> u64 {
    let id = manager
        .managed_upload_begin(owner, expected, bytes.len() as u32)
        .unwrap();
    for (index, chunk) in bytes.chunks(MANAGED_UPLOAD_CHUNK_BYTES).enumerate() {
        let offset = index * MANAGED_UPLOAD_CHUNK_BYTES;
        assert_eq!(
            manager
                .managed_upload_chunk(owner, id, offset as u32, chunk)
                .unwrap(),
            (offset + chunk.len()) as u32
        );
    }
    id
}

fn prepare_and_commit(manager: &mut BpfManager, id: u64) -> (PreparedWork, usize) {
    manager.managed_upload_finalize(7, id).unwrap();
    let charged = manager.resource_usage().program_bytes;
    let work = manager.take_managed_work().unwrap();
    let prepared = work.prepare();
    manager.commit_managed_work(&prepared).unwrap();
    (prepared, charged)
}

fn finish(manager: &mut BpfManager, prepared: PreparedWork) {
    let PreparedWork {
        id,
        buffer,
        artifact,
        ..
    } = prepared;
    drop(artifact);
    manager.finish_managed_work(id, buffer).unwrap();
}

// These pre-slot tests deliberately retain unassigned low-level artifacts to
// exercise workspace/dedup/reclamation. Installation tests cover real role moves.
fn unassign_candidate_fixture(manager: &mut BpfManager) {
    manager.preparation.candidate = None;
}

#[test]
fn managed_preparation_begin_ids_and_counter_exhaustion_are_fail_closed() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let floor = manager.resource_usage();
    let first = manager
        .managed_upload_begin(7, 0, bytes.len() as u32)
        .unwrap();
    assert_eq!(first, 1);
    assert_eq!(manager.managed_upload_begin(7, 0, 8), Err(EBUSY));
    assert!(manager.reclaim_owner(7));
    manager.preparation.last_id = isize::MAX as u64;
    assert_eq!(
        manager.managed_upload_begin(7, isize::MAX as u64, 8),
        Err(EOVERFLOW)
    );
    assert_eq!(manager.resource_usage(), floor);
}

#[test]
fn managed_preparation_chunks_are_ordered_bounded_and_exact_replays_only() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let id = manager
        .managed_upload_begin(7, 0, bytes.len() as u32)
        .unwrap();
    let split = bytes.len().min(17);
    assert_eq!(
        manager.managed_upload_chunk(7, id + 1, 0, &bytes[..split]),
        Err(ESTALE)
    );
    assert_eq!(
        manager.managed_upload_chunk(8, id, 0, &bytes[..split]),
        Err(EPERM)
    );
    assert_eq!(
        manager.managed_upload_chunk(7, id, 1, &bytes[..split]),
        Err(EINVAL)
    );
    assert_eq!(
        manager
            .managed_upload_chunk(7, id, 0, &bytes[..split])
            .unwrap(),
        split as u32
    );
    assert_eq!(
        manager
            .managed_upload_chunk(7, id, 0, &bytes[..split])
            .unwrap(),
        split as u32
    );
    let mut conflict = bytes[..split].to_vec();
    conflict[0] ^= 1;
    assert_eq!(
        manager.managed_upload_chunk(7, id, 0, &conflict),
        Err(EINVAL)
    );
    assert_eq!(
        manager.managed_upload_chunk(7, id, split as u32 + 1, &[1]),
        Err(EINVAL)
    );
    assert_eq!(
        manager.managed_upload_chunk(7, id, split as u32, &[0; MANAGED_UPLOAD_CHUNK_BYTES + 1]),
        Err(EINVAL)
    );
    for (offset, chunk) in
        bytes[split..]
            .chunks(MANAGED_UPLOAD_CHUNK_BYTES)
            .scan(split, |offset, chunk| {
                let current = *offset;
                *offset += chunk.len();
                Some((current, chunk))
            })
    {
        manager
            .managed_upload_chunk(7, id, offset as u32, chunk)
            .unwrap();
    }
    assert_eq!(manager.managed_upload_finalize(7, id + 1), Err(ESTALE));
    assert_eq!(manager.managed_upload_finalize(8, id), Err(EPERM));
    assert_eq!(manager.managed_upload_finalize(7, id), Ok(id));
}

#[test]
fn managed_preparation_exit_cancels_only_incomplete_process_owned_upload() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let id = manager
        .managed_upload_begin(7, 0, bytes.len() as u32)
        .unwrap();
    assert!(manager.reclaim_owner(7));
    assert_eq!(
        manager.managed_operation_query(id).unwrap().phase,
        MANAGED_OPERATION_CANCELLED
    );

    let id = upload(&mut manager, 7, id, &bytes);
    manager.managed_upload_finalize(7, id).unwrap();
    assert!(manager.reclaim_owner(7));
    assert_eq!(
        manager.managed_operation_query(id).unwrap().phase,
        MANAGED_OPERATION_QUEUED
    );
    let work = manager.take_managed_work().unwrap();
    assert!(manager.reclaim_owner(7));
    assert_eq!(
        manager.managed_operation_query(id).unwrap().phase,
        MANAGED_OPERATION_PREPARING
    );
    let prepared = work.prepare();
    manager.commit_managed_work(&prepared).unwrap();
    finish(&mut manager, prepared);
    assert_eq!(
        manager.managed_operation_query(id).unwrap().phase,
        MANAGED_OPERATION_RESIDENT
    );
}

#[test]
fn managed_preparation_workspace_rejection_preserves_existing_artifact_and_upload() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let first = upload(&mut manager, 7, 0, &bytes);
    let (prepared, _) = prepare_and_commit(&mut manager, first);
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    let resident = manager.managed_operation_query(first).unwrap();
    let before = manager.resource_usage();

    let second = upload(&mut manager, 7, first, &bytes);
    manager.limits.max_program_bytes = manager.program_bytes + WORKSPACE_BYTES - 1;
    assert_eq!(manager.managed_upload_finalize(7, second), Err(ENOMEM));
    assert_eq!(manager.resource_usage(), before);
    assert_eq!(manager.managed_operation_query(first).unwrap(), resident);
    assert_eq!(
        manager.managed_operation_query(second).unwrap().phase,
        MANAGED_OPERATION_UPLOADING
    );
}

#[test]
fn managed_preparation_rejects_fourth_transient_artifact_before_workspace_reservation() {
    let program = [BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
    let (first_bytes, trust) = signed_bundle(1, &program);
    let mut manager = manager_with_upload(trust);
    let mut expected = 0;
    let mut receipts = Vec::new();

    for revision in 1..=3 {
        let bytes = if revision == 1 {
            first_bytes.clone()
        } else {
            signed_bundle(revision, &program).0
        };
        let id = upload(&mut manager, 7, expected, &bytes);
        let (prepared, _) = prepare_and_commit(&mut manager, id);
        finish(&mut manager, prepared);
        unassign_candidate_fixture(&mut manager);
        receipts.push(manager.managed_operation_query(id).unwrap());
        expected = id;
    }
    let full = manager.resource_usage();
    let fourth_bytes = signed_bundle(4, &program).0;
    let fourth = upload(&mut manager, 7, expected, &fourth_bytes);

    assert_eq!(manager.managed_upload_finalize(7, fourth), Err(ENOMEM));
    assert_eq!(manager.resource_usage(), full);
    assert_eq!(
        manager.managed_operation_query(fourth).unwrap().phase,
        MANAGED_OPERATION_UPLOADING
    );
    for receipt in receipts {
        assert_eq!(
            manager.managed_operation_query(receipt.id).unwrap(),
            receipt
        );
    }
}

#[test]
fn managed_preparation_valid_dedup_auth_verify_and_cancel_paths_balance_charges() {
    let valid_program = [BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
    let (bytes, trust) = signed_bundle(1, &valid_program);
    let mut manager = manager_with_upload(trust.clone());
    let floor = manager.resource_usage();

    let first = upload(&mut manager, 7, 0, &bytes);
    let (prepared, workspace_charge) = prepare_and_commit(&mut manager, first);
    assert_eq!(manager.resource_usage().program_bytes, workspace_charge);
    let handle = manager
        .managed_operation_query(first)
        .unwrap()
        .artifact_handle;
    let PreparedWork {
        id,
        buffer,
        artifact,
        ..
    } = prepared;
    drop(artifact);
    assert_eq!(manager.resource_usage().program_bytes, workspace_charge);
    manager.finish_managed_work(id, buffer).unwrap();
    unassign_candidate_fixture(&mut manager);
    let resident_floor = manager.resource_usage();
    assert_eq!(
        manager.managed_operation_query(first).unwrap().phase,
        MANAGED_OPERATION_RESIDENT
    );
    assert!(resident_floor.live_programs > floor.live_programs);

    let duplicate = upload(&mut manager, 7, first, &bytes);
    let (prepared, workspace_charge) = prepare_and_commit(&mut manager, duplicate);
    assert_eq!(manager.resource_usage().program_bytes, workspace_charge);
    assert_eq!(
        manager
            .managed_operation_query(duplicate)
            .unwrap()
            .artifact_handle,
        handle
    );
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    assert_eq!(manager.resource_usage(), resident_floor);

    let mut bad_auth = bytes.clone();
    bad_auth[MANIFEST_SIZE] ^= 1;
    let auth = upload(&mut manager, 7, duplicate, &bad_auth);
    let (prepared, _) = prepare_and_commit(&mut manager, auth);
    assert_eq!(
        manager.managed_operation_query(auth).unwrap().error,
        i32::from(EACCES) as u32
    );
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    assert_eq!(manager.resource_usage(), resident_floor);

    let (bad_program, _) = signed_bundle(2, &[BpfInsn::new(0xff, 0, 0, 0, 0)]);
    let rejected = upload(&mut manager, 7, auth, &bad_program);
    let (prepared, _) = prepare_and_commit(&mut manager, rejected);
    assert_eq!(
        manager.managed_operation_query(rejected).unwrap().error,
        i32::from(ENOEXEC) as u32
    );
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    assert_eq!(manager.resource_usage(), resident_floor);

    let cancelled = upload(&mut manager, 7, rejected, &bytes);
    manager.managed_upload_finalize(7, cancelled).unwrap();
    let prepared = manager.take_managed_work().unwrap().prepare();
    manager.managed_operation_cancel(99, cancelled).unwrap();
    manager.commit_managed_work(&prepared).unwrap();
    assert_eq!(
        manager.managed_operation_query(cancelled).unwrap().phase,
        MANAGED_OPERATION_CANCELLED
    );
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    assert_eq!(manager.resource_usage(), resident_floor);

    let after_commit = upload(&mut manager, 7, cancelled, &bytes);
    let (prepared, _) = prepare_and_commit(&mut manager, after_commit);
    assert_eq!(
        manager.managed_operation_cancel(7, after_commit),
        Err(EALREADY)
    );
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    assert_eq!(
        manager.managed_operation_query(after_commit).unwrap().phase,
        MANAGED_OPERATION_RESIDENT
    );
    assert_eq!(manager.resource_usage(), resident_floor);
}

#[test]
fn managed_preparation_evicts_only_after_four_terminal_receipts() {
    let (valid, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let mut expected = 0;
    let mut ids = Vec::new();
    for _ in 0..=MANAGED_TERMINAL_RECEIPTS {
        let mut invalid = valid.clone();
        invalid[MANIFEST_SIZE] ^= 1;
        let id = upload(&mut manager, 7, expected, &invalid);
        let (prepared, _) = prepare_and_commit(&mut manager, id);
        finish(&mut manager, prepared);
        ids.push(id);
        expected = id;
    }
    assert_eq!(manager.managed_operation_query(ids[0]), Err(ESTALE));
    for id in &ids[1..] {
        assert_eq!(
            manager.managed_operation_query(*id).unwrap().phase,
            MANAGED_OPERATION_FAILED
        );
    }
}

#[test]
fn managed_preparation_waits_for_reclamation_release_and_refund() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let first = upload(&mut manager, 7, 0, &bytes);
    let (prepared, _) = prepare_and_commit(&mut manager, first);
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    let artifact = manager
        .managed_operation_query(first)
        .unwrap()
        .artifact_handle;
    let second = upload(&mut manager, 7, first, &bytes);
    let charged = manager.resource_usage();
    let retired = manager
        .begin_managed_artifact_reclamation(artifact)
        .unwrap();
    assert_eq!(manager.managed_upload_finalize(7, second), Err(EBUSY));
    assert_eq!(manager.resource_usage(), charged);
    let receipt = retired.release();
    assert_eq!(manager.managed_upload_finalize(7, second), Err(EBUSY));
    assert_eq!(manager.resource_usage(), charged);
    manager.finish_managed_reclamation(receipt).unwrap();
    assert_eq!(manager.managed_upload_finalize(7, second), Ok(second));
    let prepared = manager.take_managed_work().unwrap().prepare();
    manager.commit_managed_work(&prepared).unwrap();
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    let current = manager.managed_operation_query(second).unwrap();
    assert_eq!(current.phase, MANAGED_OPERATION_RESIDENT);
    assert_ne!(current.artifact_handle, artifact);
    assert_eq!(manager.resource_usage(), charged);
}

#[test]
fn managed_preparation_prevents_reclamation_from_disrupting_accepted_work() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let first = upload(&mut manager, 7, 0, &bytes);
    let (prepared, _) = prepare_and_commit(&mut manager, first);
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    let artifact = manager
        .managed_operation_query(first)
        .unwrap()
        .artifact_handle;
    let second = upload(&mut manager, 7, first, &bytes);
    manager.managed_upload_finalize(7, second).unwrap();
    let charged = manager.resource_usage();
    let reject_reclamation = |manager: &mut BpfManager| {
        assert!(matches!(
            manager.begin_managed_artifact_reclamation(artifact),
            Err(BpfError::ObjectBusy)
        ));
        assert!(matches!(
            manager.begin_managed_instance_reclamation(),
            Err(BpfError::ObjectBusy)
        ));
        assert_eq!(manager.resource_usage(), charged);
        assert!(manager.managed_reclamation.is_none());
    };
    reject_reclamation(&mut manager);
    let work = manager.take_managed_work().unwrap();
    reject_reclamation(&mut manager);
    let prepared = work.prepare();
    manager.commit_managed_work(&prepared).unwrap();
    reject_reclamation(&mut manager);
    finish(&mut manager, prepared);
    unassign_candidate_fixture(&mut manager);
    assert_eq!(
        manager.managed_operation_query(second).unwrap().phase,
        MANAGED_OPERATION_RESIDENT
    );
    let reclamation = manager
        .begin_managed_artifact_reclamation(artifact)
        .unwrap();
    let receipt = reclamation.release();
    manager.finish_managed_reclamation(receipt).unwrap();
}

#[test]
fn managed_preparation_rejects_second_resident_candidate_even_without_active() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let id = upload(&mut manager, 7, 0, &bytes);
    let (prepared, _) = prepare_and_commit(&mut manager, id);
    finish(&mut manager, prepared);
    let before = manager.resource_usage();
    let handle = manager.preparation.candidate.unwrap();
    assert_eq!(
        manager.managed_upload_begin(7, id, bytes.len() as u32),
        Err(EBUSY)
    );
    assert_eq!(manager.resource_usage(), before);
    assert_eq!(manager.preparation.candidate, Some(handle));
    assert!(matches!(
        manager.begin_managed_artifact_reclamation(handle),
        Err(BpfError::ObjectBusy)
    ));
}

#[test]
fn managed_accepted_upload_and_instance_preparation_exclude_each_other() {
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let handle = manager
        .register_managed_artifact(crate::bpf::managed::tests::artifact(1))
        .unwrap();
    let id = upload(&mut manager, 7, 0, &bytes);
    manager.managed_upload_finalize(7, id).unwrap();
    let before = manager.resource_usage();
    assert!(matches!(
        manager.begin_managed_instance(handle),
        Err(BpfError::ObjectBusy)
    ));
    assert_eq!(manager.resource_usage(), before);
    let work = manager.take_managed_work().unwrap();
    assert!(matches!(
        manager.begin_managed_instance(handle),
        Err(BpfError::ObjectBusy)
    ));
    let prepared = work.prepare();
    manager.commit_managed_work(&prepared).unwrap();
    assert!(matches!(
        manager.begin_managed_instance(handle),
        Err(BpfError::ObjectBusy)
    ));
    finish(&mut manager, prepared);
}

#[test]
fn managed_uploaded_candidate_transfers_only_after_actual_slot_commit_and_cleanup() {
    use crate::bpf::installation::ControlSlot;
    let (bytes, trust) = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let mut manager = manager_with_upload(trust);
    let mut slot = ControlSlot::new();
    let id = upload(&mut manager, 7, 0, &bytes);
    let (prepared, _) = prepare_and_commit(&mut manager, id);
    finish(&mut manager, prepared);
    let handle = manager.preparation.candidate.unwrap();
    let preparation = slot.begin(&mut manager, 0, None).unwrap();
    let operation = slot.snapshot().pending.unwrap();
    slot.finish_build(&mut manager, preparation.build())
        .unwrap();
    slot.enter_handoff(operation).unwrap();
    slot.commit_test_handoff(operation).unwrap();
    assert_eq!(slot.snapshot().active, Some(handle));
    assert_eq!(
        manager.managed_upload_begin(7, id, bytes.len() as u32),
        Err(EBUSY)
    );
    let mut retirement = slot.take_retirement().unwrap().release_references();
    assert!(retirement.begin_release(&mut manager).unwrap().is_none());
    slot.finish_retirement(&mut manager, retirement.complete().ok().unwrap())
        .unwrap();
    assert!(manager.preparation.candidate.is_none());
    assert!(manager
        .managed_upload_begin(7, id, bytes.len() as u32)
        .is_ok());
}

// Exercise exactly the actions and lock scopes used by the permanent task.
fn service_worker(
    worker: &mut WorkerState,
    slot: &spin::Mutex<ControlSlot>,
    manager: &spin::Mutex<BpfManager>,
) -> bool {
    for _ in 0..8 {
        let action = crate::mcore::context::with_interrupts_masked(|| {
            worker.take(&mut slot.lock(), &mut manager.lock())
        });
        match action {
            WorkerAction::Wait => return true,
            WorkerAction::Retry => return false,
            action => worker.perform(action, slot, manager),
        }
        assert!(!crate::mcore::context::interrupts_masked_for_test());
    }
    panic!("bounded batch should finish or return Busy");
}

fn resident_via_worker(
    worker: &mut WorkerState,
    slot: &spin::Mutex<ControlSlot>,
    manager: &spin::Mutex<BpfManager>,
    expected: u64,
    revision: u64,
) -> (u64, LifecycleTarget) {
    let bytes = signed_bundle(revision, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]).0;
    let id = upload(&mut manager.lock(), 7, expected, &bytes);
    manager.lock().managed_upload_finalize(7, id).unwrap();
    assert!(service_worker(worker, slot, manager));
    let operation = manager.lock().managed_operation_query(id).unwrap();
    assert_eq!(operation.phase, MANAGED_OPERATION_RESIDENT);
    (id, LifecycleTarget::Candidate(operation.artifact_handle))
}

fn fixture_worker() -> (
    WorkerState,
    spin::Mutex<ControlSlot>,
    spin::Mutex<BpfManager>,
) {
    let trust = signed_bundle(1, &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]).1;
    (
        WorkerState::default(),
        spin::Mutex::new(ControlSlot::new()),
        spin::Mutex::new(manager_with_upload(trust)),
    )
}

fn host_commit(slot: &spin::Mutex<ControlSlot>) {
    let mut slot = slot.lock();
    let private_id = slot.snapshot().pending.unwrap();
    slot.enter_handoff(private_id).unwrap();
    slot.commit_test_handoff(private_id).unwrap();
}

#[test]
fn handoff_failure_retains_its_errno_through_query_worker_cleanup_and_receipt() {
    use shrike_link::handoff::HandoffError;
    for (fault, expected) in [
        (HandoffError::TimedOut, ETIMEDEOUT),
        (HandoffError::NotEstablished, ENOLINK),
        (HandoffError::ClockReversed, EPROTO),
    ] {
        for phase in 0..3 {
            let (mut worker, slot, manager) = fixture_worker();
            let (uploaded, target) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
            let operation = manager
                .lock()
                .request_installation(&mut slot.lock(), uploaded, 0, target)
                .unwrap();
            let held = if phase == 1 {
                Some(worker.take(&mut slot.lock(), &mut manager.lock()))
            } else {
                None
            };
            if phase == 2 {
                assert!(service_worker(&mut worker, &slot, &manager));
            }
            let instance = slot.lock().snapshot().pending.unwrap();
            if phase == 2 {
                slot.lock().enter_handoff(instance).unwrap();
            }
            slot.lock().fail_handoff(instance, fault);
            // Generic stop consequences and later cancellation cannot rewrite the
            // first cause after this operation has already failed.
            slot.lock().stop();
            manager
                .lock()
                .cancel_installation(&mut slot.lock(), operation, 0, target)
                .unwrap();
            let query = manager
                .lock()
                .query_installation(&slot.lock(), operation)
                .unwrap();
            assert_eq!(query.phase, MANAGED_OPERATION_CLEANUP);
            assert_eq!(query.error, i32::from(expected) as u32);
            if let Some(action) = held {
                worker.perform(action, &slot, &manager);
            }
            assert!(service_worker(&mut worker, &slot, &manager));
            let receipt = manager.lock().managed_operation_query(operation).unwrap();
            assert_eq!(receipt.phase, MANAGED_OPERATION_FAILED);
            assert_eq!(receipt.error, i32::from(expected) as u32);
            assert!(!manager.lock().managed_slot_busy);
            assert_eq!(slot.lock().snapshot().generation, 0);
            assert!(slot.lock().snapshot().inhibited);
        }
    }
}

#[test]
fn slot_query_exposes_public_operation_identity_and_presence_through_retirement() {
    let (mut worker, slot, manager) = fixture_worker();
    let empty = manager.lock().managed_slot_query(&slot.lock());
    assert_eq!(empty.flags, MANAGED_SLOT_INHIBITED);
    assert_eq!(
        (empty.last_id, empty.generation, empty.pending_id),
        (0, 0, 0)
    );
    let (uploaded, target) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
    let resident = manager.lock().managed_slot_query(&slot.lock());
    assert_eq!(resident.last_id, uploaded);
    assert_eq!(
        resident.flags,
        MANAGED_SLOT_INHIBITED | MANAGED_SLOT_HAS_CANDIDATE
    );
    assert_eq!(resident.candidate_artifact, target.handle());
    let identity = manager.lock().managed_operation_query(uploaded).unwrap();
    let operation = manager
        .lock()
        .request_installation(&mut slot.lock(), uploaded, 0, target)
        .unwrap();
    let preparing = manager.lock().managed_slot_query(&slot.lock());
    let activation = manager
        .lock()
        .query_installation(&slot.lock(), operation)
        .unwrap();
    assert_eq!(activation.behavior_id, identity.behavior_id);
    assert_eq!(activation.revision, identity.revision);
    assert_eq!(activation.bundle_digest, identity.bundle_digest);
    assert_eq!(activation.payload_digest, identity.payload_digest);
    assert_eq!(activation.signer_fingerprint, identity.signer_fingerprint);
    assert_eq!(activation.signer_public_key, identity.signer_public_key);
    assert_eq!(preparing.pending_id, operation);
    assert_ne!(
        preparing.pending_id,
        slot.lock().snapshot().pending.unwrap()
    );
    assert_eq!(preparing.pending_target_kind, MANAGED_TARGET_CANDIDATE);
    assert_ne!(preparing.flags & MANAGED_SLOT_HAS_PENDING, 0);
    assert!(service_worker(&mut worker, &slot, &manager));
    host_commit(&slot);
    let committed = manager.lock().managed_slot_query(&slot.lock());
    assert_eq!(committed.generation, 1);
    assert_eq!(committed.active_artifact, target.handle());
    assert_ne!(committed.flags & MANAGED_SLOT_HAS_ACTIVE, 0);
    assert_eq!(committed.flags & MANAGED_SLOT_INHIBITED, 0);
    assert_ne!(committed.flags & MANAGED_SLOT_RETIRING, 0);
    assert_eq!(
        committed.pending_id, operation,
        "accepted cleanup still owns this public operation"
    );
    assert!(service_worker(&mut worker, &slot, &manager));
    let retired = manager.lock().managed_slot_query(&slot.lock());
    assert_eq!(retired.flags, MANAGED_SLOT_HAS_ACTIVE);
    assert_eq!((retired.pending_id, retired.pending_target_kind), (0, 0));
    assert_eq!(retired.last_id, operation);
    assert_eq!(
        retired.active_charge_ns_per_s,
        slot.lock().snapshot().active_charge_ns_per_s.unwrap()
    );
}

#[test]
fn worker_signed_upload_install_commit_cleanup_and_next_operation_share_ids_and_custody() {
    let (mut worker, slot, manager) = fixture_worker();
    let (upload_id, target) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
    let id = manager
        .lock()
        .request_installation(&mut slot.lock(), upload_id, 0, target)
        .unwrap();
    assert_eq!(id, upload_id + 1);
    assert_ne!(
        id,
        slot.lock().snapshot().pending.unwrap(),
        "user operation ID is not instance cleanup ID"
    );
    assert_eq!(
        manager
            .lock()
            .query_installation(&slot.lock(), id)
            .unwrap()
            .phase,
        MANAGED_OPERATION_QUEUED
    );
    assert!(manager.lock().reclaim_owner(7));
    assert!(service_worker(&mut worker, &slot, &manager));
    assert_eq!(
        manager
            .lock()
            .query_installation(&slot.lock(), id)
            .unwrap()
            .phase,
        MANAGED_OPERATION_STAGED
    );
    assert!(slot.lock().snapshot().inhibited);
    assert_eq!(slot.lock().snapshot().generation, 0);
    let private_id = slot.lock().snapshot().pending.unwrap();
    slot.lock().enter_handoff(private_id).unwrap();
    assert_eq!(
        manager
            .lock()
            .query_installation(&slot.lock(), id)
            .unwrap()
            .phase,
        MANAGED_OPERATION_HANDOFF
    );
    slot.lock().commit_test_handoff(private_id).unwrap();
    let charged = manager.lock().resource_usage();
    assert_eq!(
        manager
            .lock()
            .query_installation(&slot.lock(), id)
            .unwrap()
            .phase,
        MANAGED_OPERATION_COMMITTED
    );
    assert_eq!(
        manager
            .lock()
            .cancel_installation(&mut slot.lock(), id, 0, target),
        Err(EALREADY)
    );
    assert!(manager.lock().managed_slot_busy);
    assert!(service_worker(&mut worker, &slot, &manager));
    assert_eq!(manager.lock().resource_usage(), charged);
    assert!(!manager.lock().managed_slot_busy);
    assert_eq!(
        manager.lock().managed_operation_query(id).unwrap().phase,
        MANAGED_OPERATION_COMMITTED
    );
    assert_eq!(
        manager
            .lock()
            .cancel_installation(&mut slot.lock(), id, 0, target),
        Err(EALREADY)
    );
    let (next, _) = resident_via_worker(&mut worker, &slot, &manager, id, 2);
    assert_eq!(next, id + 1);
}

#[test]
fn worker_cancellation_at_each_build_and_handoff_boundary_preserves_old_active() {
    for ordering in 0..4 {
        let (mut worker, slot, manager) = fixture_worker();
        let (uploaded, first) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
        let active_op = manager
            .lock()
            .request_installation(&mut slot.lock(), uploaded, 0, first)
            .unwrap();
        assert!(service_worker(&mut worker, &slot, &manager));
        host_commit(&slot);
        assert!(service_worker(&mut worker, &slot, &manager));
        let (uploaded, target) = resident_via_worker(&mut worker, &slot, &manager, active_op, 2);
        let floor = manager.lock().resource_usage();
        let id = manager
            .lock()
            .request_installation(&mut slot.lock(), uploaded, 1, target)
            .unwrap();
        let action = if ordering == 1 {
            Some(worker.take(&mut slot.lock(), &mut manager.lock()))
        } else {
            None
        };
        if ordering >= 2 {
            assert!(service_worker(&mut worker, &slot, &manager));
        }
        if ordering == 3 {
            let private_id = slot.lock().snapshot().pending.unwrap();
            slot.lock().enter_handoff(private_id).unwrap();
        }
        assert!(manager.lock().reclaim_owner(7));
        manager
            .lock()
            .cancel_installation(&mut slot.lock(), id, 1, target)
            .unwrap();
        manager
            .lock()
            .cancel_installation(&mut slot.lock(), id, 1, target)
            .unwrap();
        assert_eq!(
            manager
                .lock()
                .query_installation(&slot.lock(), id)
                .unwrap()
                .phase,
            MANAGED_OPERATION_CLEANUP
        );
        if let Some(action) = action {
            worker.perform(action, &slot, &manager);
        }
        assert!(service_worker(&mut worker, &slot, &manager));
        assert_eq!(manager.lock().resource_usage(), floor);
        let state = slot.lock().snapshot();
        assert_eq!(state.active, Some(first.handle()));
        assert_eq!(state.generation, 1);
        assert_eq!(state.inhibited, ordering == 3);
        let receipt = manager.lock().managed_operation_query(id).unwrap();
        assert_eq!(receipt.phase, MANAGED_OPERATION_CANCELLED);
        assert_eq!(receipt.error, i32::from(ECANCELED) as u32);
        assert_eq!(
            manager
                .lock()
                .request_installation(&mut slot.lock(), id, 1, target),
            Ok(id + 1)
        );
        manager
            .lock()
            .cancel_installation(&mut slot.lock(), id + 1, 1, target)
            .unwrap();
        assert!(service_worker(&mut worker, &slot, &manager));
    }
}

#[test]
fn worker_lifecycle_stale_checks_exclusion_receipt_bound_and_id_exhaustion() {
    let (mut worker, slot, manager) = fixture_worker();
    let (uploaded, target) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
    let floor = manager.lock().resource_usage();
    for (last, generation, target) in [
        (uploaded - 1, 0, target),
        (uploaded, 1, target),
        (uploaded, 0, LifecycleTarget::Candidate(target.handle() + 1)),
        (uploaded, 0, LifecycleTarget::Previous(target.handle())),
    ] {
        assert_eq!(
            manager
                .lock()
                .request_installation(&mut slot.lock(), last, generation, target),
            Err(ESTALE)
        );
        assert_eq!(manager.lock().resource_usage(), floor);
        assert!(slot.lock().snapshot().pending.is_none());
    }
    let mut last = uploaded;
    let mut ids = Vec::new();
    for _ in 0..=MANAGED_TERMINAL_RECEIPTS {
        let id = manager
            .lock()
            .request_installation(&mut slot.lock(), last, 0, target)
            .unwrap();
        ids.push(id);
        assert_eq!(
            manager
                .lock()
                .request_installation(&mut slot.lock(), id, 0, target),
            Err(EBUSY)
        );
        assert_eq!(manager.lock().managed_upload_begin(7, id, 8), Err(EBUSY));
        assert!(matches!(
            manager.lock().begin_managed_instance(target.handle()),
            Err(BpfError::ObjectBusy)
        ));
        assert!(matches!(
            manager
                .lock()
                .begin_managed_artifact_reclamation(target.handle()),
            Err(BpfError::ObjectBusy)
        ));
        assert_eq!(
            manager
                .lock()
                .cancel_installation(&mut slot.lock(), id + 1, 0, target),
            Err(ESTALE)
        );
        assert_eq!(
            manager
                .lock()
                .cancel_installation(&mut slot.lock(), id, 1, target),
            Err(ESTALE)
        );
        assert_eq!(
            manager.lock().cancel_installation(
                &mut slot.lock(),
                id,
                0,
                LifecycleTarget::Previous(target.handle())
            ),
            Err(ESTALE)
        );
        manager
            .lock()
            .cancel_installation(&mut slot.lock(), id, 0, target)
            .unwrap();
        assert!(service_worker(&mut worker, &slot, &manager));
        assert_eq!(manager.lock().resource_usage(), floor);
        last = id;
    }
    assert_eq!(manager.lock().managed_operation_query(ids[0]), Err(ESTALE));
    for id in &ids[1..] {
        assert_eq!(
            manager.lock().managed_operation_query(*id).unwrap().phase,
            MANAGED_OPERATION_CANCELLED
        );
    }
    manager.lock().preparation.last_id = isize::MAX as u64;
    assert_eq!(
        manager
            .lock()
            .request_installation(&mut slot.lock(), isize::MAX as u64, 0, target),
        Err(EOVERFLOW)
    );
    assert_eq!(manager.lock().resource_usage(), floor);
    assert!(slot.lock().snapshot().pending.is_none());
}

#[test]
fn worker_failed_build_and_stop_keep_cleanup_custody() {
    for stop in [false, true] {
        let (mut worker, slot, manager) = fixture_worker();
        let (uploaded, target) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
        let floor = manager.lock().resource_usage();
        let id = manager
            .lock()
            .request_installation(&mut slot.lock(), uploaded, 0, target)
            .unwrap();
        let action = worker.take(&mut slot.lock(), &mut manager.lock());
        if stop {
            slot.lock().stop();
        }
        let action = if let WorkerAction::Install(preparation, _) = action {
            WorkerAction::Install(preparation, true)
        } else {
            panic!("expected fresh build")
        };
        worker.perform(action, &slot, &manager);
        assert_eq!(
            manager
                .lock()
                .query_installation(&slot.lock(), id)
                .unwrap()
                .phase,
            MANAGED_OPERATION_CLEANUP
        );
        assert!(manager.lock().managed_slot_busy);
        assert!(service_worker(&mut worker, &slot, &manager));
        assert_eq!(
            manager.lock().managed_operation_query(id).unwrap().phase,
            if stop {
                MANAGED_OPERATION_CANCELLED
            } else {
                MANAGED_OPERATION_FAILED
            }
        );
        assert_eq!(manager.lock().resource_usage(), floor);
        assert!(slot.lock().snapshot().inhibited);
    }
}

#[test]
fn worker_queued_stop_projects_cancellation_before_take_without_releasing_custody() {
    let (mut worker, slot, manager) = fixture_worker();
    let (uploaded, first) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
    let active_op = manager
        .lock()
        .request_installation(&mut slot.lock(), uploaded, 0, first)
        .unwrap();
    assert!(service_worker(&mut worker, &slot, &manager));
    host_commit(&slot);
    assert!(service_worker(&mut worker, &slot, &manager));
    let (uploaded, target) = resident_via_worker(&mut worker, &slot, &manager, active_op, 2);
    let floor = manager.lock().resource_usage();
    let id = manager
        .lock()
        .request_installation(&mut slot.lock(), uploaded, 1, target)
        .unwrap();
    let charged = manager.lock().resource_usage();
    assert_eq!(
        manager
            .lock()
            .query_installation(&slot.lock(), id)
            .unwrap()
            .phase,
        MANAGED_OPERATION_QUEUED
    );

    slot.lock().stop();
    let stopped = slot.lock().snapshot();
    let operation = manager.lock().query_installation(&slot.lock(), id).unwrap();
    assert_eq!(operation.phase, MANAGED_OPERATION_CLEANUP);
    assert_eq!(operation.error, i32::from(ECANCELED) as u32);
    assert_eq!(slot.lock().snapshot(), stopped);
    assert_eq!(manager.lock().resource_usage(), charged);
    assert!(manager.lock().preparation.installation.is_some());
    assert!(!manager.lock().preparation.cancelled);
    assert!(manager.lock().managed_slot_busy);
    assert!(manager.lock().managed_instance_preparation.is_some());
    assert_eq!(stopped.active, Some(first.handle()));
    assert_eq!(stopped.generation, 1);
    assert!(stopped.inhibited);

    assert!(service_worker(&mut worker, &slot, &manager));
    let receipt = manager.lock().managed_operation_query(id).unwrap();
    assert_eq!(receipt.phase, MANAGED_OPERATION_CANCELLED);
    assert_eq!(receipt.error, i32::from(ECANCELED) as u32);
    assert_eq!(manager.lock().resource_usage(), floor);
    assert!(!manager.lock().managed_slot_busy);
    let settled = slot.lock().snapshot();
    assert_eq!(settled.active, stopped.active);
    assert_eq!(settled.generation, stopped.generation);
    assert!(settled.inhibited);
    assert!(settled.pending.is_none());
    assert!(!settled.retiring);
}
