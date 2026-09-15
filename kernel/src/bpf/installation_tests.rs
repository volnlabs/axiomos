extern crate std;
use kernel_bpf::signing::managed::{PrivateArray, EFFECT_MOTOR_PAIR};
use kernel_bpf::verifier::admission::AdmissionLedger;

use super::*;
use crate::bpf::managed::tests::{artifact, artifact_from_program, stateful_managed_program};

fn candidate(manager: &mut BpfManager, revision: u64) -> u32 {
    assert!(manager.preparation.candidate.is_none());
    let id = manager
        .register_managed_artifact(artifact(revision))
        .unwrap();
    manager.preparation.candidate = Some(id);
    id
}

fn drain(slot: &mut ControlSlot, manager: &mut BpfManager) {
    let mut retirement = slot.take_retirement().unwrap().release_references();
    while let Some(release) = retirement.begin_release(manager).unwrap() {
        let receipt = release.release();
        retirement.finish_release(manager, receipt).unwrap();
    }
    let receipt = retirement.complete().ok().unwrap();
    slot.finish_retirement(manager, receipt).unwrap();
}

fn stage(slot: &mut ControlSlot, manager: &mut BpfManager, previous: Option<u32>) -> u64 {
    let token = slot
        .begin(manager, slot.snapshot().generation, previous)
        .unwrap();
    let id = slot.snapshot().pending.unwrap();
    slot.finish_build(manager, token.build()).unwrap();
    id
}

fn commit(slot: &mut ControlSlot, id: u64) -> u64 {
    slot.enter_handoff(id).unwrap();
    slot.commit_test_handoff(id).unwrap()
}

fn peer_ready() -> Handoff {
    let mut handoff = Handoff::new();
    let offer = handoff.offer_after_drain().unwrap();
    handoff.started(offer).unwrap();
    handoff.sent(0).unwrap();
    assert!(handoff
        .on_reply(shrike_link::Msg::SessionReady { session: 1 }, 0)
        .unwrap());
    handoff
}

fn release(sequence: u64, scheduled: u64, actual: u64) -> PeriodicRelease {
    PeriodicRelease {
        sequence,
        scheduled,
        actual,
        deadline: scheduled + 10,
        missed_before: 0,
        wake_lateness: actual - scheduled,
    }
}

fn acknowledge(handoff: &mut Handoff, tx: &mut TxState, sent: u64, ack: u64) {
    let shrike_link::Msg::SafeBarrier {
        session,
        correlation,
        sequence,
    } = handoff.outbound().unwrap()
    else {
        panic!("expected barrier")
    };
    handoff.enqueue(tx, sent).unwrap();
    while tx.next_byte().is_some() {}
    handoff.sent(sent).unwrap();
    assert!(!handoff
        .on_reply(
            shrike_link::Msg::SafeAck {
                session,
                correlation: correlation + 1,
                sequence,
            },
            ack
        )
        .unwrap());
    assert!(handoff
        .on_reply(
            shrike_link::Msg::SafeAck {
                session,
                correlation,
                sequence
            },
            ack
        )
        .unwrap());
}

#[test]
fn inactive_retirement_skips_handoff_and_holds_charge_until_last_reader_release() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let usage = manager.resource_usage();
    let reader = manager.managed_artifact(a).unwrap().clone();
    let weak = Arc::downgrade(&reader);
    // Retirement needs no new generation, even at the exhausted slot epoch.
    slot.generation = u64::MAX;
    let id = slot
        .begin_artifact_retirement(&mut manager, u64::MAX, a)
        .unwrap();
    assert!(!slot.needs_handoff_transport());
    assert_eq!(slot.enter_handoff(id), Err(BpfError::ObjectBusy));
    let mut handoff = Handoff::new();
    let mut tx = TxState::new();
    let mut sequence = 0;
    assert_eq!(
        slot.handoff_boundary(
            release(1, 100, 100),
            1000,
            &mut handoff,
            &mut tx,
            &mut sequence
        ),
        Ok(None)
    );
    assert!(tx.is_idle());
    assert_eq!(handoff.operation(), None);
    assert_eq!(manager.preparation.candidate, Some(a));
    slot.commit_artifact_retirement(&mut manager, id).unwrap();
    assert_eq!(slot.snapshot().generation, u64::MAX);
    assert!(slot.snapshot().inhibited);
    assert!(manager.preparation.candidate.is_none());
    assert_eq!(manager.resource_usage(), usage);
    let mut retirement = slot.take_retirement().unwrap().release_references();
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    drop(reader);
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    drop(weak);
    let release = retirement.begin_release(&mut manager).unwrap().unwrap();
    assert_eq!(manager.resource_usage(), usage);
    assert!(manager.managed_artifact(a).is_err());
    let receipt = release.release();
    assert_eq!(manager.resource_usage(), usage);
    retirement.finish_release(&mut manager, receipt).unwrap();
    assert!(manager.resource_usage().program_bytes < usage.program_bytes);
    assert!(retirement.begin_release(&mut manager).unwrap().is_none());
    slot.finish_retirement(&mut manager, retirement.complete().ok().unwrap())
        .unwrap();
    assert!(!manager.managed_slot_busy);
    assert_eq!(slot.snapshot().generation, u64::MAX);
    assert_eq!(manager.admission.reserved_ns_per_s(), 0);
}

#[test]
fn inactive_retirement_at_max_generation_reuses_bounded_capacity_and_receipts() {
    use crate::bpf::preparation::{WorkerAction, WorkerState};
    let manager = spin::Mutex::new(BpfManager::new());
    let slot = spin::Mutex::new(ControlSlot::new());
    let mut worker = WorkerState::default();
    manager.lock().prepare_managed_storage().unwrap();
    let floor = manager.lock().resource_usage();
    slot.lock().generation = u64::MAX;
    let mut last = 0;
    let mut first_handle = None;
    for revision in 1..=16 {
        let handle = candidate(&mut manager.lock(), revision);
        let old_handle = *first_handle.get_or_insert(handle);
        if revision > 1 {
            assert_ne!(old_handle, handle);
            assert_eq!(
                manager.lock().request_installation(
                    &mut slot.lock(),
                    last,
                    u64::MAX,
                    LifecycleTarget::Retire(old_handle)
                ),
                Err(kernel_abi::ESTALE)
            );
        }
        last = manager
            .lock()
            .request_installation(
                &mut slot.lock(),
                last,
                u64::MAX,
                LifecycleTarget::Retire(handle),
            )
            .unwrap();
        assert_eq!(
            manager
                .lock()
                .query_installation(&slot.lock(), last)
                .unwrap()
                .phase,
            kernel_abi::MANAGED_OPERATION_QUEUED
        );
        for _ in 0..4 {
            let action = {
                let mut slot = slot.lock();
                let mut manager = manager.lock();
                worker.take(&mut slot, &mut manager)
            };
            match action {
                WorkerAction::Wait => break,
                WorkerAction::Retry => panic!("no retained reader"),
                action => worker.perform(action, &slot, &manager),
            }
        }
        assert_eq!(
            manager.lock().managed_operation_query(last).unwrap().phase,
            kernel_abi::MANAGED_OPERATION_COMMITTED
        );
        assert_eq!(manager.lock().resource_usage(), floor);
        assert!(!manager.lock().managed_slot_busy);
        assert_eq!(slot.lock().snapshot().generation, u64::MAX);
        assert!(slot.lock().snapshot().inhibited);
    }
    assert_eq!(
        manager.lock().managed_operation_query(1),
        Err(kernel_abi::ESTALE)
    );
}

#[test]
fn inactive_retirement_worker_consumes_stop_mailbox_before_its_commit() {
    use crate::bpf::preparation::{WorkerAction, WorkerState};
    for before_commit in [true, false] {
        for stale_handoff in [false, true] {
            let manager = spin::Mutex::new(BpfManager::new());
            let slot = spin::Mutex::new(ControlSlot::new());
            let mut worker = WorkerState::default();
            let requested = spin::Mutex::new(None);
            let handle = candidate(&mut manager.lock(), 1);
            let operation = manager
                .lock()
                .request_installation(&mut slot.lock(), 0, 0, LifecycleTarget::Retire(handle))
                .unwrap();
            let notice = if stale_handoff {
                StopNotice::Handoff {
                    instance_id: slot.lock().snapshot().pending.unwrap() + 1,
                    error: HandoffError::TimedOut,
                }
            } else {
                StopNotice::Stop
            };
            if before_commit {
                latch_stop(&requested, notice);
            }
            let action = worker.take_requested(&mut slot.lock(), &mut manager.lock(), &requested);
            assert!(matches!(action, WorkerAction::Retire(_)));
            if !before_commit {
                latch_stop(&requested, notice);
            }
            worker.perform(action, &slot, &manager);
            for _ in 0..4 {
                let action =
                    worker.take_requested(&mut slot.lock(), &mut manager.lock(), &requested);
                match action {
                    WorkerAction::Wait => break,
                    WorkerAction::Retry => panic!("no retained reader"),
                    action => worker.perform(action, &slot, &manager),
                }
            }
            let receipt = manager.lock().managed_operation_query(operation).unwrap();
            assert_eq!(
                receipt.phase,
                if before_commit {
                    kernel_abi::MANAGED_OPERATION_CANCELLED
                } else {
                    kernel_abi::MANAGED_OPERATION_COMMITTED
                }
            );
            assert_eq!(
                receipt.error,
                if before_commit {
                    i32::from(kernel_abi::ECANCELED) as u32
                } else {
                    0
                }
            );
            assert_eq!(
                manager.lock().preparation.candidate,
                before_commit.then_some(handle)
            );
            assert!(!manager.lock().managed_slot_busy);
            assert_eq!(slot.lock().snapshot().generation, 0);
            assert!(requested.lock().is_none());
        }
    }
}

#[test]
fn deactivation_requires_safe_ack_and_retires_state_before_refunding_admission() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let b = candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let charged = manager.admission.reserved_ns_per_s();
    let private_bytes = manager.map_bytes;
    let resources = manager.resource_usage();
    let old_instance = slot.active.as_ref().unwrap().instance_id;
    let old_reader = slot.active.as_ref().unwrap().instance.clone();
    let id = slot.begin_deactivation(&mut manager, 2, b).unwrap();
    assert_ne!(id, old_instance);
    assert!(slot.staged.is_none());
    assert_eq!(manager.resource_usage(), resources);
    assert!(!slot.snapshot().inhibited);
    assert_eq!(manager.admission.reserved_ns_per_s(), charged);
    let mut handoff = peer_ready();
    let mut tx = TxState::new();
    let mut sequence = 0;
    assert_eq!(
        slot.handoff_boundary(
            release(1, 100, 100),
            1000,
            &mut handoff,
            &mut tx,
            &mut sequence
        ),
        Ok(None)
    );
    assert_eq!(slot.snapshot().active, Some(b));
    assert!(slot.snapshot().inhibited);
    assert_eq!(slot.snapshot().previous, Some(a));
    assert_eq!(slot.snapshot().generation, 2);
    acknowledge(&mut handoff, &mut tx, 101, 105);
    assert_eq!(
        slot.handoff_boundary(
            release(2, 110, 110),
            1000,
            &mut handoff,
            &mut tx,
            &mut sequence
        ),
        Ok(Some(3))
    );
    assert_eq!(slot.snapshot().active, None);
    assert_eq!(slot.snapshot().previous, Some(b));
    assert!(slot.snapshot().inhibited);
    assert_eq!(manager.admission.reserved_ns_per_s(), charged);
    assert_eq!(manager.map_bytes, private_bytes);
    let mut retirement = slot.take_retirement().unwrap().release_references();
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    assert!(matches!(
        slot.begin(&mut manager, 3, Some(b)),
        Err(BpfError::ObjectBusy)
    ));
    drop(old_reader);
    while let Some(release) = retirement.begin_release(&mut manager).unwrap() {
        let receipt = release.release();
        retirement.finish_release(&mut manager, receipt).unwrap();
    }
    slot.finish_retirement(&mut manager, retirement.complete().ok().unwrap())
        .unwrap();
    assert_eq!(manager.admission.reserved_ns_per_s(), 0);
    assert!(manager.managed_artifact(a).is_err());
    assert!(manager.managed_artifact(b).is_ok());
    assert!(manager.managed_instances.iter().all(Option::is_none));
    let fresh = stage(&mut slot, &mut manager, Some(b));
    assert_ne!(fresh, id);
    assert_eq!(commit(&mut slot, fresh), 4);
    drain(&mut slot, &mut manager);
}

#[test]
fn deactivation_preserves_candidate_alias_and_activation_from_empty_keeps_previous() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let b = candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    // A duplicate upload may retain the previous artifact as its candidate.
    assert_eq!(candidate(&mut manager, 1), a);
    let id = slot.begin_deactivation(&mut manager, 2, b).unwrap();
    commit(&mut slot, id);
    assert!(!slot.retire.as_ref().unwrap().evict_artifact);
    drain(&mut slot, &mut manager);
    assert_eq!(slot.snapshot().previous, Some(b));
    assert_eq!(manager.preparation.candidate, Some(a));
    assert!(manager.managed_artifact(a).is_ok());
    let id = stage(&mut slot, &mut manager, None);
    assert_eq!(commit(&mut slot, id), 4);
    drain(&mut slot, &mut manager);
    assert_eq!(slot.snapshot().active, Some(a));
    assert_eq!(slot.snapshot().previous, Some(b));
    assert!(manager.preparation.candidate.is_none());
    let id = stage(&mut slot, &mut manager, Some(b));
    assert_eq!(commit(&mut slot, id), 5);
    drain(&mut slot, &mut manager);
    assert_eq!(slot.snapshot().previous, Some(a));
}

#[test]
fn deactivation_100000_transitions_keep_retained_code_and_zero_instance_floor() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let floor = manager.resource_usage();
    let mut high_water = None;
    for generation in (1..100_000).step_by(2) {
        let previous = slot.snapshot().previous;
        let id = stage(&mut slot, &mut manager, previous);
        commit(&mut slot, id);
        drain(&mut slot, &mut manager);
        let full = manager.resource_usage();
        if let Some(high_water) = high_water {
            assert_eq!(full, high_water);
        }
        high_water = Some(full);
        assert_eq!(slot.snapshot().generation, generation);
        let id = slot
            .begin_deactivation(&mut manager, generation, a)
            .unwrap();
        assert_eq!(manager.resource_usage(), full);
        assert_eq!(commit(&mut slot, id), generation + 1);
        assert_eq!(manager.resource_usage(), full);
        drain(&mut slot, &mut manager);
        assert_eq!(manager.resource_usage(), floor);
        assert_eq!(manager.admission.reserved_ns_per_s(), 0);
        assert!(slot.snapshot().inhibited);
        assert_eq!(slot.snapshot().active, None);
        assert_eq!(slot.snapshot().previous, Some(a));
        assert!(manager.managed_instances.iter().all(Option::is_none));
        assert_eq!(Arc::strong_count(manager.managed_artifact(a).unwrap()), 2);
    }
    std::println!("deactivation 100000: floor={floor:?}, high_water={high_water:?}");
}

#[test]
fn real_boundary_commits_only_matching_ack_at_next_release_and_keeps_retirement_owned() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let mut handoff = peer_ready();
    let mut tx = TxState::new();
    let mut seq = 0;
    let a = candidate(&mut manager, 1);
    stage(&mut slot, &mut manager, None);
    assert_eq!(
        slot.handoff_boundary(release(1, 100, 100), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(None)
    );
    assert!(slot.snapshot().inhibited);
    assert_eq!(slot.snapshot().generation, 0);
    acknowledge(&mut handoff, &mut tx, 101, 102);
    assert_eq!(
        slot.handoff_boundary(release(1, 100, 103), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(None)
    );
    assert_eq!(
        slot.handoff_boundary(release(2, 110, 110), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(Some(1))
    );
    assert_eq!(slot.snapshot().active, Some(a));
    assert!(!slot.snapshot().inhibited);
    assert!(slot.snapshot().retiring);
    drain(&mut slot, &mut manager);
    let b = candidate(&mut manager, 2);
    stage(&mut slot, &mut manager, None);
    let charge = slot.snapshot().active_charge_ns_per_s;
    assert_eq!(
        slot.handoff_boundary(release(3, 120, 120), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(None)
    );
    assert_eq!(slot.snapshot().active, Some(a));
    assert_eq!(slot.snapshot().active_charge_ns_per_s, charge);
    acknowledge(&mut handoff, &mut tx, 121, 129);
    assert_eq!(
        slot.handoff_boundary(release(4, 130, 130), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(Some(2))
    );
    assert_eq!(
        (slot.snapshot().active, slot.snapshot().previous),
        (Some(b), Some(a))
    );
    drain(&mut slot, &mut manager);
    stage(&mut slot, &mut manager, Some(a));
    assert_eq!(
        slot.handoff_boundary(release(5, 140, 140), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(None)
    );
    acknowledge(&mut handoff, &mut tx, 141, 149);
    assert_eq!(
        slot.handoff_boundary(release(6, 150, 150), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(Some(3))
    );
    assert_eq!(
        (slot.snapshot().active, slot.snapshot().previous),
        (Some(a), Some(b))
    );
    slot.stop();
    assert_eq!(
        slot.handoff_boundary(release(7, 160, 160), 1000, &mut handoff, &mut tx, &mut seq),
        Ok(None)
    );
    assert!(
        slot.snapshot().inhibited,
        "postcommit stop cannot implicitly resume"
    );
}

#[test]
fn stop_cancel_timeout_and_reset_cannot_publish_even_with_matching_ack() {
    for fault in 0..4 {
        let mut manager = BpfManager::new();
        let mut slot = ControlSlot::new();
        candidate(&mut manager, 1);
        let id = stage(&mut slot, &mut manager, None);
        commit(&mut slot, id);
        drain(&mut slot, &mut manager);
        let before = slot.snapshot();
        candidate(&mut manager, 2);
        let pending = stage(&mut slot, &mut manager, None);
        let mut handoff = peer_ready();
        let mut tx = TxState::new();
        let mut seq = 0;
        slot.handoff_boundary(release(1, 100, 100), 1000, &mut handoff, &mut tx, &mut seq)
            .unwrap();
        acknowledge(
            &mut handoff,
            &mut tx,
            101,
            if fault == 2 { 179 } else { 109 },
        );
        match fault {
            0 => slot.stop(),
            1 => {
                slot.cancel(pending).unwrap();
            }
            2 => {}
            3 => handoff.disarm(),
            _ => unreachable!(),
        }
        let at = if fault == 2 { 180 } else { 110 };
        assert!(slot
            .handoff_boundary(release(2, at, at), 1000, &mut handoff, &mut tx, &mut seq)
            .is_err());
        let after = slot.snapshot();
        assert_eq!(
            (
                after.generation,
                after.active,
                after.previous,
                after.active_charge_ns_per_s
            ),
            (
                before.generation,
                before.active,
                before.previous,
                before.active_charge_ns_per_s
            )
        );
        assert!(after.inhibited);
        assert!(!handoff.motion_permitted());
        assert_eq!(tx.take_motor(), None);
        slot.abort_cancelled();
        drain(&mut slot, &mut manager);
        assert_eq!(
            slot.snapshot().active_charge_ns_per_s,
            before.active_charge_ns_per_s
        );
    }
}

#[test]
fn trusted_stop_notification_cancels_prepublication_and_inhibits_committed_code() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let requested = spin::Mutex::new(None);
    candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let active = slot.snapshot().active;
    let generation = slot.snapshot().generation;
    latch_stop(&requested, StopNotice::Stop);
    apply_requested_stop(&mut slot, &requested);
    assert!(slot.snapshot().inhibited);
    assert_eq!(slot.snapshot().active, active);
    assert_eq!(slot.snapshot().generation, generation);
    apply_requested_stop(&mut slot, &requested);
    assert!(
        slot.snapshot().inhibited,
        "consuming stop never resumes an installation"
    );

    candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    slot.enter_handoff(id).unwrap();
    latch_stop(&requested, StopNotice::Stop);
    apply_requested_stop(&mut slot, &requested);
    assert_eq!(slot.commit_test_handoff(id), Err(BpfError::ObjectBusy));
    assert_eq!(slot.snapshot().active, active);
    assert_eq!(slot.snapshot().generation, generation);
}

#[test]
fn stop_mailbox_preserves_order_and_cannot_attach_a_failure_to_another_operation() {
    for first_stop in [false, true] {
        let mut manager = BpfManager::new();
        let mut slot = ControlSlot::new();
        candidate(&mut manager, 1);
        let instance = stage(&mut slot, &mut manager, None);
        slot.enter_handoff(instance).unwrap();
        let notice = spin::Mutex::new(None);
        let failed = StopNotice::Handoff {
            instance_id: instance,
            error: HandoffError::TimedOut,
        };
        latch_stop(&notice, if first_stop { StopNotice::Stop } else { failed });
        latch_stop(&notice, if first_stop { failed } else { StopNotice::Stop });
        apply_requested_stop(&mut slot, &notice);
        assert_eq!(
            slot.operation_error(instance),
            Some(if first_stop {
                kernel_abi::ECANCELED
            } else {
                kernel_abi::ETIMEDEOUT
            })
        );
        assert!(notice.lock().is_none());
        apply_requested_stop(&mut slot, &notice);
        assert_eq!(slot.snapshot().generation, 0);
        assert!(slot.snapshot().inhibited);
    }
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    candidate(&mut manager, 1);
    let instance = stage(&mut slot, &mut manager, None);
    let notice = spin::Mutex::new(None);
    latch_stop(
        &notice,
        StopNotice::Handoff {
            instance_id: instance + 1,
            error: HandoffError::TimedOut,
        },
    );
    apply_requested_stop(&mut slot, &notice);
    assert_eq!(slot.operation_error(instance), Some(kernel_abi::ECANCELED));
}

#[test]
fn cancelled_transport_cannot_assign_its_failure_to_a_new_preparation() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    candidate(&mut manager, 1);
    let old = stage(&mut slot, &mut manager, None);
    let mut handoff = peer_ready();
    let mut tx = TxState::new();
    let mut seq = 0;
    slot.handoff_boundary(release(1, 100, 100), 1000, &mut handoff, &mut tx, &mut seq)
        .unwrap();
    assert_eq!(handoff.operation(), Some(old));
    slot.cancel(old).unwrap();
    slot.abort_cancelled();
    drain(&mut slot, &mut manager);
    let new = stage(&mut slot, &mut manager, None);
    assert_ne!(new, old);
    assert_eq!(
        slot.handoff_boundary(release(2, 110, 110), 1000, &mut handoff, &mut tx, &mut seq),
        Err(HandoffError::Stale)
    );
    assert_eq!(slot.operation_error(new), Some(kernel_abi::ECANCELED));
    assert!(slot.snapshot().inhibited);
    assert_eq!(slot.snapshot().generation, 0);
}

fn costlier_artifact(revision: u64) -> BehaviorArtifact {
    let mut program = std::vec::Vec::new();
    for value in 0..32 {
        program.push(kernel_bpf::bytecode::insn::BpfInsn::mov64_imm(0, value));
    }
    program.push(kernel_bpf::bytecode::insn::BpfInsn::exit());
    artifact_from_program(revision, true, 0, None, &program)
}

#[test]
fn installation_a_b_c_rollback_keeps_actual_code_and_fresh_helper_state() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    assert_eq!(commit(&mut slot, id), 1);
    drain(&mut slot, &mut manager);
    let b = manager
        .register_managed_artifact(artifact_from_program(
            2,
            true,
            EFFECT_MOTOR_PAIR,
            Some(PrivateArray {
                value_size: 8,
                max_entries: 1,
            }),
            &stateful_managed_program(),
        ))
        .unwrap();
    manager.preparation.candidate = Some(b);
    let id = stage(&mut slot, &mut manager, None);
    assert_eq!(commit(&mut slot, id), 2);
    drain(&mut slot, &mut manager);
    let context = ManagedControlContextV1 {
        version: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_VERSION,
        size: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_SIZE,
        ..Default::default()
    };
    assert_eq!(slot.execute(&context).unwrap().motor_pair().left, 0);
    assert_eq!(slot.execute(&context).unwrap().motor_pair().left, 1);
    let c = candidate(&mut manager, 3);
    let id = stage(&mut slot, &mut manager, None);
    let before = manager.resource_usage();
    assert_eq!(commit(&mut slot, id), 3);
    assert_eq!(
        manager.resource_usage(),
        before,
        "publication refunds nothing"
    );
    let batch = slot.retire.as_ref().unwrap();
    assert!(batch.instance.is_some());
    assert_eq!(batch.artifact.as_ref().unwrap().handle, a);
    assert!(batch.evict_artifact);
    assert!(manager.managed_artifact(a).is_ok());
    drain(&mut slot, &mut manager);
    assert!(manager.managed_artifact(a).is_err());
    assert_eq!(slot.snapshot().previous, Some(b));
    let id = stage(&mut slot, &mut manager, Some(b));
    assert_eq!(commit(&mut slot, id), 4);
    assert!(!slot.retire.as_ref().unwrap().evict_artifact);
    drain(&mut slot, &mut manager);
    assert_eq!(slot.snapshot().active, Some(b));
    assert_eq!(slot.snapshot().previous, Some(c));
    assert!(manager.managed_artifact(b).is_ok());
    assert_eq!(slot.execute(&context).unwrap().motor_pair().left, 0);
    assert_eq!(slot.execute(&context).unwrap().motor_pair().left, 1);
}

#[test]
fn installation_stale_exhaustion_and_failed_build_preserve_active() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    candidate(&mut manager, 2);
    let before = slot.snapshot();
    let usage = manager.resource_usage();
    assert!(matches!(
        slot.begin(&mut manager, 0, None),
        Err(BpfError::NotLoaded)
    ));
    assert!(matches!(
        slot.begin(&mut manager, 1, Some(99)),
        Err(BpfError::NotLoaded)
    ));
    assert_eq!(slot.snapshot(), before);
    assert_eq!(manager.resource_usage(), usage);
    slot.generation = u64::MAX;
    assert!(matches!(
        slot.begin(&mut manager, u64::MAX, None),
        Err(BpfError::ResourceLimit)
    ));
    assert_eq!(
        manager.request_installation(
            &mut slot,
            0,
            u64::MAX,
            LifecycleTarget::Deactivate(before.active.unwrap()),
        ),
        Err(kernel_abi::EOVERFLOW)
    );
    assert_eq!(manager.resource_usage(), usage);
    assert!(!manager.managed_slot_busy);
    slot.generation = 1;
    let token = slot.begin(&mut manager, 1, None).unwrap();
    assert_eq!(
        slot.finish_build(&mut manager, token.fail()),
        Err(BpfError::ObjectBusy)
    );
    assert_eq!(slot.snapshot().active, before.active);
    assert!(!slot.snapshot().inhibited);
    drain(&mut slot, &mut manager);
    assert_eq!(manager.resource_usage(), usage);
    assert_eq!(slot.snapshot(), before);
}

#[test]
fn installation_cancel_and_stop_cover_worker_and_both_boundary_sides() {
    for stop in [false, true] {
        for phase in 0..4 {
            let mut manager = BpfManager::new();
            let mut slot = ControlSlot::new();
            let a = candidate(&mut manager, 1);
            let id = stage(&mut slot, &mut manager, None);
            commit(&mut slot, id);
            drain(&mut slot, &mut manager);
            let b = candidate(&mut manager, 2);
            let token = slot.begin(&mut manager, 1, None).unwrap();
            let id = slot.snapshot().pending.unwrap();
            let built = token.build();
            if phase >= 1 {
                slot.finish_build(&mut manager, built).unwrap();
            } else {
                if stop {
                    slot.stop();
                } else {
                    slot.cancel(id).unwrap();
                }
                assert_eq!(
                    slot.finish_build(&mut manager, built),
                    Err(BpfError::ObjectBusy)
                );
                assert_eq!(slot.snapshot().inhibited, stop);
                drain(&mut slot, &mut manager);
                assert_eq!(slot.snapshot().active, Some(a));
                continue;
            }
            if phase >= 2 {
                slot.enter_handoff(id).unwrap();
            }
            if phase == 3 {
                slot.commit_test_handoff(id).unwrap();
            }
            if stop {
                slot.stop();
            } else if phase == 3 {
                assert_eq!(slot.cancel(id), Err(BpfError::NotLoaded));
            } else {
                slot.cancel(id).unwrap();
            }
            if phase < 3 {
                assert_eq!(slot.commit_test_handoff(id), Err(BpfError::ObjectBusy));
                slot.abort_staged().unwrap();
            }
            assert_eq!(slot.snapshot().inhibited, stop || phase == 2);
            drain(&mut slot, &mut manager);
            assert_eq!(slot.snapshot().active, Some(if phase == 3 { b } else { a }));
            assert_eq!(slot.snapshot().generation, if phase == 3 { 2 } else { 1 });
        }
    }
}

#[test]
fn installation_retirement_retains_capacity_through_readers_release_and_refund() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let private_slot = manager
        .maps
        .iter()
        .position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.owner == crate::bpf::ObjectOwner::KernelManaged)
        })
        .unwrap();
    candidate(&mut manager, 3);
    let id = stage(&mut slot, &mut manager, None);
    let reader = slot.active.as_ref().unwrap().instance.clone();
    let weak_instance = Arc::downgrade(&reader);
    let weak_code = Arc::downgrade(manager.managed_artifact(a).unwrap());
    commit(&mut slot, id);
    let full = manager.resource_usage();
    assert!(matches!(
        slot.begin(&mut manager, 3, None),
        Err(BpfError::ObjectBusy)
    ));
    let mut retirement = slot.take_retirement().unwrap().release_references();
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    drop(reader);
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    drop(weak_instance);
    let map_reader = manager.maps[private_slot].as_ref().unwrap().runtime.clone();
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    drop(map_reader);
    manager.maps[private_slot]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .store(true, core::sync::atomic::Ordering::Release);
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    manager.maps[private_slot]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .store(false, core::sync::atomic::Ordering::Release);
    assert_eq!(manager.resource_usage(), full);
    let release = retirement.begin_release(&mut manager).unwrap().unwrap();
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    let receipt = release.release();
    assert_eq!(manager.resource_usage(), full);
    retirement.finish_release(&mut manager, receipt).unwrap();
    let after_instance = manager.resource_usage();
    assert!(matches!(
        retirement.begin_release(&mut manager),
        Err(BpfError::ObjectBusy)
    ));
    assert_eq!(manager.resource_usage(), after_instance);
    assert!(slot.snapshot().retiring);
    drop(weak_code);
    let release = retirement.begin_release(&mut manager).unwrap().unwrap();
    let receipt = release.release();
    assert!(slot.snapshot().retiring);
    assert_eq!(manager.resource_usage(), after_instance);
    retirement.finish_release(&mut manager, receipt).unwrap();
    slot.finish_retirement(&mut manager, retirement.complete().ok().unwrap())
        .unwrap();
    assert!(!slot.snapshot().retiring);
    assert!(manager.managed_artifact(a).is_err());
}

#[test]
fn installation_lost_release_receipt_never_reopens_capacity() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    let full = manager.resource_usage();
    let mut work = slot.take_retirement().unwrap().release_references();
    let release = work.begin_release(&mut manager).unwrap().unwrap();
    drop(release.release());
    assert_eq!(manager.resource_usage(), full);
    assert!(work.complete().is_err());
    assert!(slot.snapshot().retiring);
    assert!(manager.managed_slot_busy);
    assert!(matches!(
        manager.begin_managed_instance(slot.snapshot().active.unwrap()),
        Err(BpfError::ObjectBusy)
    ));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "100k host ownership churn; bounded cases run under Miri"
)]
fn installation_100000_transitions_bound_real_retention_and_high_water() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let b = candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);
    let floor = manager.resource_usage();
    let mut high_water = None;
    for generation in 3..=100_000 {
        let previous = slot.snapshot().previous.unwrap();
        let id = stage(&mut slot, &mut manager, Some(previous));
        let full = manager.resource_usage();
        if let Some(high_water) = high_water {
            assert_eq!(full, high_water);
        }
        high_water = Some(full);
        assert_eq!(commit(&mut slot, id), generation);
        assert_eq!(manager.resource_usage(), full);
        assert_eq!(manager.managed_instances.iter().flatten().count(), 2);
        drain(&mut slot, &mut manager);
        assert_eq!(manager.resource_usage(), floor);
        assert_eq!(manager.managed_instances.iter().flatten().count(), 1);
        // Manager + active instance + precloned Previous reference, or manager + Previous.
        let active = slot.snapshot().active.unwrap();
        assert_eq!(
            Arc::strong_count(manager.managed_artifact(active).unwrap()),
            3
        );
        assert_eq!(
            Arc::strong_count(
                manager
                    .managed_artifact(slot.snapshot().previous.unwrap())
                    .unwrap()
            ),
            2
        );
        assert!(active == a || active == b);
    }
    std::println!(
        "installation 100000: floor={floor:?}, high_water={high_water:?}, generation={}",
        slot.snapshot().generation
    );
}

#[test]
fn installation_rejected_completed_build_keeps_charge_until_worker_refund() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    candidate(&mut manager, 1);
    let floor = manager.resource_usage();
    let token = slot.begin(&mut manager, 0, None).unwrap();
    let built = token.build();
    let reserved = manager.resource_usage();
    manager.limits.max_map_slots = manager.maps.len();
    assert_eq!(
        slot.finish_build(&mut manager, built),
        Err(BpfError::ResourceLimit)
    );
    assert_eq!(manager.resource_usage(), reserved);
    let batch = slot.take_retirement().unwrap();
    assert!(batch.failed.is_some());
    let mut retirement = batch.release_references();
    assert_eq!(manager.resource_usage(), reserved);
    assert!(matches!(
        slot.begin(&mut manager, 0, None),
        Err(BpfError::ObjectBusy)
    ));
    assert!(retirement.begin_release(&mut manager).unwrap().is_none());
    assert_eq!(manager.resource_usage(), floor);
    slot.finish_retirement(&mut manager, retirement.complete().ok().unwrap())
        .unwrap();
    assert_eq!(slot.snapshot().generation, 0);
    assert!(slot.snapshot().inhibited);
}

#[test]
fn installation_duplicate_active_artifact_does_not_evict_new_previous() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    for _ in 0..2 {
        manager.preparation.candidate = Some(a);
        let id = stage(&mut slot, &mut manager, None);
        commit(&mut slot, id);
        drain(&mut slot, &mut manager);
    }
    assert_eq!(slot.snapshot().active, Some(a));
    assert_eq!(slot.snapshot().previous, Some(a));
    candidate(&mut manager, 2);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    assert!(!slot.retire.as_ref().unwrap().evict_artifact);
    drain(&mut slot, &mut manager);
    assert_eq!(slot.snapshot().previous, Some(a));
    assert!(manager.managed_artifact(a).is_ok());
}

#[test]
fn installation_admission_tracks_publication_then_worker_settlement() {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let artifact = artifact(1);
    let a_wcet = artifact.wcet_cycles();
    manager.admission = AdmissionLedger::new(u64::MAX, 1);
    let a = manager.register_managed_artifact(artifact).unwrap();
    manager.preparation.candidate = Some(a);

    let id = stage(&mut slot, &mut manager, None);
    assert_eq!(manager.admission.committed_ns_per_s(), 0);
    assert_eq!(manager.admission.reserved_ns_per_s(), a_wcet * 100);
    commit(&mut slot, id);
    assert_eq!(slot.snapshot().active_charge_ns_per_s, Some(a_wcet * 100));
    assert_eq!(manager.admission.committed_ns_per_s(), 0);
    drain(&mut slot, &mut manager);
    assert_eq!(manager.admission.committed_ns_per_s(), a_wcet * 100);

    let legacy_charge = 70;
    manager.admission.admit(91, 92, 7, 10).unwrap();
    let artifact = costlier_artifact(2);
    let b_wcet = artifact.wcet_cycles();
    assert!(b_wcet > a_wcet);
    let b = manager.register_managed_artifact(artifact).unwrap();
    manager.preparation.candidate = Some(b);
    let id = stage(&mut slot, &mut manager, None);
    assert_eq!(
        manager.admission.reserved_ns_per_s(),
        legacy_charge + b_wcet * 100
    );
    commit(&mut slot, id);
    assert_eq!(slot.snapshot().active_charge_ns_per_s, Some(b_wcet * 100));
    assert_eq!(
        manager.admission.committed_ns_per_s(),
        legacy_charge + a_wcet * 100
    );
    assert_eq!(
        manager.admission.reserved_ns_per_s(),
        legacy_charge + b_wcet * 100
    );
    drain(&mut slot, &mut manager);
    assert_eq!(
        manager.admission.committed_ns_per_s(),
        legacy_charge + b_wcet * 100
    );

    let id = stage(&mut slot, &mut manager, Some(a));
    assert_eq!(
        manager.admission.reserved_ns_per_s(),
        legacy_charge + b_wcet * 100,
        "rollback keeps the larger active charge reserved"
    );
    commit(&mut slot, id);
    assert_eq!(slot.snapshot().active_charge_ns_per_s, Some(a_wcet * 100));
    drain(&mut slot, &mut manager);
    assert_eq!(
        manager.admission.committed_ns_per_s(),
        legacy_charge + a_wcet * 100
    );
    slot.stop();
    assert_eq!(slot.snapshot().active_charge_ns_per_s, Some(a_wcet * 100));
    assert_eq!(
        manager.admission.committed_ns_per_s(),
        legacy_charge + a_wcet * 100
    );
}

#[test]
fn installation_admission_rejects_overbudget_candidate_without_touching_active() {
    let artifact = artifact(1);
    let a_wcet = artifact.wcet_cycles();
    let mut manager = BpfManager::new();
    manager.admission = AdmissionLedger::new(a_wcet * 100, 1);
    let mut slot = ControlSlot::new();
    let a = manager.register_managed_artifact(artifact).unwrap();
    manager.preparation.candidate = Some(a);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);

    let b = manager
        .register_managed_artifact(costlier_artifact(2))
        .unwrap();
    manager.preparation.candidate = Some(b);
    let before = slot.snapshot();
    assert!(matches!(
        slot.begin(&mut manager, before.generation, None),
        Err(BpfError::AdmissionRejected)
    ));
    assert_eq!(slot.snapshot(), before);
    assert_eq!(manager.admission.committed_ns_per_s(), a_wcet * 100);
    assert_eq!(manager.admission.reserved_ns_per_s(), a_wcet * 100);
    assert!(!manager.managed_slot_busy);
    assert!(manager.managed_instance_preparation.is_none());
}

#[test]
fn installation_admission_cancels_failed_construction_and_staged_work() {
    let artifact = artifact(1);
    let a_wcet = artifact.wcet_cycles();
    let mut manager = BpfManager::new();
    manager.admission = AdmissionLedger::new(u64::MAX, 1);
    let mut slot = ControlSlot::new();
    let a = manager.register_managed_artifact(artifact).unwrap();
    manager.preparation.candidate = Some(a);
    let id = stage(&mut slot, &mut manager, None);
    commit(&mut slot, id);
    drain(&mut slot, &mut manager);

    let artifact = costlier_artifact(2);
    let b_wcet = artifact.wcet_cycles();
    let b = manager.register_managed_artifact(artifact).unwrap();
    manager.preparation.candidate = Some(b);
    let before = slot.snapshot();
    let max_program_bytes = manager.limits.max_program_bytes;
    manager.limits.max_program_bytes = manager.resource_usage().program_bytes;
    assert!(matches!(
        slot.begin(&mut manager, before.generation, None),
        Err(BpfError::ResourceLimit)
    ));
    assert_eq!(slot.snapshot(), before);
    assert_eq!(manager.admission.committed_ns_per_s(), a_wcet * 100);
    assert_eq!(manager.admission.reserved_ns_per_s(), a_wcet * 100);
    assert!(!manager.managed_slot_busy);
    manager.limits.max_program_bytes = max_program_bytes;

    let token = slot.begin(&mut manager, before.generation, None).unwrap();
    let id = slot.snapshot().pending.unwrap();
    slot.finish_build(&mut manager, token.build()).unwrap();
    slot.cancel(id).unwrap();
    slot.abort_staged().unwrap();
    assert_eq!(slot.snapshot().active_charge_ns_per_s, Some(a_wcet * 100));
    assert_eq!(manager.admission.committed_ns_per_s(), a_wcet * 100);
    assert_eq!(manager.admission.reserved_ns_per_s(), b_wcet * 100);
    drain(&mut slot, &mut manager);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(manager.admission.committed_ns_per_s(), a_wcet * 100);
    assert_eq!(manager.admission.reserved_ns_per_s(), a_wcet * 100);
}

#[test]
fn installation_permanent_worker_retries_exact_retirement_until_readers_and_weak_release() {
    use kernel_abi::*;

    use crate::bpf::preparation::{LifecycleTarget, WorkerAction, WorkerState};
    let slot = spin::Mutex::new(ControlSlot::new());
    let manager = spin::Mutex::new(BpfManager::new());
    let mut worker = WorkerState::default();
    let service = |worker: &mut WorkerState| {
        for _ in 0..8 {
            let action = worker.take(&mut slot.lock(), &mut manager.lock());
            match action {
                WorkerAction::Wait => return true,
                WorkerAction::Retry => return false,
                action => worker.perform(action, &slot, &manager),
            }
        }
        panic!("bounded worker batch");
    };
    let mut last = 0;
    let mut handles = [0; 3];
    for revision in 1..=2 {
        let handle = candidate(&mut manager.lock(), revision);
        handles[revision as usize - 1] = handle;
        last = manager
            .lock()
            .request_installation(
                &mut slot.lock(),
                last,
                revision - 1,
                LifecycleTarget::Candidate(handle),
            )
            .unwrap();
        assert!(service(&mut worker));
        let id = slot.lock().snapshot().pending.unwrap();
        commit(&mut slot.lock(), id);
        assert!(service(&mut worker));
    }
    let reader = slot.lock().active.as_ref().unwrap().instance.clone();
    let weak_instance = Arc::downgrade(&reader);
    let weak_code = Arc::downgrade(manager.lock().managed_artifact(handles[0]).unwrap());
    let old_instance_id = slot.lock().active.as_ref().unwrap().instance_id;
    handles[2] = candidate(&mut manager.lock(), 3);
    last = manager
        .lock()
        .request_installation(
            &mut slot.lock(),
            last,
            2,
            LifecycleTarget::Candidate(handles[2]),
        )
        .unwrap();
    assert!(service(&mut worker));
    let private_id = slot.lock().snapshot().pending.unwrap();
    commit(&mut slot.lock(), private_id);
    let charged = manager.lock().resource_usage();
    assert!(!service(&mut worker));
    for _ in 0..3 {
        assert!(!service(&mut worker));
        assert_eq!(manager.lock().resource_usage(), charged);
        assert!(manager.lock().managed_slot_busy);
        assert_eq!(slot.lock().snapshot().active, Some(handles[2]));
        assert_eq!(
            manager.lock().request_installation(
                &mut slot.lock(),
                last,
                3,
                LifecycleTarget::Previous(handles[1])
            ),
            Err(EBUSY)
        );
        assert!(matches!(
            manager
                .lock()
                .begin_managed_instance_reclamation_for(old_instance_id),
            Err(BpfError::ObjectBusy)
        ));
    }
    drop(reader);
    assert!(!service(&mut worker));
    assert_eq!(manager.lock().resource_usage(), charged);
    drop(weak_instance);
    assert!(
        !service(&mut worker),
        "instance refund leaves artifact Weak outstanding"
    );
    let after_instance = manager.lock().resource_usage();
    assert!(after_instance.program_bytes < charged.program_bytes);
    assert!(slot.lock().snapshot().retiring);
    assert!(manager.lock().managed_slot_busy);
    assert_eq!(manager.lock().managed_instances.iter().flatten().count(), 1);
    assert!(!service(&mut worker));
    assert_eq!(manager.lock().resource_usage(), after_instance);
    drop(weak_code);
    assert!(service(&mut worker));
    assert!(manager.lock().managed_artifact(handles[0]).is_err());
    assert!(!slot.lock().snapshot().retiring);
    assert!(!manager.lock().managed_slot_busy);
    assert_eq!(
        manager.lock().managed_operation_query(last).unwrap().phase,
        MANAGED_OPERATION_COMMITTED
    );
    assert!(manager
        .lock()
        .request_installation(
            &mut slot.lock(),
            last,
            3,
            LifecycleTarget::Previous(handles[1])
        )
        .is_ok());
    let id = manager.lock().managed_operation_query(0).unwrap().id;
    manager
        .lock()
        .cancel_installation(
            &mut slot.lock(),
            id,
            3,
            LifecycleTarget::Previous(handles[1]),
        )
        .unwrap();
    assert!(service(&mut worker));
}

#[test]
fn installation_global_entries_reject_unqualified_host_without_cpu_mmio() {
    use crate::bpf::preparation::LifecycleTarget;
    assert!(!qualified_topology());
    assert_eq!(
        request_installation(0, 0, LifecycleTarget::Candidate(1)),
        Err(kernel_abi::ENOTSUP)
    );
    assert_eq!(query_installation(0), Err(kernel_abi::ENODEV));
    assert_eq!(
        cancel_installation(1, 0, LifecycleTarget::Candidate(1)),
        Err(kernel_abi::ENOTSUP)
    );
    assert!(matches!(
        try_release_boundary(|_| panic!("unqualified boundary must not run")),
        Err(BpfError::PermissionDenied)
    ));
}
