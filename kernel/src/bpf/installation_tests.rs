extern crate std;
use kernel_bpf::signing::managed::{PrivateArray, EFFECT_MOTOR_PAIR};

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
    slot.commit_validated_handoff(id).unwrap()
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
                slot.commit_validated_handoff(id).unwrap();
            }
            if stop {
                slot.stop();
            } else if phase == 3 {
                assert_eq!(slot.cancel(id), Err(BpfError::NotLoaded));
            } else {
                slot.cancel(id).unwrap();
            }
            if phase < 3 {
                assert_eq!(slot.commit_validated_handoff(id), Err(BpfError::ObjectBusy));
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
