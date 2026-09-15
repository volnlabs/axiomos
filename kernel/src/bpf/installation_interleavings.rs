//! Bounded single-CPU schedules across the managed publication entry points.
//! Every step calls the production state machines; schedule cuts represent the
//! points at which an IRQ-masked atomic entry can hand control to another task.

use super::*;
use crate::bpf::preparation::{LifecycleTarget, WorkerAction, WorkerState};

fn active_a() -> (BpfManager, ControlSlot, u32) {
    let mut manager = BpfManager::new();
    let mut slot = ControlSlot::new();
    let a = candidate(&mut manager, 1);
    let id = stage(&mut slot, &mut manager, None);
    assert_eq!(commit(&mut slot, id), 1);
    drain(&mut slot, &mut manager);
    (manager, slot, a)
}

fn settle_worker(
    worker: &mut WorkerState,
    slot: &spin::Mutex<ControlSlot>,
    manager: &spin::Mutex<BpfManager>,
) {
    for _ in 0..8 {
        let action = worker.take(&mut slot.lock(), &mut manager.lock());
        match action {
            WorkerAction::Wait => return,
            WorkerAction::Retry => panic!("schedule retains no external reader"),
            action => worker.perform(action, slot, manager),
        }
    }
    panic!("bounded worker settlement exceeded");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScheduleEvent {
    StaleWriter,
    DuplicateWriter,
    CancelOrStop,
    WorkerTake,
    WorkerPublish,
}

fn permutations(
    events: &mut [ScheduleEvent; 5],
    next: usize,
    visit: &mut impl FnMut(&[ScheduleEvent; 5]),
) {
    if next == events.len() {
        visit(events);
        return;
    }
    for choice in next..events.len() {
        events.swap(next, choice);
        permutations(events, next + 1, visit);
        events.swap(next, choice);
    }
}

#[test]
fn all_legal_writer_cancel_stop_and_worker_schedules_preserve_the_active_installation() {
    let mut events = [
        ScheduleEvent::StaleWriter,
        ScheduleEvent::DuplicateWriter,
        ScheduleEvent::CancelOrStop,
        ScheduleEvent::WorkerTake,
        ScheduleEvent::WorkerPublish,
    ];
    let mut legal_histories = 0;
    permutations(&mut events, 0, &mut |history| {
        let take = history
            .iter()
            .position(|event| *event == ScheduleEvent::WorkerTake)
            .unwrap();
        let publish = history
            .iter()
            .position(|event| *event == ScheduleEvent::WorkerPublish)
            .unwrap();
        if take > publish {
            return;
        }
        for stop in [false, true] {
            legal_histories += 1;
            let (manager, slot, a) = active_a();
            let baseline_admission = manager.admission.committed_ns_per_s();
            let manager = spin::Mutex::new(manager);
            let slot = spin::Mutex::new(slot);
            let mut worker = WorkerState::default();
            let mut owned = None;

            let b = candidate(&mut manager.lock(), 2);
            let public_id = manager
                .lock()
                .request_installation(&mut slot.lock(), 0, 1, LifecycleTarget::Candidate(b))
                .unwrap();
            let accepted_admission = manager.lock().admission.reserved_ns_per_s();
            for event in history {
                match event {
                    ScheduleEvent::StaleWriter | ScheduleEvent::DuplicateWriter => {
                        let before = slot.lock().snapshot();
                        let before_admission = manager.lock().admission.reserved_ns_per_s();
                        let expected_last = if *event == ScheduleEvent::StaleWriter {
                            0
                        } else {
                            public_id
                        };
                        let expected_error = if *event == ScheduleEvent::StaleWriter {
                            kernel_abi::ESTALE
                        } else {
                            kernel_abi::EBUSY
                        };
                        assert_eq!(
                            manager.lock().request_installation(
                                &mut slot.lock(),
                                expected_last,
                                1,
                                LifecycleTarget::Candidate(b),
                            ),
                            Err(expected_error),
                            "history {history:?}, stop {stop}"
                        );
                        assert_eq!(slot.lock().snapshot(), before);
                        assert_eq!(
                            manager.lock().admission.reserved_ns_per_s(),
                            before_admission
                        );
                    }
                    ScheduleEvent::CancelOrStop => {
                        if stop {
                            slot.lock().stop();
                        } else {
                            manager
                                .lock()
                                .cancel_installation(
                                    &mut slot.lock(),
                                    public_id,
                                    1,
                                    LifecycleTarget::Candidate(b),
                                )
                                .unwrap();
                        }
                    }
                    ScheduleEvent::WorkerTake => {
                        let action = worker.take(&mut slot.lock(), &mut manager.lock());
                        assert!(matches!(&action, WorkerAction::Install(_, _)));
                        assert!(owned.replace(action).is_none());
                    }
                    ScheduleEvent::WorkerPublish => {
                        worker.perform(owned.take().unwrap(), &slot, &manager);
                    }
                }
            }

            let before_settlement = slot.lock().snapshot();
            assert_eq!(
                (before_settlement.active, before_settlement.generation),
                (Some(a), 1),
                "history {history:?}, stop {stop}"
            );
            assert_eq!(before_settlement.inhibited, stop);
            assert!(manager.lock().managed_slot_busy);
            assert_eq!(
                manager.lock().admission.reserved_ns_per_s(),
                accepted_admission
            );
            settle_worker(&mut worker, &slot, &manager);

            let final_slot = slot.lock().snapshot();
            assert_eq!((final_slot.active, final_slot.generation), (Some(a), 1));
            assert_eq!(final_slot.inhibited, stop);
            assert!(!final_slot.retiring);
            assert_eq!(manager.lock().preparation.candidate, Some(b));
            assert!(!manager.lock().managed_slot_busy);
            assert_eq!(
                manager.lock().admission.committed_ns_per_s(),
                baseline_admission
            );
            assert_eq!(
                manager.lock().admission.reserved_ns_per_s(),
                baseline_admission
            );
        }
    });
    assert_eq!(legal_histories, 120);
}

#[test]
fn stop_before_or_after_release_commit_has_one_authoritative_generation() {
    for stop_before_commit in [true, false] {
        let (mut manager, mut slot, a) = active_a();
        let baseline_admission = manager.admission.committed_ns_per_s();
        let b = candidate(&mut manager, 2);
        let private_id = stage(&mut slot, &mut manager, None);
        let staged_admission = manager.admission.reserved_ns_per_s();
        let mut handoff = peer_ready();
        let mut tx = TxState::new();
        let mut sequence = 0;

        assert_eq!(
            slot.handoff_boundary(
                release(1, 100, 100),
                1000,
                &mut handoff,
                &mut tx,
                &mut sequence,
                0,
            ),
            Ok(None)
        );
        acknowledge(&mut handoff, &mut tx, 101, 102);

        if stop_before_commit {
            slot.stop();
            assert_eq!(
                slot.handoff_boundary(
                    release(2, 110, 110),
                    1000,
                    &mut handoff,
                    &mut tx,
                    &mut sequence,
                    0,
                ),
                Err(HandoffError::Stale)
            );
            assert_eq!(
                (slot.snapshot().active, slot.snapshot().generation),
                (Some(a), 1)
            );
            assert!(slot.snapshot().inhibited);
            assert_eq!(slot.abort_staged(), Ok(()));
            assert!(slot.snapshot().retiring);
            assert!(manager.managed_slot_busy);
            assert_eq!(manager.admission.reserved_ns_per_s(), staged_admission);
            drain(&mut slot, &mut manager);
            assert_eq!(
                (slot.snapshot().active, slot.snapshot().generation),
                (Some(a), 1)
            );
            assert_eq!(manager.preparation.candidate, Some(b));
            assert_eq!(manager.admission.committed_ns_per_s(), baseline_admission);
        } else {
            assert_eq!(
                slot.handoff_boundary(
                    release(2, 110, 110),
                    1000,
                    &mut handoff,
                    &mut tx,
                    &mut sequence,
                    0,
                ),
                Ok(Some(2))
            );
            assert_eq!(
                (slot.snapshot().active, slot.snapshot().generation),
                (Some(b), 2)
            );
            assert!(slot.snapshot().retiring);
            assert!(manager.managed_slot_busy);
            assert_eq!(manager.admission.committed_ns_per_s(), baseline_admission);
            assert_eq!(manager.admission.reserved_ns_per_s(), staged_admission);
            slot.stop();
            assert_eq!(
                (slot.snapshot().active, slot.snapshot().generation),
                (Some(b), 2)
            );
            assert!(slot.snapshot().inhibited);
            drain(&mut slot, &mut manager);
            assert_eq!(
                (slot.snapshot().active, slot.snapshot().generation),
                (Some(b), 2)
            );
            assert_eq!(manager.preparation.candidate, None);
            assert_eq!(
                manager.admission.committed_ns_per_s(),
                slot.snapshot().active_charge_ns_per_s.unwrap()
            );
        }
        assert!(!slot.snapshot().retiring);
        assert!(!manager.managed_slot_busy);
        assert_eq!(slot.snapshot().pending, None);
        assert_ne!(private_id, 0);
    }
}

#[test]
fn stale_a_b_a_operation_and_generation_ids_cannot_republish() {
    let (mut manager, mut slot, a) = active_a();
    let first_a = slot.active.as_ref().unwrap().instance_id;

    let b = candidate(&mut manager, 2);
    let b_id = stage(&mut slot, &mut manager, None);
    assert_eq!(commit(&mut slot, b_id), 2);
    drain(&mut slot, &mut manager);

    let second_a = stage(&mut slot, &mut manager, Some(a));
    assert_eq!(commit(&mut slot, second_a), 3);
    assert_eq!(
        (slot.snapshot().active, slot.snapshot().previous),
        (Some(a), Some(b))
    );
    assert!(slot.snapshot().retiring);
    assert!(manager.managed_slot_busy);
    let authoritative = slot.snapshot();
    let admission = (
        manager.admission.committed_ns_per_s(),
        manager.admission.reserved_ns_per_s(),
    );

    for stale in [first_a, b_id] {
        assert_ne!(stale, second_a);
        assert_eq!(slot.cancel(stale), Err(BpfError::NotLoaded));
        assert_eq!(slot.commit_test_handoff(stale), Err(BpfError::NotLoaded));
        assert_eq!(slot.snapshot(), authoritative);
        assert_eq!(
            (
                manager.admission.committed_ns_per_s(),
                manager.admission.reserved_ns_per_s(),
            ),
            admission
        );
    }
    assert!(matches!(
        slot.begin(&mut manager, 1, None),
        Err(BpfError::NotLoaded)
    ));
    assert_eq!(slot.snapshot(), authoritative);

    drain(&mut slot, &mut manager);
    let settled = slot.snapshot();
    assert_eq!((settled.active, settled.previous), (Some(a), Some(b)));
    assert_eq!(settled.generation, 3);
    assert!(!settled.inhibited);
    assert!(!settled.retiring);
    assert_eq!(manager.preparation.candidate, None);
    assert!(!manager.managed_slot_busy);
    assert_eq!(
        manager.admission.committed_ns_per_s(),
        settled.active_charge_ns_per_s.unwrap()
    );
}
