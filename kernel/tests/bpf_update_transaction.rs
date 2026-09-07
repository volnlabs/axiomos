#![cfg(all(
    feature = "bpf-update-diagnostics",
    feature = "bpf-unsigned-development"
))]

use std::sync::{mpsc, Arc, Barrier, Mutex};

use kernel::bpf::{
    BpfLoadAuthorization, BpfManager, ControlSlot, InstallError, InstallationId, MapAccess,
    StatePolicy, ATTACH_TYPE_SYS_ENTER,
};
use kernel_abi::BPF_MAP_TYPE_ARRAY;
use kernel_bpf::actuation::{AuditSource, Authority};
use kernel_bpf::attach::GpioEdge;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::execution::{BpfContext, BpfError};
use kernel_bpf::verifier::{HelperId, LoadCaller};

fn return_program(value: i32) -> Vec<BpfInsn> {
    vec![BpfInsn::mov64_imm(0, value), BpfInsn::exit()]
}

fn learned_program(value: i32) -> (Vec<BpfInsn>, BpfLoadAuthorization) {
    (
        return_program(value),
        BpfLoadAuthorization::new(LoadCaller::Unprivileged, false, MapAccess::NONE),
    )
}

fn unchanged(
    manager: &BpfManager,
    identity: InstallationId,
    charge: u64,
    receipt: kernel::bpf::InstallReceipt,
) {
    assert_eq!(manager.exclusive_timer_identity(), Some(identity));
    assert_eq!(manager.committed_exclusive_ns_per_s(), charge);
    assert_eq!(manager.last_install_receipt(), Some(receipt));
}

#[test]
fn replacement_rejections_preserve_publication_accounting_and_aba_identity() {
    // Raw programs are unsigned development fixtures. Authentication behavior
    // is intentionally outside this test's claim.
    let mut manager = BpfManager::new_with_admission_budget_for_diagnostics(2_000_000);
    let owner = 7;
    let (a_insns, learned) = learned_program(11);
    let a = manager
        .load_raw_program_authorized(owner, a_insns, learned)
        .expect("load A");
    let (mut b_insns, learned) = learned_program(22);
    b_insns.insert(1, BpfInsn::add64_imm(0, 1));
    let b = manager
        .load_raw_program_authorized(owner, b_insns, learned)
        .expect("load B");
    let (mut c_insns, learned) = learned_program(55);
    c_insns.insert(1, BpfInsn::add64_imm(0, 2));
    c_insns.insert(2, BpfInsn::add64_imm(0, 3));
    let c = manager
        .load_raw_program_authorized(owner, c_insns, learned)
        .expect("load C");
    let higher_authority = manager
        .load_raw_program_for(owner, return_program(33))
        .expect("load higher-authority candidate");
    let timer_invalid = manager
        .load_raw_program_authorized(
            owner,
            vec![
                BpfInsn::mov64_reg(6, 1),
                BpfInsn::new(0x79, 6, 1, 0, 0),
                BpfInsn::new(0x79, 0, 6, 0, 0),
                BpfInsn::mov64_imm(0, 0),
                BpfInsn::exit(),
            ],
            learned,
        )
        .expect("load program requiring nonempty hook context data");
    let map = manager
        .create_map_for(owner, BPF_MAP_TYPE_ARRAY, 4, 8, 1)
        .expect("create fixture map");
    let map_candidate = manager
        .load_raw_program_authorized(
            owner,
            vec![
                BpfInsn::mov64_imm(1, 0),
                BpfInsn::new(0x7b, 10, 1, -8, 0),
                BpfInsn::mov64_imm(1, map as i32),
                BpfInsn::mov64_reg(2, 10),
                BpfInsn::add64_imm(2, -8),
                BpfInsn::call(HelperId::MapLookupElem as i32),
                BpfInsn::mov64_imm(0, 0),
                BpfInsn::exit(),
            ],
            BpfLoadAuthorization::new(LoadCaller::Unprivileged, false, MapAccess::READ),
        )
        .expect("load map-bearing candidate");
    let mut expensive_insns = vec![BpfInsn::mov64_imm(0, 0)];
    expensive_insns.extend((0..300).map(|_| BpfInsn::add64_imm(0, 1)));
    expensive_insns.push(BpfInsn::exit());
    let expensive = manager
        .load_raw_program_authorized(owner, expensive_insns, learned)
        .expect("load schedulability-rejection candidate");
    let unrelated = manager
        .load_raw_program_for(8, return_program(44))
        .expect("load unrelated owner's program");

    #[cfg(feature = "verifier-cost")]
    {
        let cloned_before_install = manager.get_program_for(owner, a).unwrap();
        assert_eq!(
            manager.try_install_exclusive_for(owner, ControlSlot::Timer, a, StatePolicy::Reset),
            Err(InstallError::CandidateInUse)
        );
        drop(cloned_before_install);
    }

    let installed = manager
        .try_install_exclusive_for(owner, ControlSlot::Timer, a, StatePolicy::Reset)
        .expect("bootstrap A");
    assert_eq!(installed.previous, None);
    assert_eq!(
        installed.installed,
        InstallationId {
            program: a,
            epoch: 1
        }
    );
    assert!(installed.committed_exclusive_ns_per_s > 0);
    let a_charge = installed.committed_exclusive_ns_per_s;

    assert_eq!(
        manager.attach_for(owner, ATTACH_TYPE_SYS_ENTER, a),
        Err(BpfError::ObjectBusy)
    );
    assert_eq!(
        manager.attach_gpio_route_for(owner, 0, 17, GpioEdge::Rising, a),
        Err(BpfError::ObjectBusy)
    );
    assert_eq!(
        manager.execute(a, &BpfContext::empty()),
        Err(BpfError::ObjectBusy)
    );
    #[cfg(feature = "verifier-cost")]
    assert!(matches!(
        manager.get_program_for(owner, a),
        Err(BpfError::ObjectBusy)
    ));

    std::thread::scope(|scope| {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        scope.spawn(move || {
            BpfManager::observe_timer_exclusive(|identity| {
                assert_eq!(identity, installed.installed);
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap();
        });
        entered_rx.recv().unwrap();
        assert_eq!(
            manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                installed.installed,
                b,
                StatePolicy::Transfer
            ),
            Err(InstallError::StateTransferUnsupported)
        );
        assert_eq!(
            manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                installed.installed,
                map_candidate,
                StatePolicy::Reset
            ),
            Err(InstallError::PersistentStateUnsupported)
        );
        assert_eq!(
            manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                installed.installed,
                b,
                StatePolicy::Reset
            ),
            Err(InstallError::Busy)
        );
        assert!(!manager.reclaim_owner_for_diagnostics(owner));
        unchanged(&manager, installed.installed, a_charge, installed);
        assert!(manager.reclaim_owner_for_diagnostics(8));
        assert_eq!(
            manager.unload_program_for(8, unrelated),
            Err(BpfError::NotLoaded)
        );
        unchanged(&manager, installed.installed, a_charge, installed);
        release_tx.send(()).unwrap();
    });

    manager.attach_for(owner, ATTACH_TYPE_SYS_ENTER, b).unwrap();
    assert_eq!(
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset
        ),
        Err(InstallError::CandidateAttached)
    );
    manager.detach_for(owner, ATTACH_TYPE_SYS_ENTER, b).unwrap();
    for (candidate, error) in [
        (higher_authority, InstallError::AuthorityExceeded),
        (timer_invalid, InstallError::TimerVerificationFailed),
        (expensive, InstallError::AdmissionRejected),
    ] {
        assert_eq!(
            manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                installed.installed,
                candidate,
                StatePolicy::Reset
            ),
            Err(error)
        );
        unchanged(&manager, installed.installed, a_charge, installed);
    }

    manager.fail_next_exclusive_snapshot_for_diagnostics();
    assert_eq!(
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset
        ),
        Err(InstallError::SnapshotAllocationFailed)
    );
    unchanged(&manager, installed.installed, a_charge, installed);

    std::thread::scope(|scope| {
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        scope.spawn(move || {
            kernel::actuation::hold_actuation_gate_for_diagnostics(|| {
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });
        locked_rx.recv().unwrap();
        assert_eq!(
            manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                installed.installed,
                b,
                StatePolicy::Reset
            ),
            Err(InstallError::EmergencyStopBusy)
        );
        release_tx.send(()).unwrap();
    });
    kernel::actuation::ACTUATION_MONITOR
        .lock()
        .estop_trigger(AuditSource::Operator, 1);
    assert_eq!(
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset
        ),
        Err(InstallError::EmergencyStopActive)
    );
    kernel::actuation::ACTUATION_MONITOR.lock().estop_release(
        Authority::Operator,
        AuditSource::Operator,
        2,
    );

    let replaced = manager
        .try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset,
        )
        .expect("retry A -> B");
    assert_eq!(replaced.previous, Some(installed.installed));
    assert_eq!(
        replaced.installed,
        InstallationId {
            program: b,
            epoch: 2
        }
    );
    assert!(replaced.admission_delta_ns_per_s > 0);
    assert_eq!(
        manager.committed_exclusive_ns_per_s(),
        replaced.committed_exclusive_ns_per_s
    );

    let rolled_back = manager
        .try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            replaced.installed,
            a,
            StatePolicy::Reset,
        )
        .expect("rollback B -> A");
    assert_eq!(
        rolled_back.installed,
        InstallationId {
            program: a,
            epoch: 3
        }
    );
    assert_eq!(
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset
        ),
        Err(InstallError::StaleInstallation {
            expected: installed.installed,
            current: Some(rolled_back.installed)
        })
    );

    let manager = Arc::new(Mutex::new(manager));
    let start = Arc::new(Barrier::new(3));
    let (b_result, c_result) = std::thread::scope(|scope| {
        let b_manager = Arc::clone(&manager);
        let b_start = Arc::clone(&start);
        let b_proposer = scope.spawn(move || {
            b_start.wait();
            b_manager.lock().unwrap().try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                rolled_back.installed,
                b,
                StatePolicy::Reset,
            )
        });
        let c_manager = Arc::clone(&manager);
        let c_start = Arc::clone(&start);
        let c_proposer = scope.spawn(move || {
            c_start.wait();
            c_manager.lock().unwrap().try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                rolled_back.installed,
                c,
                StatePolicy::Reset,
            )
        });
        start.wait();
        (b_proposer.join().unwrap(), c_proposer.join().unwrap())
    });
    let (winner, stale) = match (b_result, c_result) {
        (Ok(winner), Err(stale)) | (Err(stale), Ok(winner)) => (winner, stale),
        results => panic!("expected exactly one successful proposer, got {results:?}"),
    };
    assert!(winner.installed.program == b || winner.installed.program == c);
    assert_eq!(winner.installed.epoch, 4);
    assert_eq!(
        stale,
        InstallError::StaleInstallation {
            expected: rolled_back.installed,
            current: Some(winner.installed),
        }
    );
    let mutex = Arc::into_inner(manager).expect("proposer references dropped");
    let mut manager = mutex
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(manager.exclusive_timer_identity(), Some(winner.installed));
    assert_eq!(manager.last_install_receipt(), Some(winner));
    assert_eq!(
        manager.committed_exclusive_ns_per_s(),
        winner.committed_exclusive_ns_per_s
    );
    assert_eq!(
        i128::from(rolled_back.committed_exclusive_ns_per_s) + winner.admission_delta_ns_per_s,
        i128::from(winner.committed_exclusive_ns_per_s)
    );
    BpfManager::observe_timer_exclusive(|identity| {
        assert_eq!(identity, winner.installed);
    })
    .unwrap();
    assert_eq!(
        BpfManager::observe_timer_atomic_without_quiescence(|_| ()),
        Err(kernel::bpf::HookRunError::Execution(BpfError::ObjectBusy))
    );
    let guarded_alternative = if winner.installed.program == b { c } else { b };
    assert_eq!(
        manager.try_replace_atomic_without_quiescence_for(
            owner,
            ControlSlot::Timer,
            winner.installed,
            guarded_alternative,
            StatePolicy::Reset,
        ),
        Err(InstallError::Busy)
    );
    BpfManager::hold_timer_exclusive_transition_for_diagnostics(|| {
        assert_eq!(
            BpfManager::observe_timer_exclusive(|_| ()),
            Err(kernel::bpf::HookRunError::TransitionBusy)
        );
    })
    .unwrap();

    manager.force_timer_epoch_for_diagnostics(u64::MAX);
    let next_candidate = if winner.installed.program == b { c } else { b };
    assert_eq!(
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            winner.installed,
            next_candidate,
            StatePolicy::Reset
        ),
        Err(InstallError::EpochExhausted)
    );
    unchanged(
        &manager,
        winner.installed,
        winner.committed_exclusive_ns_per_s,
        winner,
    );

    manager
        .clear_exclusive_for_diagnostics(owner, winner.installed)
        .unwrap();
    manager.force_timer_epoch_for_diagnostics(winner.installed.epoch);
    let atomic_a = manager
        .try_install_atomic_without_quiescence_for(owner, ControlSlot::Timer, a, StatePolicy::Reset)
        .expect("bootstrap atomic baseline A");
    assert_eq!(
        BpfManager::observe_timer_exclusive(|_| ()),
        Err(kernel::bpf::HookRunError::Execution(BpfError::ObjectBusy))
    );
    assert_eq!(
        manager.try_replace_atomic_without_quiescence_for(
            owner,
            ControlSlot::Timer,
            winner.installed,
            next_candidate,
            StatePolicy::Reset,
        ),
        Err(InstallError::StaleInstallation {
            expected: winner.installed,
            current: Some(atomic_a.installed),
        })
    );
    unchanged(
        &manager,
        atomic_a.installed,
        atomic_a.committed_exclusive_ns_per_s,
        atomic_a,
    );
    assert_eq!(
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            atomic_a.installed,
            next_candidate,
            StatePolicy::Reset,
        ),
        Err(InstallError::Busy)
    );
    unchanged(
        &manager,
        atomic_a.installed,
        atomic_a.committed_exclusive_ns_per_s,
        atomic_a,
    );

    for (candidate, state, error) in [
        (
            next_candidate,
            StatePolicy::Transfer,
            InstallError::StateTransferUnsupported,
        ),
        (
            map_candidate,
            StatePolicy::Reset,
            InstallError::PersistentStateUnsupported,
        ),
        (
            higher_authority,
            StatePolicy::Reset,
            InstallError::AuthorityExceeded,
        ),
        (
            expensive,
            StatePolicy::Reset,
            InstallError::AdmissionRejected,
        ),
    ] {
        assert_eq!(
            manager.try_replace_atomic_without_quiescence_for(
                owner,
                ControlSlot::Timer,
                atomic_a.installed,
                candidate,
                state,
            ),
            Err(error)
        );
        unchanged(
            &manager,
            atomic_a.installed,
            atomic_a.committed_exclusive_ns_per_s,
            atomic_a,
        );
    }
    manager.fail_next_exclusive_snapshot_for_diagnostics();
    assert_eq!(
        manager.try_replace_atomic_without_quiescence_for(
            owner,
            ControlSlot::Timer,
            atomic_a.installed,
            next_candidate,
            StatePolicy::Reset,
        ),
        Err(InstallError::SnapshotAllocationFailed)
    );
    unchanged(
        &manager,
        atomic_a.installed,
        atomic_a.committed_exclusive_ns_per_s,
        atomic_a,
    );

    let (a_entered_tx, a_entered_rx) = mpsc::channel();
    let (release_a_tx, release_a_rx) = mpsc::channel();
    let atomic_b = std::thread::scope(|scope| {
        scope.spawn(move || {
            BpfManager::observe_timer_atomic_without_quiescence(|identity| {
                assert_eq!(identity, atomic_a.installed);
                a_entered_tx.send(()).unwrap();
                release_a_rx.recv().unwrap();
            })
            .unwrap();
        });
        a_entered_rx.recv().unwrap();
        let writer = scope.spawn(|| {
            manager.try_replace_atomic_without_quiescence_for(
                owner,
                ControlSlot::Timer,
                atomic_a.installed,
                next_candidate,
                StatePolicy::Reset,
            )
        });
        loop {
            let observed = BpfManager::observe_timer_atomic_without_quiescence(|id| id).unwrap();
            if observed.program == next_candidate {
                assert_eq!(observed.epoch, atomic_a.installed.epoch + 1);
                assert!(
                    !writer.is_finished(),
                    "writer returned before A guard drained"
                );
                break;
            }
            std::thread::yield_now();
        }
        release_a_tx.send(()).unwrap();
        writer.join().unwrap().expect("atomic A -> B replacement")
    });
    assert_eq!(atomic_b.previous, Some(atomic_a.installed));
    assert_eq!(atomic_b.installed.program, next_candidate);
    assert_eq!(
        manager.last_install_receipt(),
        Some(atomic_b),
        "receipt becomes visible with the completed manager operation"
    );
    assert_eq!(
        manager.committed_exclusive_ns_per_s(),
        atomic_b.committed_exclusive_ns_per_s
    );
    manager
        .clear_exclusive_for_diagnostics(owner, atomic_b.installed)
        .unwrap();

    kernel::actuation::ACTUATION_MONITOR
        .lock()
        .estop_trigger(AuditSource::Operator, 3);
    assert!(manager.reclaim_owner_for_diagnostics(owner));
    assert_eq!(manager.exclusive_timer_identity(), None);
    kernel::actuation::ACTUATION_MONITOR.lock().estop_release(
        Authority::Operator,
        AuditSource::Operator,
        4,
    );
}
