//! Host-only paired manager publication campaign. Raw fixtures require
//! `bpf-unsigned-development`.

#![cfg(all(
    feature = "bpf-update-diagnostics",
    feature = "bpf-unsigned-development"
))]

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier, Mutex};

use kernel::bpf::{
    BpfLoadAuthorization, BpfManager, ControlSlot, HookRunError, InstallError, InstallReceipt,
    InstallationId, MapAccess, ProgramHandle, StatePolicy, ATTACH_TYPE_SYS_ENTER,
    ATTACH_TYPE_TIMER,
};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::execution::BpfError;
use kernel_bpf::verifier::{HelperId, LoadCaller};

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    snapshot: Vec<ProgramHandle>,
    installation: Option<InstallationId>,
    committed: Option<u64>,
    receipt: Option<InstallReceipt>,
    guards: Vec<InstallationId>,
}

struct Attempt {
    candidate: ProgramHandle,
    outcome: String,
}

struct Record {
    case: &'static str,
    request_id: usize,
    before: State,
    observations: Vec<State>,
    after: State,
    outcome: String,
    attempts: Vec<Attempt>,
    expected: Option<InstallationId>,
    candidate: ProgramHandle,
    skipped_dispatches: usize,
    ordinary_charge: Option<u64>,
    scope: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publication {
    Atomic,
    Transactional,
}

impl Publication {
    fn protocol(self) -> &'static str {
        match self {
            Self::Atomic => "atomic_publication",
            Self::Transactional => "transactional",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Atomic => "bpf_manager_atomic_without_quiescence",
            Self::Transactional => "bpf_manager_guarded",
        }
    }

    fn install(
        self,
        manager: &mut BpfManager,
        owner: u64,
        candidate: ProgramHandle,
    ) -> Result<InstallReceipt, InstallError> {
        match self {
            Self::Atomic => manager.try_install_atomic_without_quiescence_for(
                owner,
                ControlSlot::Timer,
                candidate,
                StatePolicy::Reset,
            ),
            Self::Transactional => manager.try_install_exclusive_for(
                owner,
                ControlSlot::Timer,
                candidate,
                StatePolicy::Reset,
            ),
        }
    }

    fn replace(
        self,
        manager: &mut BpfManager,
        owner: u64,
        expected: InstallationId,
        candidate: ProgramHandle,
    ) -> Result<InstallReceipt, InstallError> {
        match self {
            Self::Atomic => manager.try_replace_atomic_without_quiescence_for(
                owner,
                ControlSlot::Timer,
                expected,
                candidate,
                StatePolicy::Reset,
            ),
            Self::Transactional => manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                expected,
                candidate,
                StatePolicy::Reset,
            ),
        }
    }

    fn observe<R>(self, observer: impl FnOnce(InstallationId) -> R) -> Result<R, HookRunError> {
        match self {
            Self::Atomic => BpfManager::observe_timer_atomic_without_quiescence(observer),
            Self::Transactional => BpfManager::observe_timer_exclusive(observer),
        }
    }
}

fn program(value: i32) -> Vec<BpfInsn> {
    vec![BpfInsn::mov64_imm(0, value), BpfInsn::exit()]
}

fn learned_program(value: i32, additions: usize) -> (Vec<BpfInsn>, BpfLoadAuthorization) {
    let mut insns = vec![BpfInsn::mov64_imm(0, value)];
    insns.extend((0..additions).map(|_| BpfInsn::add64_imm(0, 1)));
    insns.push(BpfInsn::exit());
    (
        insns,
        BpfLoadAuthorization::new(LoadCaller::Unprivileged, false, MapAccess::NONE),
    )
}

fn timed_program(calls: usize) -> Vec<BpfInsn> {
    let mut insns = Vec::with_capacity(calls + 1);
    for _ in 0..calls {
        insns.push(BpfInsn::call(HelperId::KtimeGetNs as i32));
    }
    insns.push(BpfInsn::exit());
    insns
}

fn budget_background(
    manager: &mut BpfManager,
    owner: u64,
) -> (ProgramHandle, u64, ProgramHandle, u64) {
    let first = manager
        .load_raw_program_for(owner, timed_program(7_000))
        .unwrap();
    let second = manager
        .load_raw_program_for(owner, timed_program(7_000))
        .unwrap();
    manager
        .attach_for(owner, ATTACH_TYPE_SYS_ENTER, first)
        .unwrap();
    let first_cost = manager.committed_total_ns_per_s();
    manager
        .attach_for(owner, ATTACH_TYPE_SYS_ENTER, second)
        .unwrap();
    let second_cost = manager.committed_total_ns_per_s() - first_cost;
    (first, first_cost, second, second_cost)
}

fn result_name<T>(result: &Result<T, impl core::fmt::Debug>) -> String {
    match result {
        Ok(_) => "Ok".into(),
        Err(error) => format!("{error:?}"),
    }
}

fn attempt<T>(candidate: ProgramHandle, result: &Result<T, impl core::fmt::Debug>) -> Attempt {
    Attempt {
        candidate,
        outcome: result_name(result),
    }
}

fn json_id(id: InstallationId) -> String {
    format!("[{},{}]", id.program, id.epoch)
}

fn json_ids(ids: &[InstallationId]) -> String {
    format!(
        "[{}]",
        ids.iter()
            .copied()
            .map(json_id)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_handles(handles: &[ProgramHandle]) -> String {
    format!(
        "[{}]",
        handles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_receipt(receipt: Option<InstallReceipt>) -> String {
    receipt.map_or_else(
        || "null".into(),
        |receipt| {
            format!(
                "{{\"previous\":{},\"installed\":{},\"admission_delta\":{},\"committed\":{}}}",
                receipt
                    .previous
                    .map(json_id)
                    .unwrap_or_else(|| "null".into()),
                json_id(receipt.installed),
                receipt.admission_delta_ns_per_s,
                receipt.committed_exclusive_ns_per_s,
            )
        },
    )
}

fn json_state(state: &State) -> String {
    format!(
        "{{\"snapshot\":{},\"installation\":{},\"committed\":{},\"receipt\":{},\"guards\":{}}}",
        json_handles(&state.snapshot),
        state
            .installation
            .map(json_id)
            .unwrap_or_else(|| "null".into()),
        state
            .committed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".into()),
        json_receipt(state.receipt),
        json_ids(&state.guards),
    )
}

fn emit(protocol: &str, costs: &BTreeMap<ProgramHandle, u64>, record: Record) {
    let json_costs = costs
        .iter()
        .map(|(handle, cost)| format!("\"{handle}\":{cost}"))
        .collect::<Vec<_>>()
        .join(",");
    let observations = record
        .observations
        .iter()
        .map(json_state)
        .collect::<Vec<_>>()
        .join(",");
    let attempts = record
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "{{\"candidate\":{},\"outcome\":\"{}\"}}",
                attempt.candidate, attempt.outcome
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "UPDATE_TXN {{\"schema\":2,\"protocol\":\"{protocol}\",\"scope\":\"{}\",\"case\":\"{}\",\"request_id\":{},\"before\":{},\"observations\":[{}],\"after\":{},\"costs\":{{{json_costs}}},\"ordinary_charge\":{},\"outcome\":\"{}\",\"attempts\":[{}],\"expected\":{},\"candidate\":{},\"skipped_dispatches\":{}}}",
        record.scope,
        record.case,
        record.request_id,
        json_state(&record.before),
        observations,
        json_state(&record.after),
        record
            .ordinary_charge
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".into()),
        record.outcome,
        attempts,
        record
            .expected
            .map(json_id)
            .unwrap_or_else(|| "null".into()),
        record.candidate,
        record.skipped_dispatches,
    );
}

fn manager_state(publication: Publication, manager: &BpfManager) -> State {
    let installation = manager.exclusive_timer_identity();
    let committed = manager.committed_total_ns_per_s();
    let receipt = manager.last_install_receipt();
    publication
        .observe(|id| State {
            snapshot: vec![id.program],
            installation,
            committed: Some(committed),
            receipt,
            guards: vec![id],
        })
        .unwrap()
}

fn held_manager_state(manager: &BpfManager, id: InstallationId) -> State {
    State {
        snapshot: vec![id.program],
        installation: manager.exclusive_timer_identity(),
        committed: Some(manager.committed_total_ns_per_s()),
        receipt: manager.last_install_receipt(),
        guards: vec![id],
    }
}

fn hook_state(manager: &BpfManager) -> State {
    let snapshot = BpfManager::observe_hook_snapshot(ATTACH_TYPE_TIMER, |handles| handles.to_vec())
        .unwrap_or_default();
    State {
        snapshot,
        installation: None,
        committed: Some(manager.committed_total_ns_per_s()),
        receipt: None,
        guards: Vec::new(),
    }
}

fn preserved(before: &State, after: &State) {
    assert_eq!(before.snapshot, after.snapshot);
    assert_eq!(before.installation, after.installation);
    assert_eq!(before.committed, after.committed);
    assert_eq!(before.receipt, after.receipt);
}

fn record_failure(
    records: &mut Vec<Record>,
    publication: Publication,
    case: &'static str,
    request_id: usize,
    before: State,
    after: State,
    expected: InstallationId,
    candidate: ProgramHandle,
    ordinary_charge: u64,
    outcome: String,
) {
    preserved(&before, &after);
    records.push(Record {
        case,
        request_id,
        before,
        observations: Vec::new(),
        after,
        attempts: vec![Attempt {
            candidate,
            outcome: outcome.clone(),
        }],
        outcome,
        expected: Some(expected),
        candidate,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: publication.scope(),
    });
}

fn paired_manager(publication: Publication) {
    let mut manager = BpfManager::new();
    let owner = 7;
    let (a_program, learned) = learned_program(11, 0);
    let a = manager
        .load_raw_program_authorized(owner, a_program, learned)
        .unwrap();
    let (b_program, learned) = learned_program(22, 1);
    let b = manager
        .load_raw_program_authorized(owner, b_program, learned)
        .unwrap();
    let (c_program, learned) = learned_program(33, 2);
    let c = manager
        .load_raw_program_authorized(owner, c_program, learned)
        .unwrap();
    let higher_authority = manager.load_raw_program_for(owner, program(44)).unwrap();
    let (background_a, background_a_cost, background_b, background_b_cost) =
        budget_background(&mut manager, owner);
    let heavy = manager
        .load_raw_program_authorized(owner, timed_program(7_000), learned)
        .unwrap();
    let ordinary_charge = background_a_cost + background_b_cost;

    let mut costs = BTreeMap::new();
    for handle in [a, b, c] {
        manager
            .attach_for(owner, ATTACH_TYPE_TIMER, handle)
            .unwrap();
        costs.insert(handle, manager.committed_total_ns_per_s() - ordinary_charge);
        manager.detach(ATTACH_TYPE_TIMER, handle).unwrap();
    }

    let mut records = Vec::new();
    let installed_a = publication.install(&mut manager, owner, a).unwrap();
    assert_eq!(manager.last_install_receipt(), Some(installed_a));

    let before = manager_state(publication, &manager);
    manager.fail_next_exclusive_snapshot_for_diagnostics();
    let outcome = publication.replace(&mut manager, owner, installed_a.installed, b);
    assert_eq!(outcome, Err(InstallError::SnapshotAllocationFailed));
    let after = manager_state(publication, &manager);
    record_failure(
        &mut records,
        publication,
        "snapshot_prep_failure",
        0,
        before,
        after,
        installed_a.installed,
        b,
        ordinary_charge,
        result_name(&outcome),
    );

    let before = manager_state(publication, &manager);
    let outcome = publication.replace(&mut manager, owner, installed_a.installed, heavy);
    assert_eq!(outcome, Err(InstallError::AdmissionRejected));
    let after = manager_state(publication, &manager);
    record_failure(
        &mut records,
        publication,
        "budget_rejection",
        1,
        before,
        after,
        installed_a.installed,
        heavy,
        ordinary_charge,
        result_name(&outcome),
    );

    let before = manager_state(publication, &manager);
    let outcome = publication.replace(&mut manager, owner, installed_a.installed, higher_authority);
    assert_eq!(outcome, Err(InstallError::AuthorityExceeded));
    let after = manager_state(publication, &manager);
    record_failure(
        &mut records,
        publication,
        "authority_rejection",
        2,
        before,
        after,
        installed_a.installed,
        higher_authority,
        ordinary_charge,
        result_name(&outcome),
    );

    let installed_b = publication
        .replace(&mut manager, owner, installed_a.installed, b)
        .unwrap();
    let before = manager_state(publication, &manager);
    let outcome = publication.replace(&mut manager, owner, installed_a.installed, c);
    assert!(matches!(
        outcome,
        Err(InstallError::StaleInstallation { .. })
    ));
    let after = manager_state(publication, &manager);
    record_failure(
        &mut records,
        publication,
        "stale_expected",
        3,
        before,
        after,
        installed_a.installed,
        c,
        ordinary_charge,
        result_name(&outcome),
    );

    let before = manager_state(publication, &manager);
    let outcome = publication.replace(&mut manager, owner, installed_a.installed, b);
    assert!(matches!(
        outcome,
        Err(InstallError::StaleInstallation { .. })
    ));
    let after = manager_state(publication, &manager);
    record_failure(
        &mut records,
        publication,
        "completed_retry",
        4,
        before,
        after,
        installed_a.installed,
        b,
        ordinary_charge,
        result_name(&outcome),
    );

    let before = manager_state(publication, &manager);
    let rolled_back = publication
        .replace(&mut manager, owner, installed_b.installed, a)
        .unwrap();
    let after = manager_state(publication, &manager);
    assert_eq!(manager.last_install_receipt(), Some(rolled_back));
    records.push(Record {
        case: "rollback",
        request_id: 5,
        before,
        observations: Vec::new(),
        after,
        outcome: "Ok".into(),
        attempts: vec![Attempt {
            candidate: a,
            outcome: "Ok".into(),
        }],
        expected: Some(installed_b.installed),
        candidate: a,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: publication.scope(),
    });

    let before = manager_state(publication, &manager);
    let outcome = publication.replace(&mut manager, owner, installed_a.installed, b);
    assert!(matches!(
        outcome,
        Err(InstallError::StaleInstallation {
            expected,
            current: Some(current),
        }) if expected == installed_a.installed && current == rolled_back.installed
    ));
    let after = manager_state(publication, &manager);
    record_failure(
        &mut records,
        publication,
        "aba",
        6,
        before,
        after,
        installed_a.installed,
        b,
        ordinary_charge,
        result_name(&outcome),
    );

    let before = manager_state(publication, &manager);
    let shared = Arc::new(Mutex::new(manager));
    let start = Arc::new(Barrier::new(3));
    let (b_result, c_result) = std::thread::scope(|scope| {
        let b_manager = Arc::clone(&shared);
        let b_start = Arc::clone(&start);
        let b_proposer = scope.spawn(move || {
            b_start.wait();
            publication.replace(
                &mut b_manager.lock().unwrap(),
                owner,
                rolled_back.installed,
                b,
            )
        });
        let c_manager = Arc::clone(&shared);
        let c_start = Arc::clone(&start);
        let c_proposer = scope.spawn(move || {
            c_start.wait();
            publication.replace(
                &mut c_manager.lock().unwrap(),
                owner,
                rolled_back.installed,
                c,
            )
        });
        start.wait();
        (b_proposer.join().unwrap(), c_proposer.join().unwrap())
    });
    let attempts = vec![attempt(b, &b_result), attempt(c, &c_result)];
    let winner = match (b_result, c_result) {
        (Ok(winner), Err(InstallError::StaleInstallation { current, .. }))
        | (Err(InstallError::StaleInstallation { current, .. }), Ok(winner)) => {
            assert_eq!(current, Some(winner.installed));
            winner
        }
        results => panic!("expected exactly one successful proposer, got {results:?}"),
    };
    let mutex = Arc::into_inner(shared).expect("proposer references dropped");
    let mut manager = mutex
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(manager.last_install_receipt(), Some(winner));
    let after = manager_state(publication, &manager);
    records.push(Record {
        case: "concurrent_proposers",
        request_id: 7,
        before,
        observations: Vec::new(),
        after,
        outcome: "Ok".into(),
        attempts,
        expected: Some(rolled_back.installed),
        candidate: winner.installed.program,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: publication.scope(),
    });

    let held_a = publication
        .replace(&mut manager, owner, winner.installed, a)
        .unwrap();
    let held_candidate = b;
    let before = manager_state(publication, &manager);
    let (observations, replacement, attempts, skipped_dispatches) = match publication {
        Publication::Atomic => {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (overlap, replacement) = std::thread::scope(|scope| {
                scope.spawn(move || {
                    BpfManager::observe_timer_atomic_without_quiescence(|id| {
                        entered_tx.send(id).unwrap();
                        release_rx.recv().unwrap();
                    })
                    .unwrap();
                });
                let guarded_a = entered_rx.recv().unwrap();
                assert_eq!(guarded_a, held_a.installed);
                let writer = scope.spawn(|| {
                    publication.replace(&mut manager, owner, held_a.installed, held_candidate)
                });
                let overlap = loop {
                    let observed = publication
                        .observe(|guarded_b| {
                            (guarded_b.program == held_candidate).then(|| State {
                                snapshot: vec![guarded_b.program],
                                installation: Some(guarded_b),
                                committed: None,
                                receipt: None,
                                guards: vec![guarded_a, guarded_b],
                            })
                        })
                        .unwrap();
                    if let Some(overlap) = observed {
                        break overlap;
                    }
                    std::thread::yield_now();
                };
                assert!(
                    !writer.is_finished(),
                    "AP writer returned before A guard drained"
                );
                release_tx.send(()).unwrap();
                (overlap, writer.join().unwrap())
            });
            let attempts = vec![attempt(held_candidate, &replacement)];
            (vec![overlap], replacement, attempts, 0)
        }
        Publication::Transactional => {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let skips_before = manager.exclusive_slot_skips().execution_busy;
            let (held, first) = std::thread::scope(|scope| {
                let observer = scope.spawn(move || {
                    BpfManager::observe_timer_exclusive(|id| {
                        entered_tx.send(id).unwrap();
                        release_rx.recv().unwrap();
                    })
                    .unwrap();
                });
                let guarded_a = entered_rx.recv().unwrap();
                assert_eq!(guarded_a, held_a.installed);
                let first =
                    publication.replace(&mut manager, owner, held_a.installed, held_candidate);
                assert_eq!(first, Err(InstallError::Busy));
                let held = held_manager_state(&manager, guarded_a);
                preserved(&before, &held);
                assert_eq!(
                    BpfManager::observe_timer_exclusive(|_| ()),
                    Err(HookRunError::ExecutionBusy)
                );
                release_tx.send(()).unwrap();
                observer.join().unwrap();
                (held, first)
            });
            let retry = publication.replace(&mut manager, owner, held_a.installed, held_candidate);
            let attempts = vec![
                attempt(held_candidate, &first),
                attempt(held_candidate, &retry),
            ];
            (
                vec![held],
                retry,
                attempts,
                manager.exclusive_slot_skips().execution_busy - skips_before,
            )
        }
    };
    let replacement = replacement.unwrap();
    assert_eq!(replacement.previous, Some(held_a.installed));
    assert_eq!(manager.last_install_receipt(), Some(replacement));
    let after = manager_state(publication, &manager);
    records.push(Record {
        case: "held_a_schedule",
        request_id: 8,
        before,
        observations,
        after,
        outcome: "Ok".into(),
        attempts,
        expected: Some(held_a.installed),
        candidate: held_candidate,
        skipped_dispatches,
        ordinary_charge: Some(ordinary_charge),
        scope: publication.scope(),
    });

    manager
        .clear_exclusive_for_diagnostics(owner, replacement.installed)
        .unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, background_a).unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, background_b).unwrap();
    for record in records {
        emit(publication.protocol(), &costs, record);
    }
}

fn ordinary(protocol: &'static str, attach_first: bool) {
    let mut manager = BpfManager::new();
    let owner = 7;
    let a = manager.load_raw_program_for(owner, program(11)).unwrap();
    let b = manager.load_raw_program_for(owner, program(22)).unwrap();
    let (ordinary_one, ordinary_one_cost, ordinary_two, ordinary_two_cost) =
        budget_background(&mut manager, owner);
    let heavy = manager
        .load_raw_program_for(owner, timed_program(7_000))
        .unwrap();
    let ordinary_charge = ordinary_one_cost + ordinary_two_cost;
    manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
    let cost_a = manager.committed_total_ns_per_s() - ordinary_charge;
    manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
    manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
    let cost_b = manager.committed_total_ns_per_s() - ordinary_charge;
    manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
    let costs = BTreeMap::from([(a, cost_a), (b, cost_b)]);
    let mut records = Vec::new();

    manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
    let before = hook_state(&manager);
    let first_step = if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b)
    } else {
        manager.detach(ATTACH_TYPE_TIMER, a)
    };
    first_step.unwrap();
    records.push(Record {
        case: "interruption",
        request_id: 0,
        before,
        observations: Vec::new(),
        after: hook_state(&manager),
        outcome: "Interrupted".into(),
        attempts: vec![Attempt {
            candidate: b,
            outcome: "Interrupted".into(),
        }],
        expected: None,
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager_ordinary_supporting",
    });
    if attach_first {
        manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
    } else {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
    }

    let before = hook_state(&manager);
    if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
        let dual = hook_state(&manager);
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
        records.push(Record {
            case: "success",
            request_id: 1,
            before,
            observations: vec![dual],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            attempts: vec![Attempt {
                candidate: b,
                outcome: "Ok".into(),
            }],
            expected: None,
            candidate: b,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary_supporting",
        });
    } else {
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
        let empty = hook_state(&manager);
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
        records.push(Record {
            case: "success",
            request_id: 1,
            before,
            observations: vec![empty],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            attempts: vec![Attempt {
                candidate: b,
                outcome: "Ok".into(),
            }],
            expected: None,
            candidate: b,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary_supporting",
        });
    }

    manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
    manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
    let before = hook_state(&manager);
    let outcome = if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, heavy)
    } else {
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
        manager.attach_for(owner, ATTACH_TYPE_TIMER, heavy)
    };
    assert_eq!(outcome, Err(BpfError::AdmissionRejected));
    let after = hook_state(&manager);
    if attach_first {
        preserved(&before, &after);
    }
    records.push(Record {
        case: "budget_rejection",
        request_id: 2,
        before,
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        attempts: vec![attempt(heavy, &outcome)],
        expected: None,
        candidate: heavy,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager_ordinary_supporting",
    });

    if !attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
    }
    let before = hook_state(&manager);
    let outcome = if attach_first {
        manager.fail_next_hook_snapshot_for_diagnostics();
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b)
    } else {
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
        manager.fail_next_hook_snapshot_for_diagnostics();
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b)
    };
    let after = hook_state(&manager);
    if attach_first {
        preserved(&before, &after);
    }
    records.push(Record {
        case: "snapshot_prep_failure",
        request_id: 3,
        before,
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        attempts: vec![attempt(b, &outcome)],
        expected: None,
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager_ordinary_supporting",
    });

    if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
    } else {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
    }
    let before = hook_state(&manager);
    if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
        let dual = hook_state(&manager);
        manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
        records.push(Record {
            case: "rollback",
            request_id: 4,
            before,
            observations: vec![dual],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            attempts: vec![Attempt {
                candidate: a,
                outcome: "Ok".into(),
            }],
            expected: None,
            candidate: a,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary_supporting",
        });
    } else {
        manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
        let empty = hook_state(&manager);
        manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
        records.push(Record {
            case: "rollback",
            request_id: 4,
            before,
            observations: vec![empty],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            attempts: vec![Attempt {
                candidate: a,
                outcome: "Ok".into(),
            }],
            expected: None,
            candidate: a,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary_supporting",
        });
    }
    manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, ordinary_one).unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, ordinary_two).unwrap();
    for record in records {
        emit(protocol, &costs, record);
    }
}

#[test]
fn emits_real_publication_traces() {
    paired_manager(Publication::Atomic);
    paired_manager(Publication::Transactional);
    ordinary("attach_first", true);
    ordinary("detach_first", false);
}
