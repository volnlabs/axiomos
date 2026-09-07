//! Host-only trace campaign. Raw fixtures require `bpf-unsigned-development`.
//!
//! `atomic_publication` is deliberately scoped to `EpochSnapshot`: it is a
//! component baseline, not a claim about the manager invocation seam.

#![cfg(all(
    feature = "bpf-update-diagnostics",
    feature = "bpf-unsigned-development"
))]

use std::collections::BTreeMap;

use kernel::bpf::{
    BpfManager, ControlSlot, HookRunError, InstallError, InstallationId, ProgramHandle,
    StatePolicy, ATTACH_TYPE_SYS_ENTER, ATTACH_TYPE_TIMER,
};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::concurrency::epoch_snapshot::EpochSnapshot;
use kernel_bpf::execution::BpfError;
use kernel_bpf::verifier::HelperId;

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    snapshot: Vec<ProgramHandle>,
    installation: Option<InstallationId>,
    committed: Option<u64>,
    executing: Vec<InstallationId>,
    guarded_handles: Vec<ProgramHandle>,
}

struct Record {
    case: &'static str,
    request_id: usize,
    before: State,
    observations: Vec<State>,
    after: State,
    outcome: String,
    expected: Option<InstallationId>,
    candidate: ProgramHandle,
    skipped_dispatches: usize,
    ordinary_charge: Option<u64>,
    scope: &'static str,
}

fn program(value: i32) -> Vec<BpfInsn> {
    vec![BpfInsn::mov64_imm(0, value), BpfInsn::exit()]
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
    // Three 7k-call programs are each within the verifier's per-invocation
    // bound, while two admitted background programs make the third fail the
    // aggregate 500 ms/s embedded admission budget.
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

fn json_ids(ids: &[InstallationId]) -> String {
    let values: Vec<String> = ids
        .iter()
        .map(|id| format!("[{},{}]", id.program, id.epoch))
        .collect();
    format!("[{}]", values.join(","))
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

fn json_state(state: &State) -> String {
    let installation = state
        .installation
        .map(|id| format!("[{},{}]", id.program, id.epoch))
        .unwrap_or_else(|| "null".into());
    format!(
        "{{\"snapshot\":{},\"installation\":{},\"committed\":{},\"executing\":{},\"guarded_handles\":{}}}",
        json_handles(&state.snapshot),
        installation,
        state.committed.map(|value| value.to_string()).unwrap_or_else(|| "null".into()),
        json_ids(&state.executing),
        json_handles(&state.guarded_handles),
    )
}

fn emit(protocol: &str, costs: &BTreeMap<ProgramHandle, u64>, record: Record) {
    let expected = record
        .expected
        .map(|id| format!("[{},{}]", id.program, id.epoch))
        .unwrap_or_else(|| "null".into());
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
    println!(
        "UPDATE_TXN {{\"schema\":1,\"protocol\":\"{protocol}\",\"scope\":\"{}\",\"case\":\"{}\",\"request_id\":{},\"before\":{},\"observations\":[{}],\"after\":{},\"costs\":{{{json_costs}}},\"ordinary_charge\":{},\"outcome\":\"{}\",\"expected\":{},\"candidate\":{},\"skipped_dispatches\":{}}}",
        record.scope,
        record.case,
        record.request_id,
        json_state(&record.before),
        observations,
        json_state(&record.after),
        record.ordinary_charge.map(|value| value.to_string()).unwrap_or_else(|| "null".into()),
        record.outcome,
        expected,
        record.candidate,
        record.skipped_dispatches,
    );
}

fn exclusive_state(manager: &BpfManager) -> State {
    BpfManager::observe_timer_exclusive(|id| State {
        // This callback runs with the actual ExclusiveReadGuard held.
        snapshot: vec![id.program],
        installation: manager.exclusive_timer_identity(),
        committed: Some(manager.committed_total_ns_per_s()),
        executing: vec![id],
        guarded_handles: vec![id.program],
    })
    .unwrap_or_else(|_| State {
        snapshot: Vec::new(),
        installation: manager.exclusive_timer_identity(),
        committed: Some(manager.committed_total_ns_per_s()),
        executing: Vec::new(),
        guarded_handles: Vec::new(),
    })
}

fn held_exclusive_state(manager: &BpfManager, id: InstallationId) -> State {
    State {
        snapshot: vec![id.program],
        installation: manager.exclusive_timer_identity(),
        committed: Some(manager.committed_total_ns_per_s()),
        executing: vec![id],
        guarded_handles: vec![id.program],
    }
}

fn hook_state(manager: &BpfManager) -> State {
    let guarded_handles = BpfManager::observe_hook_snapshot(ATTACH_TYPE_TIMER, |ids| ids.to_vec())
        .unwrap_or_default();
    State {
        snapshot: guarded_handles.clone(),
        installation: None,
        committed: Some(manager.committed_total_ns_per_s()),
        executing: Vec::new(),
        guarded_handles,
    }
}

fn preserved(before: &State, after: &State) {
    assert_eq!(before.snapshot, after.snapshot);
    assert_eq!(before.installation, after.installation);
    assert_eq!(before.committed, after.committed);
}

fn transactional() {
    let mut manager = BpfManager::new();
    let owner = 7;
    let a = manager.load_raw_program_for(owner, program(11)).unwrap();
    let b = manager.load_raw_program_for(owner, program(22)).unwrap();
    let (background_a, _, background_b, _) = budget_background(&mut manager, owner);
    let heavy = manager
        .load_raw_program_for(owner, timed_program(7_000))
        .unwrap();
    let ordinary_charge = manager.committed_total_ns_per_s();
    manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
    let cost_a = manager.committed_total_ns_per_s() - ordinary_charge;
    manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
    manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
    let cost_b = manager.committed_total_ns_per_s() - ordinary_charge;
    manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
    let costs = BTreeMap::from([(a, cost_a), (b, cost_b)]);
    let mut records = Vec::new();

    let installed = manager
        .try_install_exclusive_for(owner, ControlSlot::Timer, a, StatePolicy::Reset)
        .unwrap();
    let before = exclusive_state(&manager);
    let interrupted = manager
        .try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset,
        )
        .unwrap();
    let after = exclusive_state(&manager);
    records.push(Record {
        case: "interruption",
        request_id: 0,
        before,
        observations: Vec::new(),
        after,
        outcome: "Ok".into(),
        expected: Some(installed.installed),
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });
    let installed = manager
        .try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            interrupted.installed,
            a,
            StatePolicy::Reset,
        )
        .unwrap();

    let before = exclusive_state(&manager);
    manager.fail_next_exclusive_snapshot_for_diagnostics();
    let outcome = manager.try_replace_exclusive_for(
        owner,
        ControlSlot::Timer,
        installed.installed,
        b,
        StatePolicy::Reset,
    );
    let after = exclusive_state(&manager);
    preserved(&before, &after);
    records.push(Record {
        case: "snapshot_prep_failure",
        request_id: 1,
        before: before.clone(),
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        expected: Some(installed.installed),
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });

    let before = exclusive_state(&manager);
    let outcome = manager.try_replace_exclusive_for(
        owner,
        ControlSlot::Timer,
        installed.installed,
        heavy,
        StatePolicy::Reset,
    );
    assert_eq!(outcome, Err(InstallError::AdmissionRejected));
    let after = exclusive_state(&manager);
    preserved(&before, &after);
    records.push(Record {
        case: "budget_rejection",
        request_id: 2,
        before: before.clone(),
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        expected: Some(installed.installed),
        candidate: heavy,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });

    let before = exclusive_state(&manager);
    let mut held = None;
    let skips_before = manager.exclusive_slot_skips().execution_busy;
    let outcome = BpfManager::observe_timer_exclusive(|id| {
        held = Some(held_exclusive_state(&manager, id));
        assert_eq!(
            BpfManager::observe_timer_exclusive(|_| ()),
            Err(HookRunError::ExecutionBusy)
        );
        manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset,
        )
    })
    .unwrap();
    assert_eq!(outcome, Err(InstallError::Busy));
    let after = exclusive_state(&manager);
    preserved(&before, &after);
    records.push(Record {
        case: "reader_busy",
        request_id: 3,
        before,
        observations: vec![held.unwrap()],
        after,
        outcome: result_name(&outcome),
        expected: Some(installed.installed),
        candidate: b,
        skipped_dispatches: manager.exclusive_slot_skips().execution_busy - skips_before,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });

    let before = exclusive_state(&manager);
    let receipt = manager
        .try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            installed.installed,
            b,
            StatePolicy::Reset,
        )
        .unwrap();
    let after = exclusive_state(&manager);
    records.push(Record {
        case: "success",
        request_id: 4,
        before,
        observations: Vec::new(),
        after,
        outcome: "Ok".into(),
        expected: Some(installed.installed),
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });

    let before = exclusive_state(&manager);
    let outcome = manager.try_replace_exclusive_for(
        owner,
        ControlSlot::Timer,
        installed.installed,
        a,
        StatePolicy::Reset,
    );
    assert!(matches!(
        outcome,
        Err(InstallError::StaleInstallation { .. })
    ));
    let after = exclusive_state(&manager);
    preserved(&before, &after);
    records.push(Record {
        case: "stale_expected",
        request_id: 5,
        before: before.clone(),
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        expected: Some(installed.installed),
        candidate: a,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });

    let before = exclusive_state(&manager);
    let repeated = manager.try_replace_exclusive_for(
        owner,
        ControlSlot::Timer,
        installed.installed,
        b,
        StatePolicy::Reset,
    );
    assert!(matches!(
        repeated,
        Err(InstallError::StaleInstallation { .. })
    ));
    let after = exclusive_state(&manager);
    preserved(&before, &after);
    records.push(Record {
        case: "completed_retry",
        request_id: 7,
        before,
        observations: Vec::new(),
        after,
        outcome: result_name(&repeated),
        expected: Some(installed.installed),
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });

    let before = exclusive_state(&manager);
    let outcome = manager.try_replace_exclusive_for(
        owner,
        ControlSlot::Timer,
        receipt.installed,
        a,
        StatePolicy::Reset,
    );
    let after = exclusive_state(&manager);
    records.push(Record {
        case: "rollback",
        request_id: 6,
        before,
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        expected: Some(receipt.installed),
        candidate: a,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager",
    });
    manager
        .clear_exclusive_for_diagnostics(owner, manager.exclusive_timer_identity().unwrap())
        .unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, background_a).unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, background_b).unwrap();
    for record in records {
        emit("transactional", &costs, record);
    }
}

fn ordinary(protocol: &str, attach_first: bool) {
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
    // Measure each verifier-accepted fixture before the recorded protocol;
    // later records never derive a cost from their own publication outcome.
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
    let after = hook_state(&manager);
    records.push(Record {
        case: "interruption",
        request_id: 0,
        before,
        observations: Vec::new(),
        after,
        outcome: "Interrupted".into(),
        expected: None,
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager_ordinary",
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
            before: before.clone(),
            observations: vec![dual],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            expected: None,
            candidate: b,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary",
        });
    } else {
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
        let empty = hook_state(&manager);
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
        records.push(Record {
            case: "success",
            request_id: 1,
            before: before.clone(),
            observations: vec![empty],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            expected: None,
            candidate: b,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary",
        });
    }
    // Restore A before each independent A→B failure schedule.
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
        before: before.clone(),
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        expected: None,
        candidate: heavy,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager_ordinary",
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
        before: before.clone(),
        observations: Vec::new(),
        after,
        outcome: result_name(&outcome),
        expected: None,
        candidate: b,
        skipped_dispatches: 0,
        ordinary_charge: Some(ordinary_charge),
        scope: "bpf_manager_ordinary",
    });

    // Set up B without recording it; the rollback request itself is B→A for
    // every manager protocol, matching the transactional rollback request.
    if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
        manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
    } else {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, b).unwrap();
    }
    let before = hook_state(&manager);
    if attach_first {
        manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
        let dual_ba = hook_state(&manager);
        manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
        records.push(Record {
            case: "rollback",
            request_id: 4,
            before,
            observations: vec![dual_ba],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            expected: None,
            candidate: a,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary",
        });
    } else {
        manager.detach(ATTACH_TYPE_TIMER, b).unwrap();
        let empty_ba = hook_state(&manager);
        manager.attach_for(owner, ATTACH_TYPE_TIMER, a).unwrap();
        records.push(Record {
            case: "rollback",
            request_id: 4,
            before,
            observations: vec![empty_ba],
            after: hook_state(&manager),
            outcome: "Ok".into(),
            expected: None,
            candidate: a,
            skipped_dispatches: 0,
            ordinary_charge: Some(ordinary_charge),
            scope: "bpf_manager_ordinary",
        });
    }
    manager.detach(ATTACH_TYPE_TIMER, a).unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, ordinary_one).unwrap();
    manager.detach(ATTACH_TYPE_SYS_ENTER, ordinary_two).unwrap();
    for record in records {
        emit(protocol, &costs, record);
    }
}

fn atomic_state(snapshot: &EpochSnapshot<ProgramHandle>) -> State {
    let handle = *snapshot.read().unwrap();
    State {
        snapshot: vec![handle],
        installation: None,
        committed: None,
        executing: Vec::new(),
        guarded_handles: vec![handle],
    }
}

fn atomic_publication() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    // Synthetic component handles identify guards, not kernel installations.
    let (a, b) = (1, 2);
    let snapshot = Arc::new(EpochSnapshot::empty());
    snapshot.publish(Box::new(a));
    let before = atomic_state(&snapshot);
    let old = snapshot.read().unwrap();
    let gate = Arc::new(Barrier::new(2));
    let writer_snapshot = snapshot.clone();
    let writer_gate = gate.clone();
    let writer = thread::spawn(move || {
        writer_gate.wait();
        writer_snapshot.publish(Box::new(b));
    });
    gate.wait();
    let new = loop {
        let guard = snapshot.read().unwrap();
        if *guard == b {
            break guard;
        }
        thread::yield_now();
    };
    let overlap = State {
        snapshot: vec![*new],
        installation: None,
        committed: None,
        executing: vec![
            InstallationId {
                program: *old,
                epoch: 1,
            },
            InstallationId {
                program: *new,
                epoch: 2,
            },
        ],
        guarded_handles: vec![*old, *new],
    };
    drop(new);
    drop(old);
    writer.join().unwrap();
    let after = atomic_state(&snapshot);
    emit(
        "atomic_publication",
        &BTreeMap::new(),
        Record {
            case: "outstanding_guards",
            request_id: 0,
            before,
            observations: vec![overlap],
            after,
            outcome: "Ok".into(),
            expected: None,
            candidate: b,
            skipped_dispatches: 0,
            ordinary_charge: None,
            scope: "component_epoch_snapshot_accounting_unsupported",
        },
    );
}

#[test]
fn emits_real_publication_traces() {
    transactional();
    ordinary("attach_first", true);
    ordinary("detach_first", false);
    atomic_publication();
}
