//! Deterministic host-only plant replay over frozen, atomic, and guarded
//! publication. This exercises real manager and snapshot guards without
//! executing privileged bytecode or actuation helpers.

#![cfg(all(
    feature = "bpf-update-diagnostics",
    feature = "bpf-unsigned-development",
    not(target_os = "none")
))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kernel::bpf::{
    BpfManager, ControlSlot, HookRunError, InstallError, InstallReceipt, InstallationId,
    ProgramHandle, StatePolicy,
};
use kernel_bpf::bytecode::insn::BpfInsn;

const STEP_US: u64 = 100;
const CONTROL_PERIOD_US: u64 = 1_000;
const DURATION_US: u64 = 8_000_000;
const MASS_CHANGE_US: u64 = 4_000_000;
const GUARD_HOLD_US: u64 = 100;
const LONG_START_US: u64 = 4_249_000;
const LONG_HOLD_US: u64 = 2_000;
const PROPOSAL_US: [u64; 4] = [4_250_000, 4_500_000, 4_750_000, 5_000_000];
const WINDOW_TICKS: usize = 250;
const TIMEOUT: Duration = Duration::from_secs(5);
const GRID_HOLDS_US: [u64; 5] = [0, 100, 500, 900, 1_100];
const GRID_PHASE_STEP_US: u64 = 20;
const RETRY_PHASE_STEP_US: u64 = 137;
const RETRY_DEADLINE_US: u64 = 20_000;
const COMMAND_BOUND: f64 = 4.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Frozen,
    Atomic,
    Guarded,
}

impl Protocol {
    const fn name(self) -> &'static str {
        match self {
            Self::Frozen => "frozen",
            Self::Atomic => "atomic",
            Self::Guarded => "guarded",
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
            Self::Frozen | Self::Guarded => manager.try_install_exclusive_for(
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
            Self::Guarded => manager.try_replace_exclusive_for(
                owner,
                ControlSlot::Timer,
                expected,
                candidate,
                StatePolicy::Reset,
            ),
            Self::Frozen => unreachable!("the frozen replay never updates"),
        }
    }

    fn observe<R>(self, observer: impl FnOnce(InstallationId) -> R) -> Result<R, HookRunError> {
        match self {
            Self::Atomic => BpfManager::observe_timer_atomic_without_quiescence(observer),
            Self::Frozen | Self::Guarded => BpfManager::observe_timer_exclusive(observer),
        }
    }
}

#[derive(Clone, Copy)]
struct Candidate {
    proposal: usize,
    scheduled_us: u64,
    prior_rmse: f64,
    previous_gain: u32,
    gain: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagerView {
    installation: InstallationId,
    committed: u64,
    receipt: InstallReceipt,
}

#[derive(Clone, Copy)]
struct CapturedInvocation {
    sequence: usize,
    completion_us: u64,
    installation: InstallationId,
    gain: u32,
    velocity: f64,
    reference: f64,
    command: f64,
}

enum StartMessage {
    Started(CapturedInvocation),
    Rejected(&'static str),
}

struct PendingInvocation {
    captured: CapturedInvocation,
    release: mpsc::Sender<()>,
    worker: thread::JoinHandle<Result<(), HookRunError>>,
}

struct PendingAttempt {
    proposal: usize,
    ordinal: usize,
    scheduled_us: u64,
    expected: InstallationId,
    candidate: ProgramHandle,
    candidate_gain: u32,
    before: ManagerView,
    published_us: u64,
    published: InstallationId,
    worker: thread::JoinHandle<Result<InstallReceipt, InstallError>>,
}

struct ScheduledPendingAttempt {
    proposal: usize,
    ordinal: usize,
    scheduled_us: u64,
    deadline_us: u64,
    expected: InstallationId,
    candidate: ProgramHandle,
    candidate_gain: u32,
    before: ManagerView,
    published_us: u64,
    published: InstallationId,
    worker: thread::JoinHandle<Result<InstallReceipt, InstallError>>,
}

struct ProposalState {
    expected: Option<InstallationId>,
    next_ordinal: usize,
    done: bool,
    censored: bool,
}

#[derive(Default)]
struct ScheduleSummary {
    pre_error_sum: f64,
    post_error_sum: f64,
    max_abs_error: f64,
    max_abs_command: f64,
    abs_command_integral_us: f64,
    scheduled_ticks: usize,
    completed_invocations: usize,
    attempted_updates: usize,
    successful_updates: usize,
    busy_attempts: usize,
    retry_attempts: usize,
    deadline_censored: usize,
    old_new_overlaps: usize,
    retired_commands: usize,
    saturated_completions: usize,
    command_bound_violations: usize,
    transition_skips: usize,
    execution_skips: usize,
    empty_skips: usize,
}

#[derive(Debug)]
struct Summary {
    pre_ticks: usize,
    post_ticks: usize,
    pre_rmse: f64,
    post_rmse: f64,
    started_invocations: usize,
    completed_invocations: usize,
    guard_version_overlaps: usize,
    retired_commands_after_publication: usize,
    transition_skips: usize,
    execution_skips: usize,
    actual_attempts: usize,
    busy_attempts: usize,
    retry_attempts: usize,
    successful_retries: usize,
    activations: usize,
    stale_errors: usize,
    stale_accepted: usize,
    accounting_errors: usize,
    final_installation: InstallationId,
    final_gain: u32,
    final_committed: u64,
}

fn reference_at(time_us: u64) -> f64 {
    if (time_us / 1_000_000) % 2 == 0 {
        1.0
    } else {
        -1.0
    }
}

fn mass_at(time_us: u64) -> f64 {
    if time_us < MASS_CHANGE_US {
        1.0
    } else {
        2.0
    }
}

fn command(gain: u32, reference: f64, velocity: f64) -> f64 {
    (f64::from(gain) * (reference - velocity)).clamp(-4.0, 4.0)
}

fn advance(velocity: &mut f64, held_command: f64, time_us: u64) {
    *velocity += 0.000_1 * (held_command - *velocity) / mass_at(time_us);
}

fn rmse(errors: &[f64]) -> f64 {
    (errors.iter().sum::<f64>() / errors.len() as f64).sqrt()
}

fn generate_seed_candidates() -> Vec<Candidate> {
    let mut velocity = 0.0_f64;
    let mut held_command = 0.0_f64;
    let mut gain = 1;
    let mut errors = Vec::with_capacity((DURATION_US / CONTROL_PERIOD_US) as usize);
    let mut candidates = Vec::with_capacity(PROPOSAL_US.len());
    for time_us in (0..DURATION_US).step_by(STEP_US as usize) {
        if let Some(proposal) = PROPOSAL_US
            .iter()
            .position(|scheduled| *scheduled == time_us)
        {
            let prior_rmse = rmse(&errors[errors.len() - WINDOW_TICKS..]);
            let previous_gain = gain;
            if prior_rmse > 0.1 {
                gain = (gain * 2).min(16);
            }
            candidates.push(Candidate {
                proposal,
                scheduled_us: time_us,
                prior_rmse,
                previous_gain,
                gain,
            });
        }
        if time_us % CONTROL_PERIOD_US == 0 {
            let error = reference_at(time_us) - velocity;
            errors.push(error * error);
            held_command = command(gain, reference_at(time_us), velocity);
        }
        advance(&mut velocity, held_command, time_us);
    }
    candidates
}

fn program(gain: u32) -> Vec<BpfInsn> {
    vec![BpfInsn::mov64_imm(0, gain as i32), BpfInsn::exit()]
}

fn view(manager: &BpfManager) -> ManagerView {
    ManagerView {
        installation: manager
            .exclusive_timer_identity()
            .expect("installation disappeared"),
        committed: manager.committed_exclusive_ns_per_s(),
        receipt: manager.last_install_receipt().expect("receipt disappeared"),
    }
}

fn json_id(id: InstallationId) -> String {
    format!("[{},{}]", id.program, id.epoch)
}

fn json_receipt(receipt: InstallReceipt) -> String {
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
}

fn emit(protocol: Protocol, fields: std::fmt::Arguments<'_>) {
    println!(
        "UPDATE_ADAPT {{\"schema\":1,\"protocol\":\"{}\",{fields}}}",
        protocol.name()
    );
}

fn emit_experiment(protocol: Protocol, experiment: &str, fields: std::fmt::Arguments<'_>) {
    println!(
        "UPDATE_ADAPT {{\"schema\":1,\"experiment\":\"{experiment}\",\"protocol\":\"{}\",{fields}}}",
        protocol.name()
    );
}

fn advance_by(velocity: &mut f64, held_command: f64, time_us: u64, delta_us: u64) {
    *velocity += (delta_us as f64 / 1_000_000.0) * (held_command - *velocity) / mass_at(time_us);
}

fn scheduled_attempt_us(base_us: u64, phase_us: u64, ordinal: usize) -> u64 {
    if ordinal == 0 {
        base_us + phase_us
    } else {
        base_us
            + ordinal as u64 * CONTROL_PERIOD_US
            + (phase_us + RETRY_PHASE_STEP_US * ordinal as u64) % CONTROL_PERIOD_US
    }
}

fn join_bounded<T>(worker: thread::JoinHandle<T>, context: &str) -> T {
    let deadline = Instant::now() + TIMEOUT;
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "timed out waiting for {context}");
        thread::yield_now();
    }
    worker
        .join()
        .unwrap_or_else(|_| panic!("{context} thread panicked"))
}

fn hook_error_name(error: &HookRunError) -> &'static str {
    match error {
        HookRunError::TransitionBusy => "TransitionBusy",
        HookRunError::ExecutionBusy => "ExecutionBusy",
        other => panic!("unexpected observer error: {other:?}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn start_invocation(
    protocol: Protocol,
    sequence: usize,
    time_us: u64,
    hold_us: u64,
    velocity: f64,
    reference: f64,
    gains: Arc<BTreeMap<ProgramHandle, u32>>,
) -> Result<PendingInvocation, &'static str> {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = protocol.observe(|installation| {
            let gain = gains[&installation.program];
            let captured = CapturedInvocation {
                sequence,
                completion_us: time_us + hold_us,
                installation,
                gain,
                velocity,
                reference,
                command: command(gain, reference, velocity),
            };
            started_tx.send(StartMessage::Started(captured)).unwrap();
            release_rx
                .recv_timeout(TIMEOUT)
                .expect("timed out waiting for simulated guard completion");
        });
        if let Err(error) = &result {
            started_tx
                .send(StartMessage::Rejected(hook_error_name(error)))
                .unwrap();
        }
        result
    });
    match started_rx
        .recv_timeout(TIMEOUT)
        .expect("timed out waiting for invocation start")
    {
        StartMessage::Started(captured) => Ok(PendingInvocation {
            captured,
            release: release_tx,
            worker,
        }),
        StartMessage::Rejected(outcome) => {
            assert!(join_bounded(worker, "rejected invocation").is_err());
            Err(outcome)
        }
    }
}

fn manager_view(manager: &Arc<Mutex<BpfManager>>) -> ManagerView {
    view(
        &manager
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_attempt(
    protocol: Protocol,
    proposal: usize,
    ordinal: usize,
    scheduled_us: u64,
    attempted: bool,
    expected: InstallationId,
    candidate: ProgramHandle,
    candidate_gain: u32,
    outcome: &str,
    published_us: Option<u64>,
    completed_us: u64,
    receipt: Option<InstallReceipt>,
    before: ManagerView,
    after: ManagerView,
    accounting_ok: bool,
) {
    let receipt = receipt.map(json_receipt).unwrap_or_else(|| "null".into());
    let published_us = published_us.map_or_else(|| "null".into(), |time| time.to_string());
    emit(
        protocol,
        format_args!(
            "\"kind\":\"attempt\",\"proposal\":{proposal},\"ordinal\":{ordinal},\"scheduled_us\":{scheduled_us},\"attempted\":{attempted},\"expected\":{},\"candidate_handle\":{candidate},\"candidate_gain\":{candidate_gain},\"outcome\":\"{outcome}\",\"published_us\":{published_us},\"completed_us\":{completed_us},\"receipt\":{receipt},\"before_installation\":{},\"after_installation\":{},\"before_committed\":{},\"after_committed\":{},\"accounting_ok\":{accounting_ok}",
            json_id(expected),
            json_id(before.installation),
            json_id(after.installation),
            before.committed,
            after.committed,
        ),
    );
}

fn classify_attempt(
    result: &Result<InstallReceipt, InstallError>,
) -> (&'static str, Option<InstallReceipt>) {
    match result {
        Ok(receipt) => ("Ok", Some(*receipt)),
        Err(InstallError::Busy) => ("Busy", None),
        Err(InstallError::StaleInstallation { .. }) => ("StaleInstallation", None),
        Err(error) => panic!("unexpected adaptation update error: {error:?}"),
    }
}

fn check_attempt(
    expected: InstallationId,
    candidate: ProgramHandle,
    before: ManagerView,
    after: ManagerView,
    result: &Result<InstallReceipt, InstallError>,
) -> bool {
    match result {
        Ok(receipt) => {
            receipt.previous == Some(expected)
                && expected == before.installation
                && receipt.installed.program == candidate
                && receipt.installed.epoch == expected.epoch + 1
                && after.installation == receipt.installed
                && after.receipt == *receipt
                && after.committed == receipt.committed_exclusive_ns_per_s
                && i128::from(after.committed) - i128::from(before.committed)
                    == receipt.admission_delta_ns_per_s
        }
        Err(_) => after == before,
    }
}

fn finalize_atomic_attempt(
    pending: PendingAttempt,
    completed_us: u64,
    manager: &Arc<Mutex<BpfManager>>,
    summary: &mut Summary,
) {
    let result = join_bounded(pending.worker, "atomic replacement");
    let after = manager_view(manager);
    let accounting_ok = check_attempt(
        pending.expected,
        pending.candidate,
        pending.before,
        after,
        &result,
    );
    summary.accounting_errors += usize::from(!accounting_ok);
    let (outcome, receipt) = classify_attempt(&result);
    assert_eq!(outcome, "Ok");
    let receipt = receipt.expect("atomic publication lost its receipt");
    assert_eq!(receipt.installed, pending.published);
    summary.activations += 1;
    summary.successful_retries += usize::from(pending.ordinal == 1);
    emit_attempt(
        Protocol::Atomic,
        pending.proposal,
        pending.ordinal,
        pending.scheduled_us,
        true,
        pending.expected,
        pending.candidate,
        pending.candidate_gain,
        outcome,
        Some(pending.published_us),
        completed_us,
        Some(receipt),
        pending.before,
        after,
        accounting_ok,
    );
}

fn replay(protocol: Protocol, candidates: &[Candidate]) -> Summary {
    let owner = 7;
    let mut manager = BpfManager::new();
    let mut gain_handles = BTreeMap::new();
    let mut handle_gains = BTreeMap::new();
    for gain in std::iter::once(1).chain(candidates.iter().map(|candidate| candidate.gain)) {
        let handle = manager
            .load_raw_program_for(owner, program(gain))
            .unwrap_or_else(|error| panic!("load gain {gain}: {error:?}"));
        gain_handles.insert(gain, handle);
        handle_gains.insert(handle, gain);
    }
    let initial_handle = gain_handles[&1];
    let initial_receipt = protocol
        .install(&mut manager, owner, initial_handle)
        .expect("initial adaptation publication failed");
    let initial = view(&manager);
    assert_eq!(initial.installation, initial_receipt.installed);
    assert_eq!(initial.receipt, initial_receipt);

    let mappings = handle_gains
        .iter()
        .map(|(handle, gain)| format!("[{handle},{gain}]"))
        .collect::<Vec<_>>()
        .join(",");
    emit(
        protocol,
        format_args!(
            "\"kind\":\"config\",\"duration_us\":{DURATION_US},\"step_us\":{STEP_US},\"control_period_us\":{CONTROL_PERIOD_US},\"mass_change_us\":{MASS_CHANGE_US},\"guard_hold_us\":{GUARD_HOLD_US},\"long_start_us\":{LONG_START_US},\"long_hold_us\":{LONG_HOLD_US},\"initial_gain\":1,\"pre_ticks\":4000,\"post_ticks\":4000,\"candidate_count\":{},\"initial_installation\":{},\"initial_receipt\":{},\"initial_committed\":{},\"handle_gains\":[{mappings}]",
            candidates.len(),
            json_id(initial.installation),
            json_receipt(initial.receipt),
            initial.committed,
        ),
    );

    let manager = Arc::new(Mutex::new(manager));
    let gains = Arc::new(handle_gains);
    let skips_before = manager
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .exclusive_slot_skips();
    let mut summary = Summary {
        pre_ticks: 0,
        post_ticks: 0,
        pre_rmse: 0.0,
        post_rmse: 0.0,
        started_invocations: 0,
        completed_invocations: 0,
        guard_version_overlaps: 0,
        retired_commands_after_publication: 0,
        transition_skips: 0,
        execution_skips: 0,
        actual_attempts: 0,
        busy_attempts: 0,
        retry_attempts: 0,
        successful_retries: 0,
        activations: 0,
        stale_errors: 0,
        stale_accepted: 0,
        accounting_errors: 0,
        final_installation: initial.installation,
        final_gain: 1,
        final_committed: initial.committed,
    };
    let mut velocity = 0.0_f64;
    let mut held_command = 0.0_f64;
    let mut pre_error_sum = 0.0;
    let mut post_error_sum = 0.0;
    let mut published = initial.installation;
    let mut proposal_expected = [None; PROPOSAL_US.len()];
    let mut invocations = Vec::<PendingInvocation>::new();
    let mut pending_attempt = None::<PendingAttempt>;
    let mut sequence = 0;

    for time_us in (0..DURATION_US).step_by(STEP_US as usize) {
        while let Some(position) = invocations
            .iter()
            .position(|pending| pending.captured.completion_us == time_us)
        {
            let pending = invocations.remove(position);
            pending.release.send(()).unwrap();
            join_bounded(pending.worker, "invocation completion")
                .expect("started invocation later failed");
            held_command = pending.captured.command;
            let retired = pending.captured.installation != published;
            summary.retired_commands_after_publication += usize::from(retired);
            summary.completed_invocations += 1;
            emit(
                protocol,
                format_args!(
                    "\"kind\":\"completion\",\"invocation\":{},\"completion_us\":{time_us},\"captured_installation\":{},\"captured_gain\":{},\"captured_command\":{:.12},\"published_installation\":{},\"retired_after_publication\":{retired}",
                    pending.captured.sequence,
                    json_id(pending.captured.installation),
                    pending.captured.gain,
                    pending.captured.command,
                    json_id(published),
                ),
            );
        }

        if pending_attempt.is_some() && time_us == PROPOSAL_US[0] + CONTROL_PERIOD_US {
            finalize_atomic_attempt(
                pending_attempt.take().unwrap(),
                time_us,
                &manager,
                &mut summary,
            );
        }

        for candidate in candidates {
            if candidate.scheduled_us == time_us {
                emit(
                    protocol,
                    format_args!(
                        "\"kind\":\"candidate\",\"proposal\":{},\"scheduled_us\":{},\"window_start_us\":{},\"window_end_us\":{},\"prior_rmse\":{:.12},\"previous_gain\":{},\"candidate_gain\":{}",
                        candidate.proposal,
                        candidate.scheduled_us,
                        candidate.scheduled_us - WINDOW_TICKS as u64 * CONTROL_PERIOD_US,
                        candidate.scheduled_us,
                        candidate.prior_rmse,
                        candidate.previous_gain,
                        candidate.gain,
                    ),
                );
            }

            let ordinal = if time_us == candidate.scheduled_us {
                Some(0)
            } else if time_us == candidate.scheduled_us + CONTROL_PERIOD_US {
                Some(1)
            } else {
                None
            };
            let Some(ordinal) = ordinal else { continue };
            if ordinal == 0 {
                proposal_expected[candidate.proposal] = Some(published);
            }
            let expected = proposal_expected[candidate.proposal].unwrap();
            let candidate_handle = gain_handles[&candidate.gain];
            assert_eq!(gains[&candidate_handle], candidate.gain);
            if protocol == Protocol::Frozen {
                let unchanged = manager_view(&manager);
                emit_attempt(
                    protocol,
                    candidate.proposal,
                    ordinal,
                    time_us,
                    false,
                    expected,
                    candidate_handle,
                    candidate.gain,
                    "NotAttempted",
                    None,
                    time_us,
                    None,
                    unchanged,
                    unchanged,
                    true,
                );
                continue;
            }

            summary.actual_attempts += 1;
            summary.retry_attempts += usize::from(ordinal == 1);
            let before = manager_view(&manager);
            if protocol == Protocol::Atomic && ordinal == 0 {
                assert!(pending_attempt.is_none());
                let writer_manager = Arc::clone(&manager);
                let worker = thread::spawn(move || {
                    let mut manager = writer_manager
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    protocol.replace(&mut manager, owner, expected, candidate_handle)
                });
                let deadline = Instant::now() + TIMEOUT;
                let observed = loop {
                    let observed = protocol
                        .observe(|id| id)
                        .expect("atomic publication observer failed");
                    if observed.program == candidate_handle {
                        break observed;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for atomic publication"
                    );
                    thread::yield_now();
                };
                published = observed;
                let attempt = PendingAttempt {
                    proposal: candidate.proposal,
                    ordinal,
                    scheduled_us: time_us,
                    expected,
                    candidate: candidate_handle,
                    candidate_gain: candidate.gain,
                    before,
                    published_us: time_us,
                    published: observed,
                    worker,
                };
                if candidate.proposal == 0 {
                    assert!(
                        !attempt.worker.is_finished(),
                        "first AP writer returned while long A guard was held"
                    );
                    pending_attempt = Some(attempt);
                } else {
                    finalize_atomic_attempt(attempt, time_us, &manager, &mut summary);
                }
                continue;
            }

            assert!(pending_attempt.is_none());
            let result = {
                let mut manager = manager
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                protocol.replace(&mut manager, owner, expected, candidate_handle)
            };
            let after = manager_view(&manager);
            let accounting_ok = check_attempt(expected, candidate_handle, before, after, &result);
            summary.accounting_errors += usize::from(!accounting_ok);
            let (outcome, receipt) = classify_attempt(&result);
            match outcome {
                "Ok" => {
                    published = receipt.unwrap().installed;
                    summary.activations += 1;
                    summary.successful_retries += usize::from(ordinal == 1);
                }
                "Busy" => summary.busy_attempts += 1,
                "StaleInstallation" => summary.stale_errors += 1,
                _ => unreachable!(),
            }
            if outcome == "Ok" && expected != before.installation {
                summary.stale_accepted += 1;
            }
            emit_attempt(
                protocol,
                candidate.proposal,
                ordinal,
                time_us,
                true,
                expected,
                candidate_handle,
                candidate.gain,
                outcome,
                (outcome == "Ok").then_some(time_us),
                time_us,
                receipt,
                before,
                after,
                accounting_ok,
            );
        }

        if time_us % CONTROL_PERIOD_US == 0 {
            let tick = (time_us / CONTROL_PERIOD_US) as usize;
            let reference = reference_at(time_us);
            let error = reference - velocity;
            if time_us < MASS_CHANGE_US {
                pre_error_sum += error * error;
                summary.pre_ticks += 1;
            } else {
                post_error_sum += error * error;
                summary.post_ticks += 1;
            }
            let hold_us = if time_us == LONG_START_US {
                LONG_HOLD_US
            } else {
                GUARD_HOLD_US
            };
            let start = start_invocation(
                protocol,
                sequence,
                time_us,
                hold_us,
                velocity,
                reference,
                Arc::clone(&gains),
            );
            let outcome = match start {
                Ok(pending) => {
                    for active in &invocations {
                        if active.captured.installation != pending.captured.installation {
                            summary.guard_version_overlaps += 1;
                        }
                    }
                    summary.started_invocations += 1;
                    let captured = pending.captured;
                    emit(
                        protocol,
                        format_args!(
                            "\"kind\":\"invocation\",\"invocation\":{sequence},\"tick\":{tick},\"start_us\":{time_us},\"requested_hold_us\":{hold_us},\"outcome\":\"Started\",\"captured_installation\":{},\"captured_gain\":{},\"captured_velocity\":{:.12},\"captured_reference\":{:.1},\"captured_command\":{:.12},\"completion_us\":{}",
                            json_id(captured.installation),
                            captured.gain,
                            captured.velocity,
                            captured.reference,
                            captured.command,
                            captured.completion_us,
                        ),
                    );
                    invocations.push(pending);
                    "Started"
                }
                Err(outcome) => {
                    match outcome {
                        "TransitionBusy" => summary.transition_skips += 1,
                        "ExecutionBusy" => summary.execution_skips += 1,
                        _ => unreachable!(),
                    }
                    emit(
                        protocol,
                        format_args!(
                            "\"kind\":\"invocation\",\"invocation\":{sequence},\"tick\":{tick},\"start_us\":{time_us},\"requested_hold_us\":{hold_us},\"outcome\":\"{outcome}\",\"captured_installation\":null,\"captured_gain\":null,\"captured_velocity\":{velocity:.12},\"captured_reference\":{reference:.1},\"captured_command\":null,\"completion_us\":null"
                        ),
                    );
                    outcome
                }
            };
            emit(
                protocol,
                format_args!(
                    "\"kind\":\"control\",\"tick\":{tick},\"scheduled_us\":{time_us},\"phase\":\"{}\",\"mass\":{:.1},\"reference\":{reference:.1},\"velocity\":{velocity:.12},\"error_sq\":{:.12},\"held_command\":{held_command:.12},\"dispatch_outcome\":\"{outcome}\"",
                    if time_us < MASS_CHANGE_US { "pre" } else { "post" },
                    mass_at(time_us),
                    error * error,
                ),
            );
            sequence += 1;
        }

        advance(&mut velocity, held_command, time_us);
    }

    assert!(invocations.is_empty(), "invocations outlived the replay");
    assert!(
        pending_attempt.is_none(),
        "atomic writer outlived the replay"
    );
    summary.pre_rmse = (pre_error_sum / summary.pre_ticks as f64).sqrt();
    summary.post_rmse = (post_error_sum / summary.post_ticks as f64).sqrt();
    let final_view = manager_view(&manager);
    summary.final_installation = final_view.installation;
    summary.final_gain = gains[&final_view.installation.program];
    summary.final_committed = final_view.committed;
    let skips_after = manager
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .exclusive_slot_skips();
    assert_eq!(
        skips_after.transition_busy - skips_before.transition_busy,
        summary.transition_skips
    );
    assert_eq!(
        skips_after.execution_busy - skips_before.execution_busy,
        summary.execution_skips
    );
    assert_eq!(skips_after.empty - skips_before.empty, 0);

    emit(
        protocol,
        format_args!(
            "\"kind\":\"summary\",\"pre_ticks\":{},\"post_ticks\":{},\"pre_rmse\":{:.12},\"post_rmse\":{:.12},\"started_invocations\":{},\"completed_invocations\":{},\"guard_version_overlaps\":{},\"retired_commands_after_publication\":{},\"transition_skips\":{},\"execution_skips\":{},\"scheduled_attempt_events\":8,\"actual_attempts\":{},\"busy_attempts\":{},\"retry_attempts\":{},\"successful_retries\":{},\"activations\":{},\"stale_errors\":{},\"stale_accepted\":{},\"accounting_errors\":{},\"final_installation\":{},\"final_gain\":{},\"final_committed\":{}",
            summary.pre_ticks,
            summary.post_ticks,
            summary.pre_rmse,
            summary.post_rmse,
            summary.started_invocations,
            summary.completed_invocations,
            summary.guard_version_overlaps,
            summary.retired_commands_after_publication,
            summary.transition_skips,
            summary.execution_skips,
            summary.actual_attempts,
            summary.busy_attempts,
            summary.retry_attempts,
            summary.successful_retries,
            summary.activations,
            summary.stale_errors,
            summary.stale_accepted,
            summary.accounting_errors,
            json_id(summary.final_installation),
            summary.final_gain,
            summary.final_committed,
        ),
    );

    let mutex = match Arc::try_unwrap(manager) {
        Ok(mutex) => mutex,
        Err(_) => panic!("manager references escaped replay"),
    };
    let mut manager = mutex
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    manager
        .clear_exclusive_for_diagnostics(owner, summary.final_installation)
        .expect("adaptation fixture clear failed");
    for handle in gain_handles.values().copied() {
        manager
            .unload_program_for(owner, handle)
            .expect("adaptation program unload failed");
    }
    let usage = manager.resource_usage();
    assert_eq!(usage.live_programs, 0);
    assert_eq!(usage.program_bytes, 0);
    assert_eq!(manager.committed_total_ns_per_s(), 0);
    summary
}

#[allow(clippy::too_many_arguments)]
fn emit_grid_attempt(
    protocol: Protocol,
    hold_us: u64,
    phase_us: u64,
    proposal: usize,
    ordinal: usize,
    scheduled_us: u64,
    deadline_us: u64,
    expected: InstallationId,
    candidate: ProgramHandle,
    candidate_gain: u32,
    outcome: &str,
    published_us: Option<u64>,
    returned_us: u64,
    receipt: Option<InstallReceipt>,
    before: ManagerView,
    after: ManagerView,
) {
    let published_us = published_us.map_or_else(|| "null".into(), |value| value.to_string());
    let receipt = receipt.map(json_receipt).unwrap_or_else(|| "null".into());
    emit_experiment(
        protocol,
        "schedule_grid",
        format_args!(
            "\"kind\":\"attempt\",\"hold_us\":{hold_us},\"phase_us\":{phase_us},\"proposal\":{proposal},\"ordinal\":{ordinal},\"scheduled_us\":{scheduled_us},\"deadline_us\":{deadline_us},\"expected\":{},\"candidate_handle\":{candidate},\"candidate_gain\":{candidate_gain},\"outcome\":\"{outcome}\",\"published_us\":{published_us},\"returned_us\":{returned_us},\"receipt\":{receipt},\"before_installation\":{},\"after_installation\":{},\"before_committed\":{},\"after_committed\":{}",
            json_id(expected), json_id(before.installation), json_id(after.installation),
            before.committed, after.committed,
        ),
    );
}

fn finish_grid_atomic(
    pending: ScheduledPendingAttempt,
    returned_us: u64,
    manager: &Arc<Mutex<BpfManager>>,
    hold_us: u64,
    phase_us: u64,
    summary: &mut ScheduleSummary,
) {
    let result = join_bounded(pending.worker, "scheduled atomic replacement");
    let after = manager_view(manager);
    assert!(check_attempt(
        pending.expected,
        pending.candidate,
        pending.before,
        after,
        &result,
    ));
    let receipt = result.expect("scheduled atomic replacement failed");
    assert_eq!(receipt.installed, pending.published);
    summary.successful_updates += 1;
    emit_grid_attempt(
        Protocol::Atomic,
        hold_us,
        phase_us,
        pending.proposal,
        pending.ordinal,
        pending.scheduled_us,
        pending.deadline_us,
        pending.expected,
        pending.candidate,
        pending.candidate_gain,
        "Ok",
        Some(pending.published_us),
        returned_us,
        Some(receipt),
        pending.before,
        after,
    );
}

fn build_grid_mesh(hold_us: u64, phase_us: u64) -> Vec<u64> {
    let mut mesh = BTreeSet::new();
    for time_us in (0..=DURATION_US).step_by(STEP_US as usize) {
        mesh.insert(time_us);
    }
    for tick_us in (0..DURATION_US).step_by(CONTROL_PERIOD_US as usize) {
        mesh.insert(tick_us);
        mesh.insert(tick_us + hold_us);
    }
    for base_us in PROPOSAL_US {
        let primary_us = base_us + phase_us;
        let deadline_us = primary_us + RETRY_DEADLINE_US;
        for ordinal in 0.. {
            let scheduled_us = scheduled_attempt_us(base_us, phase_us, ordinal);
            if scheduled_us >= deadline_us {
                break;
            }
            mesh.insert(scheduled_us);
        }
    }
    mesh.into_iter().collect()
}

fn finish_invocation(
    protocol: Protocol,
    experiment: &str,
    hold_us: u64,
    phase_us: Option<u64>,
    pending: PendingInvocation,
    published: InstallationId,
    held_command: &mut f64,
    summary: &mut ScheduleSummary,
) {
    pending.release.send(()).unwrap();
    join_bounded(pending.worker, "scheduled invocation completion")
        .expect("started scheduled invocation later failed");
    *held_command = pending.captured.command;
    summary.completed_invocations += 1;
    summary.max_abs_command = summary.max_abs_command.max(held_command.abs());
    summary.saturated_completions += usize::from(held_command.abs() == COMMAND_BOUND);
    summary.command_bound_violations += usize::from(held_command.abs() > COMMAND_BOUND);
    let retired = pending.captured.installation != published;
    summary.retired_commands += usize::from(retired);
    let phase = phase_us.map_or_else(|| "null".into(), |value| value.to_string());
    emit_experiment(
        protocol,
        experiment,
        format_args!(
            "\"kind\":\"completion\",\"hold_us\":{hold_us},\"phase_us\":{phase},\"invocation\":{},\"completion_us\":{},\"captured_installation\":{},\"gain\":{},\"command\":{:.12},\"published_installation\":{},\"retired_after_publication\":{retired}",
            pending.captured.sequence,
            pending.captured.completion_us,
            json_id(pending.captured.installation),
            pending.captured.gain,
            pending.captured.command,
            json_id(published),
        ),
    );
}

fn run_schedule_replay(protocol: Protocol, candidates: &[Candidate], hold_us: u64, phase_us: u64) {
    let owner = 7;
    let mut manager = BpfManager::new();
    let mut gain_handles = BTreeMap::new();
    let mut handle_gains = BTreeMap::new();
    for gain in std::iter::once(1).chain(candidates.iter().map(|candidate| candidate.gain)) {
        let handle = manager.load_raw_program_for(owner, program(gain)).unwrap();
        gain_handles.insert(gain, handle);
        handle_gains.insert(handle, gain);
    }
    let initial = protocol
        .install(&mut manager, owner, gain_handles[&1])
        .expect("grid initial publication failed")
        .installed;
    let manager = Arc::new(Mutex::new(manager));
    let gains = Arc::new(handle_gains);
    let skips_before = manager_view(&manager);
    let counter_before = manager.lock().unwrap().exclusive_slot_skips();
    emit_experiment(
        protocol,
        "schedule_grid",
        format_args!(
            "\"kind\":\"run_start\",\"hold_us\":{hold_us},\"phase_us\":{phase_us},\"duration_us\":{DURATION_US},\"step_max_us\":{STEP_US},\"control_period_us\":{CONTROL_PERIOD_US},\"mass_change_us\":{MASS_CHANGE_US},\"initial_gain\":1,\"proposal_bases_us\":[{},{},{},{}],\"retry_phase_step_us\":{RETRY_PHASE_STEP_US},\"retry_deadline_us\":{RETRY_DEADLINE_US},\"command_bound\":{COMMAND_BOUND},\"initial_installation\":{},\"initial_committed\":{}",
            PROPOSAL_US[0], PROPOSAL_US[1], PROPOSAL_US[2], PROPOSAL_US[3],
            json_id(initial), skips_before.committed,
        ),
    );

    let mesh = build_grid_mesh(hold_us, phase_us);
    let mut proposals: [ProposalState; 4] = std::array::from_fn(|_| ProposalState {
        expected: None,
        next_ordinal: 0,
        done: false,
        censored: false,
    });
    let mut invocations = Vec::<PendingInvocation>::new();
    let mut pending_attempt = None::<ScheduledPendingAttempt>;
    let mut published = initial;
    let mut velocity = 0.0_f64;
    let mut held_command = 0.0_f64;
    let mut prior_time = 0;
    let mut sequence = 0;
    let mut summary = ScheduleSummary::default();

    for time_us in mesh {
        if prior_time < DURATION_US {
            let end = time_us.min(DURATION_US);
            if end > prior_time {
                let delta = end - prior_time;
                summary.abs_command_integral_us += held_command.abs() * delta as f64;
                advance_by(&mut velocity, held_command, prior_time, delta);
            }
        }
        prior_time = time_us;

        while let Some(position) = invocations
            .iter()
            .position(|pending| pending.captured.completion_us == time_us)
        {
            let pending = invocations.remove(position);
            finish_invocation(
                protocol,
                "schedule_grid",
                hold_us,
                Some(phase_us),
                pending,
                published,
                &mut held_command,
                &mut summary,
            );
        }
        if pending_attempt.as_ref().is_some_and(|pending| {
            !invocations
                .iter()
                .any(|active| active.captured.installation == pending.expected)
        }) {
            finish_grid_atomic(
                pending_attempt.take().unwrap(),
                time_us,
                &manager,
                hold_us,
                phase_us,
                &mut summary,
            );
        }

        for candidate in candidates {
            let state = &mut proposals[candidate.proposal];
            if state.done {
                continue;
            }
            let ordinal = state.next_ordinal;
            let scheduled_us = scheduled_attempt_us(candidate.scheduled_us, phase_us, ordinal);
            let primary_us = candidate.scheduled_us + phase_us;
            let deadline_us = primary_us + RETRY_DEADLINE_US;
            if time_us != scheduled_us {
                continue;
            }
            assert!(time_us < deadline_us);
            assert!(pending_attempt.is_none());
            if ordinal == 0 {
                state.expected = Some(published);
            }
            let expected = state.expected.unwrap();
            let candidate_handle = gain_handles[&candidate.gain];
            let before = manager_view(&manager);
            summary.attempted_updates += 1;
            summary.retry_attempts += usize::from(ordinal > 0);
            if protocol == Protocol::Atomic {
                let writer_manager = Arc::clone(&manager);
                let worker = thread::spawn(move || {
                    let mut manager = writer_manager.lock().unwrap_or_else(|p| p.into_inner());
                    protocol.replace(&mut manager, owner, expected, candidate_handle)
                });
                let deadline = Instant::now() + TIMEOUT;
                let observed = loop {
                    let observed = protocol
                        .observe(|id| id)
                        .expect("grid AP observation failed");
                    if observed.program == candidate_handle {
                        break observed;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out observing grid AP publication"
                    );
                    thread::yield_now();
                };
                published = observed;
                state.done = true;
                let pending = ScheduledPendingAttempt {
                    proposal: candidate.proposal,
                    ordinal,
                    scheduled_us,
                    deadline_us,
                    expected,
                    candidate: candidate_handle,
                    candidate_gain: candidate.gain,
                    before,
                    published_us: time_us,
                    published: observed,
                    worker,
                };
                if !invocations
                    .iter()
                    .any(|active| active.captured.installation == expected)
                {
                    finish_grid_atomic(pending, time_us, &manager, hold_us, phase_us, &mut summary);
                } else {
                    pending_attempt = Some(pending);
                }
            } else {
                let result = {
                    let mut manager = manager.lock().unwrap_or_else(|p| p.into_inner());
                    protocol.replace(&mut manager, owner, expected, candidate_handle)
                };
                let after = manager_view(&manager);
                assert!(check_attempt(
                    expected,
                    candidate_handle,
                    before,
                    after,
                    &result
                ));
                let (outcome, receipt) = classify_attempt(&result);
                if outcome == "Ok" {
                    published = receipt.unwrap().installed;
                    state.done = true;
                    summary.successful_updates += 1;
                } else {
                    assert_eq!(outcome, "Busy");
                    summary.busy_attempts += 1;
                    state.next_ordinal += 1;
                    let next =
                        scheduled_attempt_us(candidate.scheduled_us, phase_us, state.next_ordinal);
                    if next >= deadline_us {
                        state.done = true;
                        state.censored = true;
                        summary.deadline_censored += 1;
                    }
                }
                emit_grid_attempt(
                    protocol,
                    hold_us,
                    phase_us,
                    candidate.proposal,
                    ordinal,
                    scheduled_us,
                    deadline_us,
                    expected,
                    candidate_handle,
                    candidate.gain,
                    outcome,
                    (outcome == "Ok").then_some(time_us),
                    time_us,
                    receipt,
                    before,
                    after,
                );
            }
        }

        if time_us < DURATION_US && time_us % CONTROL_PERIOD_US == 0 {
            let tick = time_us / CONTROL_PERIOD_US;
            let reference = reference_at(time_us);
            let error = reference - velocity;
            if time_us < MASS_CHANGE_US {
                summary.pre_error_sum += error * error;
            } else {
                summary.post_error_sum += error * error;
            }
            summary.max_abs_error = summary.max_abs_error.max(error.abs());
            summary.scheduled_ticks += 1;
            let start = start_invocation(
                protocol,
                sequence,
                time_us,
                hold_us,
                velocity,
                reference,
                Arc::clone(&gains),
            );
            match start {
                Ok(pending) => {
                    summary.old_new_overlaps += invocations
                        .iter()
                        .filter(|active| {
                            active.captured.installation != pending.captured.installation
                        })
                        .count();
                    emit_experiment(
                        protocol,
                        "schedule_grid",
                        format_args!(
                            "\"kind\":\"dispatch\",\"hold_us\":{hold_us},\"phase_us\":{phase_us},\"tick\":{tick},\"scheduled_us\":{time_us},\"outcome\":\"Started\",\"captured_installation\":{},\"gain\":{},\"velocity\":{velocity:.12},\"reference\":{reference:.1},\"command\":{:.12},\"completion_us\":{}",
                            json_id(pending.captured.installation), pending.captured.gain,
                            pending.captured.command, pending.captured.completion_us,
                        ),
                    );
                    sequence += 1;
                    if hold_us == 0 {
                        finish_invocation(
                            protocol,
                            "schedule_grid",
                            hold_us,
                            Some(phase_us),
                            pending,
                            published,
                            &mut held_command,
                            &mut summary,
                        );
                    } else {
                        invocations.push(pending);
                    }
                }
                Err(outcome) => {
                    match outcome {
                        "TransitionBusy" => summary.transition_skips += 1,
                        "ExecutionBusy" => summary.execution_skips += 1,
                        _ => unreachable!(),
                    }
                    emit_experiment(
                        protocol,
                        "schedule_grid",
                        format_args!(
                            "\"kind\":\"dispatch\",\"hold_us\":{hold_us},\"phase_us\":{phase_us},\"tick\":{tick},\"scheduled_us\":{time_us},\"outcome\":\"{outcome}\",\"captured_installation\":null,\"gain\":null,\"velocity\":{velocity:.12},\"reference\":{reference:.1},\"command\":null,\"completion_us\":null"
                        ),
                    );
                    sequence += 1;
                }
            }
        }
    }
    assert!(invocations.is_empty());
    assert!(pending_attempt.is_none());
    for state in &mut proposals {
        if !state.done {
            state.done = true;
            state.censored = true;
            summary.deadline_censored += 1;
        }
    }
    let final_view = manager_view(&manager);
    let counters = manager.lock().unwrap().exclusive_slot_skips();
    summary.transition_skips = counters.transition_busy - counter_before.transition_busy;
    summary.execution_skips = counters.execution_busy - counter_before.execution_busy;
    summary.empty_skips = counters.empty - counter_before.empty;
    let pre_rmse = (summary.pre_error_sum / 4_000.0).sqrt();
    let post_rmse = (summary.post_error_sum / 4_000.0).sqrt();
    emit_experiment(
        protocol,
        "schedule_grid",
        format_args!(
            "\"kind\":\"run_end\",\"hold_us\":{hold_us},\"phase_us\":{phase_us},\"scheduled_ticks\":{},\"completed_invocations\":{},\"attempted_updates\":{},\"successful_updates\":{},\"busy_attempts\":{},\"retry_attempts\":{},\"deadline_censored\":{},\"old_new_overlaps\":{},\"retired_commands\":{},\"pre_rmse\":{pre_rmse:.12},\"post_rmse\":{post_rmse:.12},\"max_abs_error\":{:.12},\"max_abs_command\":{:.12},\"abs_command_integral_us\":{:.12},\"saturated_completions\":{},\"command_bound_violations\":{},\"transition_skips\":{},\"execution_skips\":{},\"empty_skips\":{},\"final_installation\":{},\"final_gain\":{},\"final_committed\":{}",
            summary.scheduled_ticks, summary.completed_invocations, summary.attempted_updates,
            summary.successful_updates, summary.busy_attempts, summary.retry_attempts,
            summary.deadline_censored, summary.old_new_overlaps, summary.retired_commands,
            summary.max_abs_error, summary.max_abs_command, summary.abs_command_integral_us,
            summary.saturated_completions, summary.command_bound_violations,
            summary.transition_skips, summary.execution_skips, summary.empty_skips,
            json_id(final_view.installation), gains[&final_view.installation.program],
            final_view.committed,
        ),
    );

    let mutex = Arc::try_unwrap(manager).unwrap_or_else(|_| panic!("grid manager escaped"));
    let mut manager = mutex.into_inner().unwrap_or_else(|p| p.into_inner());
    manager
        .clear_exclusive_for_diagnostics(owner, final_view.installation)
        .unwrap();
    for handle in gain_handles.values().copied() {
        manager.unload_program_for(owner, handle).unwrap();
    }
    assert_eq!(manager.resource_usage().live_programs, 0);
    assert_eq!(manager.resource_usage().program_bytes, 0);
    assert_eq!(manager.committed_total_ns_per_s(), 0);
}

fn run_corrective_stop(protocol: Protocol) {
    const FAULT_US: u64 = 4_250_000;
    const STOP_BAND: f64 = 0.05;
    const STOP_DWELL_US: u64 = 100_000;
    const LONG_START: u64 = 4_249_000;
    const LONG_HOLD: u64 = 2_000;
    const NORMAL_HOLD: u64 = 100;

    let owner = 7;
    let mut manager = BpfManager::new();
    let a = manager.load_raw_program_for(owner, program(1)).unwrap();
    let zero = manager.load_raw_program_for(owner, program(0)).unwrap();
    let initial = protocol.install(&mut manager, owner, a).unwrap().installed;
    let manager = Arc::new(Mutex::new(manager));
    let gains = Arc::new(BTreeMap::from([(a, 1), (zero, 0)]));
    let counter_before = manager.lock().unwrap().exclusive_slot_skips();
    emit_experiment(
        protocol,
        "corrective_stop",
        format_args!(
            "\"kind\":\"run_start\",\"duration_us\":{DURATION_US},\"step_max_us\":{STEP_US},\"control_period_us\":{CONTROL_PERIOD_US},\"retry_phase_step_us\":{RETRY_PHASE_STEP_US},\"retry_deadline_us\":{RETRY_DEADLINE_US},\"fault_us\":{FAULT_US},\"stop_band\":{STOP_BAND},\"stop_dwell_us\":{STOP_DWELL_US},\"initial_velocity\":1.0,\"initial_command\":1.0,\"reference\":2.0,\"mass\":1.0,\"command_bound\":{COMMAND_BOUND},\"long_start_us\":{LONG_START},\"long_hold_us\":{LONG_HOLD},\"normal_hold_us\":{NORMAL_HOLD},\"initial_installation\":{},\"initial_committed\":{},\"zero_handle\":{zero}",
            json_id(initial), manager_view(&manager).committed,
        ),
    );

    let mut mesh = BTreeSet::new();
    for time_us in (0..=DURATION_US).step_by(STEP_US as usize) {
        mesh.insert(time_us);
    }
    for tick_us in (0..DURATION_US).step_by(CONTROL_PERIOD_US as usize) {
        mesh.insert(tick_us);
        mesh.insert(
            tick_us
                + if tick_us == LONG_START {
                    LONG_HOLD
                } else {
                    NORMAL_HOLD
                },
        );
    }
    for ordinal in 0.. {
        let scheduled = scheduled_attempt_us(FAULT_US, 0, ordinal);
        if scheduled >= FAULT_US + RETRY_DEADLINE_US {
            break;
        }
        mesh.insert(scheduled);
    }

    let mut velocity = 1.0_f64;
    let mut held_command = 1.0_f64;
    let mut prior_time = 0;
    let mut published = initial;
    let mut published_us = None;
    let mut pending_attempt = None::<ScheduledPendingAttempt>;
    let mut invocations = Vec::<PendingInvocation>::new();
    let mut proposal = ProposalState {
        expected: None,
        next_ordinal: 0,
        done: false,
        censored: false,
    };
    let mut sequence = 0;
    let mut summary = ScheduleSummary::default();
    let mut fault_integral = 0.0;
    let mut publication_integral = 0.0;
    let mut below_since = None;
    let mut stop_entry = None;
    let mut stop_confirmed = None;
    let mut max_post_fault_abs_velocity = 0.0_f64;
    let mut max_post_fault_abs_error = 0.0_f64;

    for time_us in mesh {
        if prior_time < DURATION_US {
            let end = time_us.min(DURATION_US);
            if end > prior_time {
                let delta = end - prior_time;
                if end > FAULT_US {
                    fault_integral += held_command.abs() * (end - prior_time.max(FAULT_US)) as f64;
                }
                if let Some(publication) = published_us {
                    if end > publication {
                        publication_integral +=
                            held_command.abs() * (end - prior_time.max(publication)) as f64;
                    }
                }
                velocity += (delta as f64 / 1_000_000.0) * (held_command - velocity);
            }
        }
        prior_time = time_us;

        while let Some(position) = invocations
            .iter()
            .position(|p| p.captured.completion_us == time_us)
        {
            let pending = invocations.remove(position);
            let hold = pending.captured.completion_us
                - pending.captured.sequence as u64 * CONTROL_PERIOD_US;
            finish_invocation(
                protocol,
                "corrective_stop",
                hold,
                None,
                pending,
                published,
                &mut held_command,
                &mut summary,
            );
        }
        if pending_attempt.as_ref().is_some_and(|pending| {
            !invocations
                .iter()
                .any(|active| active.captured.installation == pending.expected)
        }) {
            let pending = pending_attempt.take().unwrap();
            let result = join_bounded(pending.worker, "corrective atomic replacement");
            let after = manager_view(&manager);
            assert!(check_attempt(
                pending.expected,
                pending.candidate,
                pending.before,
                after,
                &result
            ));
            let receipt = result.expect("corrective atomic replacement failed");
            summary.successful_updates += 1;
            emit_experiment(protocol, "corrective_stop", format_args!(
                "\"kind\":\"attempt\",\"ordinal\":{},\"scheduled_us\":{},\"deadline_us\":{},\"expected\":{},\"candidate_handle\":{},\"outcome\":\"Ok\",\"published_us\":{},\"returned_us\":{time_us},\"receipt\":{},\"before_installation\":{},\"after_installation\":{},\"before_committed\":{},\"after_committed\":{}",
                pending.ordinal, pending.scheduled_us, pending.deadline_us, json_id(pending.expected),
                pending.candidate, pending.published_us, json_receipt(receipt),
                json_id(pending.before.installation), json_id(after.installation),
                pending.before.committed, after.committed));
        }

        if !proposal.done {
            let ordinal = proposal.next_ordinal;
            let scheduled = scheduled_attempt_us(FAULT_US, 0, ordinal);
            let deadline = FAULT_US + RETRY_DEADLINE_US;
            if time_us == scheduled {
                assert!(time_us < deadline && pending_attempt.is_none());
                if ordinal == 0 {
                    proposal.expected = Some(published);
                }
                let expected = proposal.expected.unwrap();
                let before = manager_view(&manager);
                summary.attempted_updates += 1;
                summary.retry_attempts += usize::from(ordinal > 0);
                if protocol == Protocol::Atomic {
                    let writer_manager = Arc::clone(&manager);
                    let worker = thread::spawn(move || {
                        let mut manager = writer_manager.lock().unwrap_or_else(|p| p.into_inner());
                        protocol.replace(&mut manager, owner, expected, zero)
                    });
                    let deadline_real = Instant::now() + TIMEOUT;
                    let observed = loop {
                        let observed = protocol.observe(|id| id).unwrap();
                        if observed.program == zero {
                            break observed;
                        }
                        assert!(Instant::now() < deadline_real);
                        thread::yield_now();
                    };
                    published = observed;
                    published_us = Some(time_us);
                    proposal.done = true;
                    let pending = ScheduledPendingAttempt {
                        proposal: 0,
                        ordinal,
                        scheduled_us: scheduled,
                        deadline_us: deadline,
                        expected,
                        candidate: zero,
                        candidate_gain: 0,
                        before,
                        published_us: time_us,
                        published: observed,
                        worker,
                    };
                    if !invocations
                        .iter()
                        .any(|active| active.captured.installation == expected)
                    {
                        let result = join_bounded(pending.worker, "corrective atomic replacement");
                        let after = manager_view(&manager);
                        let receipt = result.unwrap();
                        summary.successful_updates += 1;
                        emit_experiment(protocol, "corrective_stop", format_args!(
                            "\"kind\":\"attempt\",\"ordinal\":{ordinal},\"scheduled_us\":{scheduled},\"deadline_us\":{deadline},\"expected\":{},\"candidate_handle\":{zero},\"outcome\":\"Ok\",\"published_us\":{time_us},\"returned_us\":{time_us},\"receipt\":{},\"before_installation\":{},\"after_installation\":{},\"before_committed\":{},\"after_committed\":{}",
                            json_id(expected), json_receipt(receipt), json_id(before.installation),
                            json_id(after.installation), before.committed, after.committed));
                    } else {
                        pending_attempt = Some(pending);
                    }
                } else {
                    let result = {
                        let mut manager = manager.lock().unwrap_or_else(|p| p.into_inner());
                        protocol.replace(&mut manager, owner, expected, zero)
                    };
                    let after = manager_view(&manager);
                    let (outcome, receipt) = classify_attempt(&result);
                    if outcome == "Ok" {
                        published = receipt.unwrap().installed;
                        published_us = Some(time_us);
                        proposal.done = true;
                        summary.successful_updates += 1;
                    } else {
                        assert_eq!(outcome, "Busy");
                        summary.busy_attempts += 1;
                        proposal.next_ordinal += 1;
                        if scheduled_attempt_us(FAULT_US, 0, proposal.next_ordinal) >= deadline {
                            proposal.done = true;
                            proposal.censored = true;
                        }
                    }
                    emit_experiment(protocol, "corrective_stop", format_args!(
                        "\"kind\":\"attempt\",\"ordinal\":{ordinal},\"scheduled_us\":{scheduled},\"deadline_us\":{deadline},\"expected\":{},\"candidate_handle\":{zero},\"outcome\":\"{outcome}\",\"published_us\":{},\"returned_us\":{time_us},\"receipt\":{},\"before_installation\":{},\"after_installation\":{},\"before_committed\":{},\"after_committed\":{}",
                        json_id(expected), if outcome == "Ok" { time_us.to_string() } else { "null".into() },
                        receipt.map(json_receipt).unwrap_or_else(|| "null".into()),
                        json_id(before.installation), json_id(after.installation),
                        before.committed, after.committed));
                }
            }
        }

        if time_us < DURATION_US && time_us % CONTROL_PERIOD_US == 0 {
            let hold = if time_us == LONG_START {
                LONG_HOLD
            } else {
                NORMAL_HOLD
            };
            match start_invocation(
                protocol,
                sequence,
                time_us,
                hold,
                velocity,
                2.0,
                Arc::clone(&gains),
            ) {
                Ok(pending) => {
                    emit_experiment(protocol, "corrective_stop", format_args!(
                        "\"kind\":\"dispatch\",\"tick\":{},\"scheduled_us\":{time_us},\"outcome\":\"Started\",\"captured_installation\":{},\"gain\":{},\"velocity\":{velocity:.12},\"reference\":2.0,\"command\":{:.12},\"completion_us\":{}",
                        time_us / CONTROL_PERIOD_US, json_id(pending.captured.installation),
                        pending.captured.gain, pending.captured.command, pending.captured.completion_us));
                    invocations.push(pending);
                }
                Err(outcome) => {
                    match outcome {
                        "TransitionBusy" => summary.transition_skips += 1,
                        "ExecutionBusy" => summary.execution_skips += 1,
                        _ => unreachable!(),
                    }
                    emit_experiment(protocol, "corrective_stop", format_args!(
                        "\"kind\":\"dispatch\",\"tick\":{},\"scheduled_us\":{time_us},\"outcome\":\"{outcome}\",\"captured_installation\":null,\"gain\":null,\"velocity\":{velocity:.12},\"reference\":2.0,\"command\":null,\"completion_us\":null",
                        time_us / CONTROL_PERIOD_US));
                }
            }
            sequence += 1;
        }

        if time_us >= FAULT_US && time_us <= DURATION_US {
            max_post_fault_abs_velocity = max_post_fault_abs_velocity.max(velocity.abs());
            max_post_fault_abs_error = max_post_fault_abs_error.max((2.0 - velocity).abs());
            if stop_confirmed.is_none() {
                if velocity.abs() <= STOP_BAND {
                    let entered = *below_since.get_or_insert(time_us);
                    if time_us - entered >= STOP_DWELL_US {
                        stop_entry = Some(entered);
                        stop_confirmed = Some(time_us);
                    }
                } else {
                    below_since = None;
                }
            }
        }
    }
    assert!(invocations.is_empty() && pending_attempt.is_none());
    let final_view = manager_view(&manager);
    let counters = manager.lock().unwrap().exclusive_slot_skips();
    summary.transition_skips = counters.transition_busy - counter_before.transition_busy;
    summary.execution_skips = counters.execution_busy - counter_before.execution_busy;
    summary.empty_skips = counters.empty - counter_before.empty;
    let entry = stop_entry.map_or_else(|| "null".into(), |value| value.to_string());
    let confirmed = stop_confirmed.map_or_else(|| "null".into(), |value| value.to_string());
    emit_experiment(protocol, "corrective_stop", format_args!(
        "\"kind\":\"run_end\",\"published_us\":{},\"stop_entry_us\":{entry},\"stop_confirmed_us\":{confirmed},\"stop_censored\":{},\"fault_abs_command_integral_us\":{fault_integral:.12},\"publication_abs_command_integral_us\":{publication_integral:.12},\"max_post_fault_abs_velocity\":{max_post_fault_abs_velocity:.12},\"max_post_fault_abs_error\":{max_post_fault_abs_error:.12},\"attempts\":{},\"busy_attempts\":{},\"retries\":{},\"transition_skips\":{},\"execution_skips\":{},\"empty_skips\":{},\"retired_commands\":{},\"saturated_completions\":{},\"command_bound_violations\":{},\"final_installation\":{},\"final_gain\":{}",
        published_us.unwrap(), stop_confirmed.is_none(), summary.attempted_updates,
        summary.busy_attempts, summary.retry_attempts, summary.transition_skips,
        summary.execution_skips, summary.empty_skips, summary.retired_commands,
        summary.saturated_completions, summary.command_bound_violations,
        json_id(final_view.installation),
        gains[&final_view.installation.program]));

    let mutex = Arc::try_unwrap(manager).unwrap_or_else(|_| panic!("corrective manager escaped"));
    let mut manager = mutex.into_inner().unwrap_or_else(|p| p.into_inner());
    manager
        .clear_exclusive_for_diagnostics(owner, final_view.installation)
        .unwrap();
    manager.unload_program_for(owner, a).unwrap();
    manager.unload_program_for(owner, zero).unwrap();
    assert_eq!(manager.resource_usage().live_programs, 0);
    assert_eq!(manager.committed_total_ns_per_s(), 0);
}

#[test]
fn deterministic_adaptation_replay_preserves_manager_and_guard_evidence() {
    let candidates = generate_seed_candidates();
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.gain)
            .collect::<Vec<_>>(),
        [2, 4, 8, 16]
    );
    assert!(candidates
        .iter()
        .all(|candidate| candidate.prior_rmse > 0.1));

    let frozen = replay(Protocol::Frozen, &candidates);
    let atomic = replay(Protocol::Atomic, &candidates);
    let guarded = replay(Protocol::Guarded, &candidates);
    for summary in [&frozen, &atomic, &guarded] {
        assert_eq!((summary.pre_ticks, summary.post_ticks), (4_000, 4_000));
        assert_eq!(summary.started_invocations, summary.completed_invocations);
        assert_eq!(summary.accounting_errors, 0);
        assert_eq!(summary.stale_accepted, 0);
        assert!(summary.pre_rmse.is_finite() && summary.post_rmse.is_finite());
    }
    assert!((frozen.pre_rmse - atomic.pre_rmse).abs() < 1e-12);
    assert!((frozen.pre_rmse - guarded.pre_rmse).abs() < 1e-12);
    assert_eq!((frozen.final_gain, frozen.activations), (1, 0));
    assert_eq!((atomic.activations, guarded.activations), (4, 4));
    assert_eq!(
        (atomic.final_gain, guarded.final_gain),
        (
            candidates.last().unwrap().gain,
            candidates.last().unwrap().gain
        )
    );
    assert_eq!(
        (
            atomic.guard_version_overlaps,
            atomic.retired_commands_after_publication
        ),
        (1, 1)
    );
    assert_eq!(
        (
            frozen.guard_version_overlaps,
            guarded.guard_version_overlaps
        ),
        (0, 0)
    );
    assert_eq!(
        (
            frozen.execution_skips,
            atomic.execution_skips,
            guarded.execution_skips
        ),
        (1, 0, 1)
    );
    assert_eq!((atomic.busy_attempts, guarded.busy_attempts), (0, 1));
    assert_eq!((atomic.stale_errors, guarded.stale_errors), (4, 3));
    assert_eq!(
        (atomic.successful_retries, guarded.successful_retries),
        (0, 1)
    );
}

#[test]
#[ignore = "finite 500-run hosted schedule campaign; use reproduce-update-adaptation.py"]
fn deterministic_schedule_grid_uses_real_manager_and_guard_paths() {
    let candidates = generate_seed_candidates();
    for protocol in [Protocol::Atomic, Protocol::Guarded] {
        for hold_us in GRID_HOLDS_US {
            for phase_us in (0..CONTROL_PERIOD_US).step_by(GRID_PHASE_STEP_US as usize) {
                run_schedule_replay(protocol, &candidates, hold_us, phase_us);
            }
        }
        run_corrective_stop(protocol);
    }
}
