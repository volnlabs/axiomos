//! Hosted same-manager publication cost measurements.
//!
//! The diagnostic observers hold the real production snapshot guards. They do
//! not execute bytecode because hosted `BpfManager::execute_program` requires a
//! privileged kernel `ExecutionContext`.

#![cfg(all(
    feature = "bpf-update-diagnostics",
    feature = "bpf-unsigned-development",
    not(target_os = "none")
))]

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use kernel::bpf::{
    BpfManager, BpfResourceUsage, ControlSlot, HookRunError, InstallError, InstallReceipt,
    InstallationId, ProgramHandle, StatePolicy,
};
use kernel_bpf::bytecode::insn::BpfInsn;

const PERIOD_NS: u64 = 1_000_000;
const CLOCK_SAMPLES: usize = 1_000;
const CONTROLLED_TRANSITION_SAMPLES: usize = 100;
const START_DELAY_NS: u64 = 5_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Atomic,
    Guarded,
}

impl Protocol {
    fn parse(value: &str) -> Self {
        match value {
            "atomic" => Self::Atomic,
            "guarded" => Self::Guarded,
            _ => panic!("AXIOM_UPDATE_COST_PROTOCOL must be atomic or guarded"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Atomic => "atomic",
            Self::Guarded => "guarded",
        }
    }
}

struct UpdateSample {
    attempt: usize,
    logical_update: usize,
    retry_ordinal: usize,
    outcome: &'static str,
    latency_ns: u64,
    scheduled_offset_ns: u64,
    started_offset_ns: u64,
    lateness_ns: u64,
}

struct DispatchSample {
    scheduled: u64,
    outcome: &'static str,
    call_ns: u64,
    entry_ns: Option<u64>,
    release_ns: Option<u64>,
    lateness_ns: u64,
    actual_hold_ns: Option<u64>,
}

struct DispatchRun {
    samples: Vec<DispatchSample>,
    scheduled_releases: u64,
    missed_releases: u64,
}

fn env_usize(name: &str) -> usize {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("missing {name}"))
        .parse()
        .unwrap_or_else(|_| panic!("invalid {name}"))
}

#[inline]
fn raw_ns() -> u64 {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: timestamp points to writable storage and CLOCK_MONOTONIC_RAW is
    // a read-only Linux process clock.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut timestamp) };
    assert_eq!(result, 0, "clock_gettime(CLOCK_MONOTONIC_RAW) failed");
    (timestamp.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(timestamp.tv_nsec as u64))
        .expect("monotonic timestamp overflow")
}

fn clock_resolution_ns() -> u64 {
    let mut resolution = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: resolution points to writable storage for a read-only query.
    let result = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC_RAW, &mut resolution) };
    assert_eq!(result, 0, "clock_getres(CLOCK_MONOTONIC_RAW) failed");
    (resolution.tv_sec as u64) * 1_000_000_000 + resolution.tv_nsec as u64
}

fn pin_current_thread(cpu: usize) {
    // SAFETY: cpu_set_t is plain C storage initialized before the libc calls.
    unsafe {
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let result = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            core::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
        assert_eq!(result, 0, "failed to pin measurement thread to CPU {cpu}");
        assert_eq!(
            libc::sched_getcpu(),
            cpu as i32,
            "measurement thread affinity mismatch"
        );
    }
}

fn cpu_topology(cpu: usize) -> (usize, usize) {
    let read = |name: &str| {
        std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu{cpu}/topology/{name}"))
            .unwrap_or_else(|_| panic!("missing topology metadata for CPU {cpu}"))
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("invalid topology metadata for CPU {cpu}"))
    };
    (read("physical_package_id"), read("core_id"))
}

fn cpu_governor(cpu: usize) -> String {
    std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
    ))
    .map(|value| value.trim().to_owned())
    .unwrap_or_else(|_| "unknown".into())
}

fn load_milli() -> (u64, u64, u64) {
    let load = std::fs::read_to_string("/proc/loadavg").expect("missing /proc/loadavg");
    let values: Vec<u64> = load
        .split_whitespace()
        .take(3)
        .map(|value| (value.parse::<f64>().expect("invalid /proc/loadavg") * 1000.0).round() as u64)
        .collect();
    assert_eq!(values.len(), 3, "incomplete /proc/loadavg");
    (values[0], values[1], values[2])
}

fn wait_until(deadline_ns: u64) -> u64 {
    loop {
        let now = raw_ns();
        if now >= deadline_ns {
            return now;
        }
        let remaining = deadline_ns - now;
        if remaining > 100_000 {
            thread::sleep(Duration::from_nanos(remaining - 50_000));
        } else {
            core::hint::spin_loop();
        }
    }
}

fn scheduled_ns(start_ns: u64, attempt: u64, run: u64) -> u64 {
    let phase_ns = ((137 * attempt + 97 * run) % 1_000) * 1_000;
    start_ns + attempt * PERIOD_NS + phase_ns
}

fn program(value: i32) -> Vec<BpfInsn> {
    vec![BpfInsn::mov64_imm(0, value), BpfInsn::exit()]
}

fn install(
    manager: &mut BpfManager,
    protocol: Protocol,
    owner: u64,
    candidate: ProgramHandle,
) -> Result<InstallReceipt, InstallError> {
    match protocol {
        Protocol::Atomic => manager.try_install_atomic_without_quiescence_for(
            owner,
            ControlSlot::Timer,
            candidate,
            StatePolicy::Reset,
        ),
        Protocol::Guarded => manager.try_install_exclusive_for(
            owner,
            ControlSlot::Timer,
            candidate,
            StatePolicy::Reset,
        ),
    }
}

fn replace(
    manager: &mut BpfManager,
    protocol: Protocol,
    owner: u64,
    expected: InstallationId,
    candidate: ProgramHandle,
) -> Result<InstallReceipt, InstallError> {
    match protocol {
        Protocol::Atomic => manager.try_replace_atomic_without_quiescence_for(
            owner,
            ControlSlot::Timer,
            expected,
            candidate,
            StatePolicy::Reset,
        ),
        Protocol::Guarded => manager.try_replace_exclusive_for(
            owner,
            ControlSlot::Timer,
            expected,
            candidate,
            StatePolicy::Reset,
        ),
    }
}

fn alternate(current: ProgramHandle, a: ProgramHandle, b: ProgramHandle) -> ProgramHandle {
    if current == a {
        b
    } else {
        a
    }
}

fn warmup(
    manager: &mut BpfManager,
    protocol: Protocol,
    owner: u64,
    a: ProgramHandle,
    b: ProgramHandle,
    count: usize,
    mut installed: InstallationId,
) -> InstallationId {
    for _ in 0..count {
        let candidate = alternate(installed.program, a, b);
        installed = replace(manager, protocol, owner, installed, candidate)
            .expect("uncontended warmup replacement failed")
            .installed;
    }
    installed
}

fn controlled_transition_samples(dispatch_cpu: usize) -> Vec<u64> {
    let entered = Arc::new(Barrier::new(2));
    let observed = Arc::new(Barrier::new(2));
    let worker_entered = entered.clone();
    let worker_observed = observed.clone();
    let worker = thread::spawn(move || {
        pin_current_thread(dispatch_cpu);
        let mut samples = Vec::with_capacity(CONTROLLED_TRANSITION_SAMPLES);
        for _ in 0..CONTROLLED_TRANSITION_SAMPLES {
            worker_entered.wait();
            let start = raw_ns();
            let outcome = BpfManager::observe_timer_exclusive(black_box);
            let end = raw_ns();
            assert!(matches!(outcome, Err(HookRunError::TransitionBusy)));
            samples.push(end - start);
            worker_observed.wait();
        }
        samples
    });
    for _ in 0..CONTROLLED_TRANSITION_SAMPLES {
        BpfManager::hold_timer_exclusive_transition_for_diagnostics(|| {
            entered.wait();
            observed.wait();
        })
        .expect("controlled transition gate was unexpectedly busy");
    }
    worker.join().expect("controlled transition probe panicked")
}

#[allow(clippy::too_many_arguments)]
fn dispatch_loop(
    protocol: Protocol,
    hold_ns: u64,
    dispatch_cpu: usize,
    start_ns: u64,
    stop: Arc<AtomicBool>,
    ready: Arc<Barrier>,
    a: ProgramHandle,
    b: ProgramHandle,
    capacity: usize,
) -> DispatchRun {
    pin_current_thread(dispatch_cpu);
    let mut samples = Vec::with_capacity(capacity);
    let mut scheduled = 0_u64;
    let mut missed = 0_u64;
    ready.wait();
    while !stop.load(Ordering::Acquire) {
        let target = start_ns + scheduled * PERIOD_NS;
        let next = target + PERIOD_NS;
        let before_wait = raw_ns();
        if before_wait >= next {
            missed += 1;
            scheduled += 1;
            continue;
        }
        let started = wait_until(target);
        if stop.load(Ordering::Acquire) {
            break;
        }
        if started >= next {
            missed += 1;
            scheduled += 1;
            continue;
        }
        let mut entry_ns = None;
        let mut release_start = None;
        let mut actual_hold_ns = None;
        let mut callback = |id: InstallationId| {
            assert!(
                id.program == a || id.program == b,
                "observer saw an unknown program"
            );
            black_box(id);
            let entered_at = raw_ns();
            entry_ns = Some(entered_at - started);
            let hold_end = wait_until(entered_at + hold_ns);
            actual_hold_ns = Some(hold_end - entered_at);
            release_start = Some(hold_end);
        };
        let outcome = match protocol {
            Protocol::Atomic => BpfManager::observe_timer_atomic_without_quiescence(&mut callback),
            Protocol::Guarded => BpfManager::observe_timer_exclusive(&mut callback),
        };
        let ended = raw_ns();
        let outcome = match outcome {
            Ok(()) => "Ok",
            Err(HookRunError::TransitionBusy) => "TransitionBusy",
            Err(HookRunError::ExecutionBusy) => "ExecutionBusy",
            Err(error) => panic!("unexpected dispatch result: {error:?}"),
        };
        assert!(
            samples.len() < samples.capacity(),
            "dispatch sample buffer exhausted"
        );
        samples.push(DispatchSample {
            scheduled,
            outcome,
            call_ns: ended - started,
            entry_ns,
            release_ns: release_start.map(|value| ended - value),
            lateness_ns: started.saturating_sub(target),
            actual_hold_ns,
        });
        scheduled += 1;
    }
    DispatchRun {
        samples,
        scheduled_releases: scheduled,
        missed_releases: missed,
    }
}

fn json_optional(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn prefix(protocol: Protocol, hold_us: usize, run: usize, kind: &str) -> String {
    format!(
        "UPDATE_COST {{\"schema\":1,\"protocol\":\"{}\",\"hold_us\":{},\"run\":{},\"kind\":\"{}\"",
        protocol.name(),
        hold_us,
        run,
        kind,
    )
}

fn emit_resource(
    protocol: Protocol,
    hold_us: usize,
    run: usize,
    phase: &str,
    usage: BpfResourceUsage,
) {
    println!(
        "{},\"phase\":\"{}\",\"live_programs\":{},\"program_bytes\":{}}}",
        prefix(protocol, hold_us, run, "resource"),
        phase,
        usage.live_programs,
        usage.program_bytes,
    );
}

#[test]
fn phase_schedule_stays_inside_each_millisecond_bin() {
    for run in 0..10 {
        for attempt in 0..10_000 {
            let scheduled = scheduled_ns(5_000_000, attempt, run);
            assert!(
                (5_000_000 + attempt * PERIOD_NS..5_000_000 + (attempt + 1) * PERIOD_NS)
                    .contains(&scheduled)
            );
        }
    }
}

#[test]
#[ignore = "finite hosted measurement; run through update-cost-matrix.py"]
fn measures_update_cost() {
    assert!(
        !cfg!(debug_assertions),
        "update-cost measurements require --release"
    );
    let protocol =
        Protocol::parse(&std::env::var("AXIOM_UPDATE_COST_PROTOCOL").expect("missing protocol"));
    let hold_us = env_usize("AXIOM_UPDATE_COST_HOLD_US");
    assert!(
        [0, 10, 100, 500].contains(&hold_us),
        "unsupported hold duration"
    );
    let run = env_usize("AXIOM_UPDATE_COST_RUN");
    let attempts = env_usize("AXIOM_UPDATE_COST_ATTEMPTS");
    let warmup_count = env_usize("AXIOM_UPDATE_COST_WARMUP");
    let dispatch_cpu = env_usize("AXIOM_UPDATE_COST_DISPATCH_CPU");
    let update_cpu = env_usize("AXIOM_UPDATE_COST_UPDATE_CPU");
    assert_ne!(
        dispatch_cpu, update_cpu,
        "measurement threads require distinct CPUs"
    );
    let (dispatch_package, dispatch_core) = cpu_topology(dispatch_cpu);
    let (update_package, update_core) = cpu_topology(update_cpu);
    assert_ne!(
        (dispatch_package, dispatch_core),
        (update_package, update_core),
        "measurement threads require distinct physical cores"
    );
    let dispatch_governor = cpu_governor(dispatch_cpu);
    let update_governor = cpu_governor(update_cpu);
    let (load1_milli, load5_milli, load15_milli) = load_milli();
    pin_current_thread(update_cpu);

    let mut clock_samples = Vec::with_capacity(CLOCK_SAMPLES);
    for _ in 0..CLOCK_SAMPLES {
        let start = raw_ns();
        let end = raw_ns();
        clock_samples.push(end - start);
    }

    let owner = 7;
    let mut manager = BpfManager::new();
    let a = manager
        .load_raw_program_for(owner, program(11))
        .expect("load A failed");
    let one_program = manager.resource_usage();
    let b = manager
        .load_raw_program_for(owner, program(22))
        .expect("load B failed");
    let two_loaded = manager.resource_usage();
    let mut installed = install(&mut manager, protocol, owner, a)
        .expect("initial publication failed")
        .installed;
    installed = warmup(&mut manager, protocol, owner, a, b, warmup_count, installed);
    let mut last_receipt = manager
        .last_install_receipt()
        .expect("warmup did not retain its receipt");
    assert_eq!(last_receipt.installed, installed);
    let committed_before = manager.committed_total_ns_per_s();

    let skips_before = manager.exclusive_slot_skips();
    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Barrier::new(2));
    let start_ns = raw_ns() + START_DELAY_NS;
    let dispatch_stop = stop.clone();
    let dispatch_ready = ready.clone();
    let dispatch_capacity = attempts.saturating_mul(4).saturating_add(1024);
    let mut update_samples = Vec::with_capacity(attempts);
    let dispatcher = thread::spawn(move || {
        dispatch_loop(
            protocol,
            (hold_us as u64) * 1_000,
            dispatch_cpu,
            start_ns,
            dispatch_stop,
            dispatch_ready,
            a,
            b,
            dispatch_capacity,
        )
    });
    ready.wait();

    let mut logical_update = 0;
    let mut retry_ordinal = 1;
    for attempt in 0..attempts {
        let scheduled_at = scheduled_ns(start_ns, attempt as u64, run as u64);
        let started = wait_until(scheduled_at);
        let candidate = alternate(installed.program, a, b);
        let previous = installed;
        let outcome = replace(&mut manager, protocol, owner, previous, candidate);
        let end = raw_ns();
        let (name, succeeded) = match outcome {
            Ok(receipt) => {
                assert_eq!(receipt.previous, Some(previous));
                assert_eq!(receipt.installed.program, candidate);
                assert_eq!(receipt.installed.epoch, previous.epoch + 1);
                installed = receipt.installed;
                last_receipt = receipt;
                ("Ok", true)
            }
            Err(InstallError::Busy) if protocol == Protocol::Guarded => ("Busy", false),
            Err(error) => panic!("unexpected replacement result: {error:?}"),
        };
        update_samples.push(UpdateSample {
            attempt,
            logical_update,
            retry_ordinal,
            outcome: name,
            latency_ns: end - started,
            scheduled_offset_ns: scheduled_at - start_ns,
            started_offset_ns: started - start_ns,
            lateness_ns: started - scheduled_at,
        });
        if succeeded {
            logical_update += 1;
            retry_ordinal = 1;
        } else {
            retry_ordinal += 1;
        }
    }
    stop.store(true, Ordering::Release);
    let dispatch = dispatcher.join().expect("dispatcher panicked");
    let skips_after = manager.exclusive_slot_skips();
    let controlled = if protocol == Protocol::Guarded {
        controlled_transition_samples(dispatch_cpu)
    } else {
        Vec::new()
    };
    let after_replace = manager.resource_usage();
    assert_eq!(manager.exclusive_timer_identity(), Some(installed));
    assert_eq!(manager.last_install_receipt(), Some(last_receipt));
    assert_eq!(manager.committed_total_ns_per_s(), committed_before);
    assert_eq!(
        two_loaded, after_replace,
        "replacement changed manager-accounted resident bytecode bytes"
    );
    manager
        .clear_exclusive_for_diagnostics(owner, installed)
        .expect("measurement cleanup failed");
    assert_eq!(manager.committed_total_ns_per_s(), 0);
    manager
        .unload_program_for(owner, a)
        .expect("unload A failed");
    manager
        .unload_program_for(owner, b)
        .expect("unload B failed");
    let after_cleanup = manager.resource_usage();
    assert_eq!(after_cleanup.live_programs, 0);
    assert_eq!(after_cleanup.program_bytes, 0);

    println!(
        "{},\"attempts\":{},\"warmup\":{},\"period_ns\":{},\"clock_resolution_ns\":{},\"dispatch_cpu\":{},\"update_cpu\":{},\"dispatch_package\":{},\"dispatch_core\":{},\"update_package\":{},\"update_core\":{},\"dispatch_governor\":\"{}\",\"update_governor\":\"{}\",\"load1_milli\":{},\"load5_milli\":{},\"load15_milli\":{},\"resource_label\":\"manager-accounted resident bytecode bytes\"}}",
        prefix(protocol, hold_us, run, "meta"),
        attempts,
        warmup_count,
        PERIOD_NS,
        clock_resolution_ns(),
        dispatch_cpu,
        update_cpu,
        dispatch_package,
        dispatch_core,
        update_package,
        update_core,
        dispatch_governor,
        update_governor,
        load1_milli,
        load5_milli,
        load15_milli,
    );
    for latency in clock_samples {
        println!(
            "{},\"latency_ns\":{}}}",
            prefix(protocol, hold_us, run, "clock"),
            latency
        );
    }
    emit_resource(protocol, hold_us, run, "one_program", one_program);
    emit_resource(protocol, hold_us, run, "two_loaded", two_loaded);
    for sample in update_samples {
        println!(
            "{},\"attempt\":{},\"logical_update\":{},\"retry_ordinal\":{},\"outcome\":\"{}\",\"latency_ns\":{},\"scheduled_offset_ns\":{},\"started_offset_ns\":{},\"lateness_ns\":{}}}",
            prefix(protocol, hold_us, run, "update"),
            sample.attempt,
            sample.logical_update,
            sample.retry_ordinal,
            sample.outcome,
            sample.latency_ns,
            sample.scheduled_offset_ns,
            sample.started_offset_ns,
            sample.lateness_ns,
        );
    }
    for sample in dispatch.samples {
        println!(
            "{},\"scheduled\":{},\"outcome\":\"{}\",\"call_ns\":{},\"entry_ns\":{},\"release_ns\":{},\"lateness_ns\":{},\"actual_hold_ns\":{}}}",
            prefix(protocol, hold_us, run, "dispatch"),
            sample.scheduled,
            sample.outcome,
            sample.call_ns,
            json_optional(sample.entry_ns),
            json_optional(sample.release_ns),
            sample.lateness_ns,
            json_optional(sample.actual_hold_ns),
        );
    }
    for latency in controlled {
        println!(
            "{},\"latency_ns\":{}}}",
            prefix(protocol, hold_us, run, "controlled_transition"),
            latency,
        );
    }
    emit_resource(protocol, hold_us, run, "after_replace", after_replace);
    emit_resource(protocol, hold_us, run, "after_cleanup", after_cleanup);
    println!(
        "{},\"scheduled_releases\":{},\"dispatch_attempts\":{},\"missed_releases\":{},\"transition_busy_skips\":{},\"execution_busy_skips\":{},\"empty_skips\":{}}}",
        prefix(protocol, hold_us, run, "end"),
        dispatch.scheduled_releases,
        dispatch.scheduled_releases - dispatch.missed_releases,
        dispatch.missed_releases,
        skips_after
            .transition_busy
            .saturating_sub(skips_before.transition_busy),
        skips_after
            .execution_busy
            .saturating_sub(skips_before.execution_busy),
        skips_after.empty.saturating_sub(skips_before.empty),
    );
}
