//! The kernel-side actuation seam. Every normal actuation-magnitude path routes
//! through here: a request is decided by the global ARM-A monitor, then the
//! decision is applied to RP1 MMIO or queued as one complete motor pair. The
//! decision logic lives in `kernel_bpf::actuation` (pure, host-tested); this file
//! owns the global monitor, managed wheel ownership and local application.

#[cfg(not(feature = "managed-runtime"))]
use core::sync::atomic::{AtomicU64, Ordering};

use kernel_bpf::actuation::{
    ActuationKind, ActuationRequest, AuditSource, Authority, ChannelId, EstopAction,
    EstopCommandResult, Monitor, MotorPairDecision, ReleaseResult, SafeDrive,
};
use kernel_bpf::execution::ManagedMotorPair;
use kernel_bpf::profile::ActiveProfile;
use spin::Mutex;

/// The single global actuation reference monitor.
pub static ACTUATION_MONITOR: Mutex<Monitor<ActiveProfile>> = Mutex::new(Monitor::new());
// The one managed wheel owner shares the existing decision/application lock.
static APPLY_LOCK: Mutex<bool> = Mutex::new(false);
#[cfg(not(feature = "managed-runtime"))]
static NEXT_V04_ESTOP_EVENT: AtomicU64 = AtomicU64::new(1);

/// Whether the reviewed PWM channel is owned by the signed motor link.
#[inline]
pub fn is_motor_channel(chip: u8, channel: u8) -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        return crate::arch::aarch64::platform::rpi5::control_link::motor_side(chip, channel)
            .is_some();
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    {
        let _ = (chip, channel);
        false
    }
}

#[cfg(not(feature = "managed-runtime"))]
pub(crate) fn next_v04_estop_event_id() -> u64 {
    NEXT_V04_ESTOP_EVENT.fetch_add(1, Ordering::Relaxed)
}

/// Run `f` holding APPLY_LOCK with IRQs masked. APPLY_LOCK is reached from BOTH
/// thread context (syscalls, the control-link poller) AND IRQ context (a BPF
/// hook firing in the timer/GPIO IRQ can call `bpf_pwm_write` -> `guard_pwm`).
/// A spin lock shared across those contexts livelocks if an IRQ preempts a
/// thread mid-hold, so every acquisition masks IRQs first. On aarch64 the
/// `are_interrupts_enabled` check makes this correct whether the caller is
/// already in (masked) IRQ context or in thread context.
fn with_apply_lock<R>(f: impl FnOnce(&mut bool) -> R) -> R {
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::Aarch64;
        use crate::arch::traits::Architecture;
        let were_enabled = Aarch64::are_interrupts_enabled();
        if were_enabled {
            Aarch64::disable_interrupts();
        }
        let r = {
            let mut managed_owned = APPLY_LOCK.lock();
            f(&mut managed_owned)
        };
        if were_enabled {
            Aarch64::enable_interrupts();
        }
        r
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut managed_owned = APPLY_LOCK.lock();
        f(&mut managed_owned)
    }
}

/// The qualified slot retains ownership while inhibited and releases it only
/// after safe deactivation. Changing this flag does not stop or release e-stop.
pub(crate) fn set_managed_motor_pair_owner(owned: bool) {
    with_apply_lock(|managed_owned| *managed_owned = owned);
}

pub(crate) fn managed_motor_pair_owned() -> bool {
    with_apply_lock(|managed_owned| *managed_owned)
}

fn apply_pwm_value(chip: u8, channel: u8, value: u32) {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        use crate::arch::aarch64::platform::rpi5::pwm::{PWM0, PWM1};
        if (1..=2).contains(&channel) {
            match chip {
                0 => PWM0.lock().set_duty_cycle(channel, value),
                1 => PWM1.lock().set_duty_cycle(channel, value),
                _ => {}
            }
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = (chip, channel, value);
}

/// Apply a monitor-clamped local PWM value. Link-owned motor channels are
/// rejected before this point and use `guard_motor_pair_with` exclusively.
#[allow(unused_variables)]
fn apply_pwm_routed(chip: u8, channel: u8, value: u32, code: i64) -> (bool, i64) {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "bench"))]
    if crate::bench::is_bench_pwm_output(chip, channel) {
        // Task 11 measures the RP1 PWM edge directly, not the Shrike UART path.
        apply_pwm_value(chip, channel, value);
        return (true, code);
    }

    apply_pwm_value(chip, channel, value);
    (true, code)
}

fn apply_gpio_value(pin: u8, value: u32) {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        if pin < crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::NUM_PINS {
            // SAFETY: validated pin; kernel has exclusive GPIO access.
            let gpio = unsafe { crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::new() };
            if value != 0 {
                gpio.set_high(pin);
            } else {
                gpio.set_low(pin);
            }
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = (pin, value);
}

/// Measure identical direct-MMIO and monitor+MMIO safe-low writes for the
/// feature-gated, physically disconnected V03-A bench image.
#[cfg(all(feature = "bench", feature = "bench-paired-overhead"))]
pub(crate) fn bench_measure_gpio_pair() -> (u64, u64) {
    with_apply_lock(|_| {
        let pin = crate::bench::BENCH_PWM_PIN;
        let level = 0; // Direct bypass is permanently restricted to safe-low.
        let baseline_start = crate::bench::now_cycles();
        apply_gpio_value(pin, level);
        let baseline_cycles = crate::bench::now_cycles().wrapping_sub(baseline_start);

        let monitor_start = crate::bench::now_cycles();
        let ch = ChannelId {
            kind: ActuationKind::GpioLevel,
            chip: 0,
            channel: pin,
        };
        let now = crate::time::get_kernel_time_ns();
        let (value, _) = ACTUATION_MONITOR
            .lock()
            .decide(
                ActuationRequest { ch, value: level },
                Authority::Learned,
                AuditSource::LearnedBehavior,
                now,
            )
            .apply();
        apply_gpio_value(pin, value);
        let monitor_cycles = crate::bench::now_cycles().wrapping_sub(monitor_start);
        (baseline_cycles, monitor_cycles)
    })
}

/// Push an e-stop command over the Shrike link so link-owned motors (driven by
/// the RP2040, not local PWM) mirror the ARM-A latch state. If the link TX ring
/// is full, the control-link poller retries before sending further setpoints.
fn notify_link_estop(assert: bool) {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        crate::arch::aarch64::platform::rpi5::control_link::command_estop(assert);
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = assert;
}

fn apply_safe_drive(drive: SafeDrive) {
    match drive.channel.kind {
        ActuationKind::PwmDuty => {
            apply_pwm_value(drive.channel.chip, drive.channel.channel, drive.safe_value)
        }
        ActuationKind::GpioLevel => apply_gpio_value(drive.channel.channel, drive.safe_value),
    }
}

/// Route a PWM-duty request through ARM-A and apply the result to RP1 MMIO.
/// Returns 0 when motion proceeds (Allow/Clamp), -1 when policy intervened or
/// the request was invalid (Safe/Reject). The only *monitored* writer of PWM duty.
fn guard_pwm_value_with(
    chip: u8,
    channel: u8,
    duty: u32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    with_apply_lock(|_| {
        let ch = ChannelId {
            kind: ActuationKind::PwmDuty,
            chip,
            channel,
        };
        let now = crate::time::get_kernel_time_ns();
        #[cfg(feature = "bench")]
        let bench_t0 = crate::bench::now_cycles();
        let (before, after, value, code) = {
            let mut monitor = ACTUATION_MONITOR.lock();
            let before = monitor.snapshot_channel_state(ch);
            let (value, code) = monitor
                .decide(ActuationRequest { ch, value: duty }, authority, source, now)
                .apply();
            let after = monitor.snapshot_channel_state(ch);
            (before, after, value, code)
        };
        #[cfg(feature = "bench")]
        let monitor_cycles = crate::bench::now_cycles().wrapping_sub(bench_t0);

        let (applied, code) = apply_pwm_routed(chip, channel, value, code);
        #[cfg(feature = "bench")]
        let applied_at = crate::bench::now_cycles();
        if !applied {
            if let (Some(before), Some(after)) = (before, after) {
                let mut monitor = ACTUATION_MONITOR.lock();
                if monitor.snapshot_channel_state(ch) == Some(after) {
                    monitor.restore_channel_state(ch, before);
                }
            }
        }
        #[cfg(feature = "bench")]
        if applied {
            crate::bench::report_edge_to_actuate("pwm", channel, value, monitor_cycles, applied_at);
        }

        code
    })
}

pub fn guard_pwm_with(
    chip: u8,
    channel: u8,
    duty: u32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    if is_motor_channel(chip, channel) {
        return -1;
    }
    guard_pwm_value_with(chip, channel, duty, authority, source)
}

/// Legacy per-wheel motor entry point. Complete motor pairs are required, so
/// every request through this stale sibling-wheel API is refused.
pub fn guard_motor_with(
    chip: u8,
    channel: u8,
    setpoint: i32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    let _ = (chip, channel, setpoint, authority, source);
    -1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MotorPairSubmissionOutcome {
    Queued,
    OwnershipRejected,
    DeadlineExpired,
    ClockReversed,
    QueueFailed,
}

/// Policy decision and local queue outcome; never a peer/physical acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MotorPairSubmission {
    pub decision: Option<MotorPairDecision>,
    pub outcome: MotorPairSubmissionOutcome,
}

#[derive(Clone, Copy)]
enum MotorPairCaller {
    Ordinary(Authority, AuditSource),
    Managed {
        not_before_ticks: u64,
        deadline_ticks: u64,
    },
}

/// Caller holds APPLY_LOCK. Keep the monitor unlocked across the queue callback
/// so the existing APPLY_LOCK -> monitor, then link lock order is unchanged.
fn decide_and_queue_motor_pair(
    monitor: &Mutex<Monitor<ActiveProfile>>,
    managed_owned: bool,
    requested: (i32, i32),
    caller: MotorPairCaller,
    read_ns: impl FnOnce() -> u64,
    mut read_ticks: impl FnMut() -> u64,
    enqueue: impl FnOnce(MotorPairDecision) -> bool,
) -> MotorPairSubmission {
    use MotorPairSubmissionOutcome::*;
    let mut result = MotorPairSubmission {
        decision: None,
        outcome: OwnershipRejected,
    };
    let managed = matches!(caller, MotorPairCaller::Managed { .. });
    if managed_owned != managed {
        return result;
    }
    let (authority, source, tick_bounds) = match caller {
        MotorPairCaller::Ordinary(authority, source) => (authority, source, None),
        MotorPairCaller::Managed {
            not_before_ticks,
            deadline_ticks,
        } => (
            Authority::Learned,
            AuditSource::ManagedControl,
            Some((not_before_ticks, deadline_ticks)),
        ),
    };
    let now_ns = read_ns();
    let (before, decision, started) = {
        let mut monitor = monitor.lock();
        let started = tick_bounds.map(|_| read_ticks());
        if let Some((now, (not_before, end))) = started.zip(tick_bounds) {
            if now < not_before || now >= end {
                result.outcome = if now < not_before {
                    ClockReversed
                } else {
                    DeadlineExpired
                };
                return result;
            }
        }
        let before = monitor.snapshot_motor_pair_state();
        let decision =
            monitor.decide_motor_pair(requested.0, requested.1, authority, source, now_ns);
        (before, decision, started)
    };
    result.decision = Some(decision);
    if let Some((started, (_, deadline))) = started.zip(tick_bounds) {
        let now = read_ticks();
        if now < started || now >= deadline {
            monitor.lock().restore_motor_pair_state(before);
            result.outcome = if now < started {
                ClockReversed
            } else {
                DeadlineExpired
            };
            return result;
        }
    }
    if !enqueue(decision) {
        // Preserve legacy Safe semantics, but a failed managed submission must
        // never consume pair slew credit or claim a queued safe pair.
        if managed || !matches!(decision, MotorPairDecision::Safe { .. }) {
            monitor.lock().restore_motor_pair_state(before);
        }
        result.outcome = QueueFailed;
        return result;
    }
    result.outcome = Queued;
    result
}

fn queue_motor_pair(
    decision: MotorPairDecision,
    origin: Option<shrike_link::tx::MotorOrigin>,
) -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        use crate::arch::aarch64::platform::rpi5::control_link;
        match decision {
            MotorPairDecision::Safe { .. } => {
                control_link::send_safe_motor_pair_with_origin(origin)
            }
            MotorPairDecision::Allow { left, right } | MotorPairDecision::Clamp { left, right } => {
                control_link::send_motor_pair_with_origin(left, right, origin)
            }
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    {
        let _ = (decision, origin);
        false
    }
}

/// Only the qualified managed slot calls this entry. Physical deadline ticks
/// and the monitor's compatibility timestamp `now_ns` are separate domains.
/// `not_before_ticks` is the caller's checked post-interpreter sample.
/// A failed submission requires the caller's independent stop path.
pub(crate) fn submit_managed_motor_pair(
    pair: ManagedMotorPair,
    origin: Option<shrike_link::tx::MotorOrigin>,
    now_ns: u64,
    not_before_ticks: u64,
    deadline_ticks: u64,
    read_ticks: impl FnMut() -> u64,
) -> MotorPairSubmission {
    let Some(origin) = origin else {
        return MotorPairSubmission {
            decision: None,
            outcome: MotorPairSubmissionOutcome::OwnershipRejected,
        };
    };
    with_apply_lock(|managed_owned| {
        decide_and_queue_motor_pair(
            &ACTUATION_MONITOR,
            *managed_owned,
            (i32::from(pair.left), i32::from(pair.right)),
            MotorPairCaller::Managed {
                not_before_ticks,
                deadline_ticks,
            },
            || now_ns,
            read_ticks,
            |decision| queue_motor_pair(decision, Some(origin)),
        )
    })
}

/// Decide and queue one complete signed rover command. A zero return means the
/// monitor allowed/clamped and the complete pair was queued, not FPGA-applied.
pub fn guard_motor_pair_with(
    left_permille: i32,
    right_permille: i32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    let result = with_apply_lock(|managed_owned| {
        decide_and_queue_motor_pair(
            &ACTUATION_MONITOR,
            *managed_owned,
            (left_permille, right_permille),
            MotorPairCaller::Ordinary(authority, source),
            crate::time::get_kernel_time_ns,
            || 0,
            |decision| {
                #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
                {
                    queue_motor_pair(decision, None)
                }
                #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
                {
                    let _ = decision;
                    true
                }
            },
        )
    });
    if result.outcome != MotorPairSubmissionOutcome::Queued {
        return -1;
    }
    let (left, right, code) = result.decision.expect("queued pair has a decision").apply();
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    crate::arch::aarch64::platform::rpi5::control_link::report_motor_queued(left, right);
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = (left, right);
    code
}

pub fn guard_motor_pair(left_permille: i32, right_permille: i32) -> i64 {
    guard_motor_pair_with(
        left_permille,
        right_permille,
        Authority::Learned,
        AuditSource::LearnedBehavior,
    )
}

pub fn guard_motor(chip: u8, channel: u8, setpoint: i32) -> i64 {
    guard_motor_with(
        chip,
        channel,
        setpoint,
        Authority::Learned,
        AuditSource::LearnedBehavior,
    )
}

pub fn guard_pwm(chip: u8, channel: u8, duty: u32) -> i64 {
    guard_pwm_with(
        chip,
        channel,
        duty,
        Authority::Learned,
        AuditSource::LearnedBehavior,
    )
}

/// Route a GPIO output-level request through ARM-A and apply it. The only
/// *monitored* writer of GPIO output level.
pub fn guard_gpio(pin: u8, level: u32) -> i64 {
    guard_gpio_with(pin, level, Authority::Learned, AuditSource::LearnedBehavior)
}

pub fn guard_gpio_with(pin: u8, level: u32, authority: Authority, source: AuditSource) -> i64 {
    with_apply_lock(|_| {
        let ch = ChannelId {
            kind: ActuationKind::GpioLevel,
            chip: 0,
            channel: pin,
        };
        let now = crate::time::get_kernel_time_ns();
        #[cfg(feature = "bench")]
        let bench_t0 = crate::bench::now_cycles();
        let (value, code) = ACTUATION_MONITOR
            .lock()
            .decide(
                ActuationRequest { ch, value: level },
                authority,
                source,
                now,
            )
            .apply();
        #[cfg(feature = "bench")]
        let monitor_cycles = crate::bench::now_cycles().wrapping_sub(bench_t0);

        apply_gpio_value(pin, value);
        #[cfg(feature = "bench")]
        {
            let applied_at = crate::bench::now_cycles();
            crate::bench::report_edge_to_actuate("gpio", pin, value, monitor_cycles, applied_at);
        }

        code
    })
}

pub fn trigger_estop(source: AuditSource) -> i64 {
    trigger_estop_with_clock(source, crate::time::get_kernel_time_ns)
}

fn trigger_estop_with_clock(source: AuditSource, read_ns: impl FnOnce() -> u64) -> i64 {
    let (_transition, _now) = with_apply_lock(|_| {
        crate::bpf::installation::request_stop();
        let now = read_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let transition = !monitor.is_latched();
        let drives = monitor.estop_trigger(source, now);
        drop(monitor);
        for drive in drives.iter() {
            apply_safe_drive(drive);
        }
        notify_link_estop(true);
        crate::bpf::recorder::events::trusted_stop(source);
        (transition, now)
    });
    #[cfg(not(feature = "managed-runtime"))]
    if _transition && matches!(source, AuditSource::Operator | AuditSource::Watchdog) {
        crate::serial_println!(
            "V04_ESTOP event_id={} source={} stage=assert ts_ns={}",
            next_v04_estop_event_id(),
            match source {
                AuditSource::Operator => "operator",
                AuditSource::Watchdog => "watchdog",
                _ => unreachable!(),
            },
            _now
        );
    }
    0
}

pub fn operator_estop(action: EstopAction) -> i64 {
    operator_estop_with_local_safe(action, || {})
}

/// Bench endpoint: local safe writes issued, before link notification or logs.
/// This is not an acknowledgement from an external MCU, FPGA or physical pad.
#[cfg(feature = "bench")]
pub(crate) fn operator_estop_timed(action: EstopAction) -> (i64, Option<u64>) {
    let mut applied_at = None;
    let code = operator_estop_with_local_safe(action, || {
        applied_at = Some(crate::bench::now_cycles());
    });
    (code, applied_at)
}

fn operator_estop_with_local_safe(action: EstopAction, local_safe: impl FnOnce()) -> i64 {
    let (code, _stage, _now) = with_apply_lock(|_| {
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let was_latched = monitor.is_latched();
        let result = monitor.operator_estop(action, now);
        drop(monitor);
        match result {
            EstopCommandResult::Triggered(drives) => {
                crate::bpf::installation::request_stop();
                for drive in drives.iter() {
                    apply_safe_drive(drive);
                }
                local_safe();
                notify_link_estop(true);
                crate::bpf::recorder::events::trusted_stop(AuditSource::Operator);
                (0, (!was_latched).then_some("assert"), now)
            }
            EstopCommandResult::Released => {
                notify_link_estop(false);
                if was_latched {
                    crate::bpf::recorder::events::released(AuditSource::Operator);
                }
                (0, was_latched.then_some("release"), now)
            }
            EstopCommandResult::Denied => (-1, None, now),
        }
    });
    #[cfg(not(feature = "managed-runtime"))]
    if let Some(stage) = _stage {
        crate::serial_println!(
            "V04_ESTOP event_id={} source=operator stage={} ts_ns={}",
            next_v04_estop_event_id(),
            stage,
            _now
        );
    }
    code
}

pub fn watchdog_estop_trigger() -> i64 {
    let (_transition, _now) = with_apply_lock(|_| {
        crate::bpf::installation::request_stop();
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let transition = !monitor.is_latched();
        let drives = monitor.watchdog_estop_trigger(now);
        drop(monitor);
        for drive in drives.iter() {
            apply_safe_drive(drive);
        }
        notify_link_estop(true);
        crate::bpf::recorder::events::trusted_stop(AuditSource::Watchdog);
        (transition, now)
    });
    #[cfg(not(feature = "managed-runtime"))]
    if _transition {
        crate::serial_println!(
            "V04_ESTOP event_id={} source=watchdog stage=assert ts_ns={}",
            next_v04_estop_event_id(),
            _now
        );
    }
    0
}

pub fn release_estop(authority: Authority, source: AuditSource) -> i64 {
    let (code, _log_release, _now) = with_apply_lock(|_| {
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let was_latched = monitor.is_latched();
        let result = monitor.estop_release(authority, source, now);
        drop(monitor);
        match result {
            ReleaseResult::Released => {
                notify_link_estop(false);
                if was_latched {
                    crate::bpf::recorder::events::released(source);
                }
                (0, was_latched, now)
            }
            ReleaseResult::Denied => (-1, false, now),
        }
    });
    #[cfg(not(feature = "managed-runtime"))]
    if _log_release {
        crate::serial_println!(
            "V04_ESTOP event_id={} source=operator stage=release ts_ns={}",
            next_v04_estop_event_id(),
            _now
        );
    }
    code
}

#[cfg(test)]
#[path = "actuation_tests.rs"]
mod tests;
