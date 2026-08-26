//! The kernel-side actuation seam. Every normal actuation-magnitude path routes
//! through here: a request is decided by the global ARM-A monitor, then the
//! decision is applied to RP1 MMIO. The decision logic lives in
//! `kernel_bpf::actuation` (pure, host-tested); this file only owns the global
//! monitor and the MMIO application.

use core::sync::atomic::{AtomicU64, Ordering};

use kernel_bpf::actuation::{
    ActuationKind, ActuationRequest, AuditSource, Authority, ChannelId, EstopAction,
    EstopCommandResult, Monitor, ReleaseResult, SafeDrive,
};
use kernel_bpf::profile::ActiveProfile;
use spin::Mutex;

/// The single global actuation reference monitor.
pub static ACTUATION_MONITOR: Mutex<Monitor<ActiveProfile>> = Mutex::new(Monitor::new());
static APPLY_LOCK: Mutex<()> = Mutex::new(());
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
fn with_apply_lock<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::Aarch64;
        use crate::arch::traits::Architecture;
        let were_enabled = Aarch64::are_interrupts_enabled();
        if were_enabled {
            Aarch64::disable_interrupts();
        }
        let r = {
            let _apply = APPLY_LOCK.lock();
            f()
        };
        if were_enabled {
            Aarch64::enable_interrupts();
        }
        r
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _apply = APPLY_LOCK.lock();
        f()
    }
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

/// Apply a monitor-clamped PWM `value`: link-owned motor channels go over the
/// Shrike UART (the RP2040 drives the motor); all other channels drive local
/// RP1 PWM. Returns the (possibly overridden) result code. Fail-closed: a
/// link-mapped channel that is dead or whose setpoint can't be enqueued is
/// REFUSED (-1) and never driven locally — the RP2040 watchdog fails it safe.
#[allow(unused_variables)]
fn apply_pwm_routed(chip: u8, channel: u8, value: u32, sign: i32, code: i64) -> (bool, i64) {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "bench"))]
    if crate::bench::is_bench_pwm_output(chip, channel) {
        // Task 11 measures the RP1 PWM edge directly, not the Shrike UART path.
        apply_pwm_value(chip, channel, value);
        return (true, code);
    }

    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        use crate::arch::aarch64::platform::rpi5::control_link;
        if let Some(side) = control_link::motor_side(chip, channel) {
            // Link owns this motor — never drive local PWM for it.
            let signed_value = if sign < 0 {
                -(value.min(i32::MAX as u32) as i32)
            } else {
                value.min(i32::MAX as u32) as i32
            };
            if !control_link::link_alive() || !control_link::send_motor(side, signed_value) {
                return (false, -1); // dead link or TX full: refuse (peer fails safe)
            }
            return (true, code);
        }
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
    with_apply_lock(|| {
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
    sign: i32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    with_apply_lock(|| {
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
        crate::bench::report_monitor_overhead(crate::bench::now_cycles().wrapping_sub(bench_t0));

        let (applied, code) = apply_pwm_routed(chip, channel, value, sign, code);
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
            crate::bench::report_edge_to_actuate("pwm", channel, value);
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
    guard_pwm_value_with(chip, channel, duty, 1, authority, source)
}

/// Route a signed motor setpoint through the same monitor magnitude guard as
/// PWM, retaining its sign only at the shared link actuation route.
pub fn guard_motor_with(
    chip: u8,
    channel: u8,
    setpoint: i32,
    authority: Authority,
    source: AuditSource,
) -> i64 {
    guard_pwm_value_with(
        chip,
        channel,
        setpoint.unsigned_abs(),
        if setpoint < 0 { -1 } else { 1 },
        authority,
        source,
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
    with_apply_lock(|| {
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
        crate::bench::report_monitor_overhead(crate::bench::now_cycles().wrapping_sub(bench_t0));

        apply_gpio_value(pin, value);
        #[cfg(feature = "bench")]
        crate::bench::report_edge_to_actuate("gpio", pin, value);

        code
    })
}

pub fn trigger_estop(source: AuditSource) -> i64 {
    with_apply_lock(|| {
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let transition = !monitor.is_latched();
        let drives = monitor.estop_trigger(source, now);
        drop(monitor);
        for drive in drives.iter() {
            apply_safe_drive(drive);
        }
        if transition && matches!(source, AuditSource::Operator | AuditSource::Watchdog) {
            crate::serial_println!(
                "V04_ESTOP event_id={} source={} stage=assert ts_ns={}",
                next_v04_estop_event_id(),
                match source {
                    AuditSource::Operator => "operator",
                    AuditSource::Watchdog => "watchdog",
                    _ => unreachable!(),
                },
                now
            );
        }
        notify_link_estop(true);
        0
    })
}

pub fn operator_estop(action: EstopAction) -> i64 {
    with_apply_lock(|| {
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let was_latched = monitor.is_latched();
        let result = monitor.operator_estop(action, now);
        drop(monitor);
        match result {
            EstopCommandResult::Triggered(drives) => {
                for drive in drives.iter() {
                    apply_safe_drive(drive);
                }
                if !was_latched {
                    crate::serial_println!(
                        "V04_ESTOP event_id={} source=operator stage=assert ts_ns={}",
                        next_v04_estop_event_id(),
                        now
                    );
                }
                notify_link_estop(true);
                0
            }
            EstopCommandResult::Released => {
                if was_latched {
                    crate::serial_println!(
                        "V04_ESTOP event_id={} source=operator stage=release ts_ns={}",
                        next_v04_estop_event_id(),
                        now
                    );
                }
                notify_link_estop(false);
                0
            }
            EstopCommandResult::Denied => -1,
        }
    })
}

pub fn watchdog_estop_trigger() -> i64 {
    with_apply_lock(|| {
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let transition = !monitor.is_latched();
        let drives = monitor.watchdog_estop_trigger(now);
        drop(monitor);
        for drive in drives.iter() {
            apply_safe_drive(drive);
        }
        if transition {
            crate::serial_println!(
                "V04_ESTOP event_id={} source=watchdog stage=assert ts_ns={}",
                next_v04_estop_event_id(),
                now
            );
        }
        notify_link_estop(true);
        0
    })
}

pub fn release_estop(authority: Authority, source: AuditSource) -> i64 {
    with_apply_lock(|| {
        let now = crate::time::get_kernel_time_ns();
        let mut monitor = ACTUATION_MONITOR.lock();
        let was_latched = monitor.is_latched();
        let result = monitor.estop_release(authority, source, now);
        drop(monitor);
        match result {
            ReleaseResult::Released => {
                if was_latched {
                    crate::serial_println!(
                        "V04_ESTOP event_id={} source=operator stage=release ts_ns={}",
                        next_v04_estop_event_id(),
                        now
                    );
                }
                notify_link_estop(false);
                0
            }
            ReleaseResult::Denied => -1,
        }
    })
}
