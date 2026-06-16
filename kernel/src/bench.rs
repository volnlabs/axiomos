//! v0.3 hardware-bench (Task 11) instrumentation.
//!
//! Compiled only under the `bench` feature, so production builds are unaffected.
//! Provides three things the on-Pi5 bench needs:
//!   1. On-chip latency timestamps (ARM `CNTVCT_EL0`) reported to the serial log,
//!      so the M-A/M-B/M-C numbers can be read without a logic analyzer.
//!   2. The physical e-stop button IRQ path (`handle_estop_button`).
//!   3. The auto-loaded GPIO reflex (`init`): a verified BPF program that stops a
//!      PWM channel on a sensor edge, attached at boot.
//!
//! Pin assignments (BCM/GPIO numbering, i.e. the numbers the kernel uses):
//!   - GPIO23 = sensor trigger (reflex fires on its rising edge)
//!   - GPIO24 = e-stop button (external 10k pull-up to 3V3; press pulls to GND)
//!   - PWM0 channel 1 = motor-A speed/enable (driver enable pin)

use core::sync::atomic::{AtomicU64, Ordering};

/// Sensor pin: the reflex fires on this pin's rising edge.
pub const REFLEX_SENSOR_PIN: u8 = 23;
/// E-stop button pin (external pull-up; press pulls to GND -> falling edge).
pub const ESTOP_BUTTON_PIN: u8 = 24;
/// PWM controller the reflex and demo drive (PWM0).
pub const BENCH_PWM_CHIP: u32 = 0;
/// PWM channel the reflex and demo drive (channel 1).
pub const BENCH_PWM_CHANNEL: u32 = 1;

/// Cycle stamp captured at GPIO IRQ entry; read at the actuation apply point to
/// compute edge->actuate latency (M-C). 0 means "no GPIO IRQ in flight".
static GPIO_IRQ_ENTRY: AtomicU64 = AtomicU64::new(0);

/// Read the ARM virtual counter (`CNTVCT_EL0`) — a cheap, always-available
/// on-chip timestamp. Returns 0 off AArch64.
#[inline]
pub fn now_cycles() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let c: u64;
        // SAFETY: reading the virtual counter is permitted at EL1.
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) c) };
        c
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

#[inline]
fn counter_freq() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let f: u64;
        // SAFETY: reading the counter frequency is permitted at EL1.
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f) };
        f
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        1
    }
}

/// Convert a counter delta to nanoseconds without intermediate overflow.
#[inline]
pub fn cycles_to_ns(delta: u64) -> u64 {
    let f = counter_freq();
    if f == 0 {
        return 0;
    }
    let secs = delta / f;
    let rem = delta % f;
    secs * 1_000_000_000 + (rem * 1_000_000_000) / f
}

/// Stamp the counter at GPIO interrupt entry (start point for M-C).
#[inline]
pub fn mark_gpio_irq_entry() {
    GPIO_IRQ_ENTRY.store(now_cycles(), Ordering::Relaxed);
}

/// Report monitor decision overhead (M-A). Logged on every guarded actuation.
#[inline]
pub fn report_monitor_overhead(decide_cycles: u64) {
    log::info!(
        "[bench] M-A monitor_overhead_ns={}",
        cycles_to_ns(decide_cycles)
    );
}

/// Report edge->actuate latency for the GPIO IRQ currently in flight (M-C).
/// No-op outside a GPIO IRQ (when no entry stamp is set); consumes the stamp so
/// a later non-IRQ actuation cannot reuse it.
pub fn report_edge_to_actuate(kind: &str, channel: u8, value: u32) {
    let start = GPIO_IRQ_ENTRY.swap(0, Ordering::Relaxed);
    if start == 0 {
        return;
    }
    let ns = cycles_to_ns(now_cycles().wrapping_sub(start));
    log::info!(
        "[bench] M-C edge->{}-apply ch={} val={} latency_ns={}",
        kind,
        channel,
        value,
        ns
    );
}

/// Handle the physical e-stop button edge (M-B), called from the GPIO IRQ
/// handler. Falling edge (2) = pressed = operator trigger; rising edge (1) =
/// released = operator release. Routes through the kernel-owned e-stop, the same
/// path as `sys_estop`.
pub fn handle_estop_button(edge: u32) {
    use kernel_bpf::actuation::EstopAction;
    match edge {
        2 => {
            let detect = now_cycles();
            crate::actuation::operator_estop(EstopAction::Trigger);
            let ns = cycles_to_ns(now_cycles().wrapping_sub(detect));
            log::info!("[bench] M-B estop button->safe latency_ns={}", ns);
        }
        1 => {
            crate::actuation::operator_estop(EstopAction::Release);
        }
        _ => {}
    }
}

/// Boot-time bench setup (Pi 5 only): arm the sensor + button pin IRQs and
/// auto-load the reflex program attached to the sensor's rising edge.
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
pub fn init() {
    use kernel_bpf::attach::GpioEdge;

    use crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio;
    use crate::bpf::ATTACH_TYPE_GPIO;

    // SAFETY: the kernel owns the RP1 GPIO block; this runs once at boot.
    let gpio = unsafe { Rp1Gpio::new() };
    gpio.configure_input(REFLEX_SENSOR_PIN);
    gpio.configure_input(ESTOP_BUTTON_PIN);
    // Sensor: rising edge only. Button: both edges (press + release).
    gpio.enable_interrupt(REFLEX_SENSOR_PIN, true, false);
    gpio.enable_interrupt(ESTOP_BUTTON_PIN, true, true);

    // Build + load + attach the reflex (stop PWM0/ch1 on the sensor edge).
    let insns = kernel_bpf::bench::reflex_pwm_program(BENCH_PWM_CHIP, BENCH_PWM_CHANNEL, 0);
    let Some(manager) = crate::BPF_MANAGER.get() else {
        log::error!("[bench] BPF manager not initialized; reflex not loaded");
        return;
    };
    let mut mgr = manager.lock();
    match mgr.load_raw_program(insns) {
        Ok(prog_id) => {
            if let Err(e) = mgr.attach(ATTACH_TYPE_GPIO, prog_id) {
                log::error!("[bench] reflex attach failed: {:?}", e);
                return;
            }
            mgr.register_gpio_route(0, REFLEX_SENSOR_PIN, GpioEdge::Rising, prog_id);
            log::info!(
                "[bench] reflex loaded id={} -> (gpiochip0, pin {}, rising) stops PWM{} ch{}",
                prog_id,
                REFLEX_SENSOR_PIN,
                BENCH_PWM_CHIP,
                BENCH_PWM_CHANNEL
            );
        }
        Err(e) => log::error!("[bench] reflex load rejected: {:?}", e),
    }
}

/// Boot-time bench setup is a no-op off the Pi 5 platform.
#[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
pub fn init() {}
