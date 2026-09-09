//! v0.3 hardware-bench (Task 11) instrumentation.
//!
//! Compiled only under the `bench` feature, so production builds are unaffected.
//! Provides three things the on-Pi5 bench needs:
//!   1. On-chip latency timestamps (ARM `CNTVCT_EL0`) reported to the serial log,
//!      so the M-A/M-B/M-C numbers can be read without a logic analyzer.
//!   2. The physical e-stop button IRQ path (`handle_estop_button`).
//!   3. The auto-loaded GPIO reflex (`init`): a verified BPF program that stops a
//!      local PWM channel on a sensor edge, attached at boot.
//!
//! Pin assignments (BCM/GPIO numbering, i.e. the numbers the kernel uses):
//!   - GPIO23 = sensor trigger (reflex fires on its rising edge)
//!   - GPIO24 = e-stop button (NC contact holds high; 10k pull-down makes an
//!     open/pressed/broken contact low)
//!   - GPIO12 = PWM0 channel 1 physical output to motor-A speed/enable
//!   - PWM0 channel 1 = motor-A speed/enable (driver enable pin)

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(all(
    feature = "bench-pwm",
    any(
        feature = "bench-reflex-rearm",
        feature = "bench-estop-rearm",
        feature = "bench-paired-overhead"
    )
))]
compile_error!("bench-pwm is a one-shot unloaded diagnostic; do not combine it with rearm or paired-overhead benches");

/// Sensor pin: the reflex fires on this pin's rising edge.
pub const REFLEX_SENSOR_PIN: u8 = 23;
/// E-stop button pin (NC-held-high; open/press/broken wire pulls low).
pub const ESTOP_BUTTON_PIN: u8 = 24;
/// Requested PWM carrier frequency. Measure the physical period separately.
pub const BENCH_PWM_FREQ_HZ: u32 = 10_000;
/// A visible carrier through the ordinary monitor envelope, not DC high.
pub const BENCH_PWM_DUTY_PERCENT: u32 = 50;
pub const BENCH_PWM_CHIP: u32 = 0;
/// PWM channel the reflex and demo drive, in the monitor's 1-based numbering.
/// Channel 1 maps to RP1 PWM0 hardware channel 0 = GPIO12 (Alt0).
pub const BENCH_PWM_CHANNEL: u32 = 1;
/// Header GPIO routed to PWM0 channel 1 for the v0.3 bench.
pub const BENCH_PWM_PIN: u8 = 12;

/// How the reflex drives its output pin (GPIO12) for the V03-B latency test.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReflexOutput {
    /// Plain GPIO output: armed high, driven low on the sensor edge. No PWM
    /// clock dependency; a clean single falling edge. Validates the rig.
    Gpio,
    /// Hardware PWM carrier on PWM0: armed to duty, driven to 0 on the edge.
    /// Faithful to the plan's "hardware-PWM actuation" claim.
    Pwm,
}

/// Selects the reflex output path for this build. Two experiments on one rig;
/// build one image per mode and report both latency numbers.
#[cfg(not(feature = "bench-pwm"))]
pub const BENCH_REFLEX_OUTPUT: ReflexOutput = ReflexOutput::Gpio;
#[cfg(feature = "bench-pwm")]
pub const BENCH_REFLEX_OUTPUT: ReflexOutput = ReflexOutput::Pwm;

/// True when an actuation targets the local PWM output reserved for Task 11.
#[inline]
pub fn is_bench_pwm_output(chip: u8, channel: u8) -> bool {
    u32::from(chip) == BENCH_PWM_CHIP && u32::from(channel) == BENCH_PWM_CHANNEL
}

/// Arm the bench reflex output through the monitor-owned actuation guards.
///
/// This is intentionally the same guarded path used for boot-time arming and
/// the opt-in unloaded-HIL re-arm diagnostic below; no bench path writes the
/// output directly.
#[inline]
#[cfg(any(
    feature = "bench-estop-rearm",
    feature = "bench-reflex-rearm",
    all(target_arch = "aarch64", feature = "rpi5")
))]
fn arm_reflex_output() -> (&'static str, i64) {
    match BENCH_REFLEX_OUTPUT {
        ReflexOutput::Gpio => ("gpio", crate::actuation::guard_gpio(BENCH_PWM_PIN, 1)),
        ReflexOutput::Pwm => (
            "pwm",
            crate::actuation::guard_pwm(
                BENCH_PWM_CHIP as u8,
                BENCH_PWM_CHANNEL as u8,
                BENCH_PWM_DUTY_PERCENT,
            ),
        ),
    }
}

/// Cycle stamp captured at GPIO IRQ entry; read at the actuation apply point to
/// compute edge->actuate latency (M-C). 0 means "no GPIO IRQ in flight".
static GPIO_IRQ_ENTRY: AtomicU64 = AtomicU64::new(0);
/// Boot-local monotonic identifier for correlating UART samples.
static NEXT_SAMPLE_ID: AtomicU64 = AtomicU64::new(1);
/// Identifier paired with `GPIO_IRQ_ENTRY`; zero means no IRQ is in flight.
static GPIO_IRQ_SAMPLE_ID: AtomicU64 = AtomicU64::new(0);
/// Press identifier retained until the matching e-stop release/re-arm.
static ESTOP_SAMPLE_ID: AtomicU64 = AtomicU64::new(0);
/// Sensor sample awaiting the feature-gated post-response re-arm.
static REFLEX_SAMPLE_ID: AtomicU64 = AtomicU64::new(0);
/// Ensures the physical route-proven marker is emitted at most once per boot.
static GPIO_IRQ_PROVEN: AtomicBool = AtomicBool::new(false);
/// Bound the per-entry handler census so a stuck source cannot flood serial.
static GPIO_IRQ_DIAG_COUNT: AtomicU64 = AtomicU64::new(0);

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

/// Stamp the counter at GPIO interrupt entry (start point for M-C and M-B).
#[inline]
pub fn mark_gpio_irq_entry() {
    let sample_id = NEXT_SAMPLE_ID.fetch_add(1, Ordering::Relaxed);
    GPIO_IRQ_ENTRY.store(now_cycles(), Ordering::Relaxed);
    GPIO_IRQ_SAMPLE_ID.store(sample_id, Ordering::Release);
}

/// Read and clear the GPIO IRQ-entry stamp (0 if none). Ensures the stamp is
/// consumed exactly once so it can never leak into a later actuation's report.
#[inline]
pub fn take_gpio_irq_entry() -> Option<(u64, u64)> {
    let sample_id = GPIO_IRQ_SAMPLE_ID.swap(0, Ordering::AcqRel);
    let entry = GPIO_IRQ_ENTRY.swap(0, Ordering::Relaxed);
    (sample_id != 0 && entry != 0).then_some((sample_id, entry))
}

/// Report M-A and M-C only after the local output write has been issued and
/// timestamped. M-C begins at this GPIO handler's software stamp, not at the
/// external sensor edge; physical edge latency requires the analyzer.
pub fn report_edge_to_actuate(
    kind: &str,
    channel: u8,
    value: u32,
    monitor_cycles: u64,
    applied_at: u64,
) {
    let Some((sample_id, start)) = take_gpio_irq_entry() else {
        return;
    };
    let ns = cycles_to_ns(applied_at.wrapping_sub(start));
    REFLEX_SAMPLE_ID.store(sample_id, Ordering::Release);
    crate::serial_println!(
        "PI5_MA sample_id={} monitor_ns={}",
        sample_id,
        cycles_to_ns(monitor_cycles)
    );
    crate::serial_println!(
        "PI5_MC sample_id={} ns={} kind={} ch={} val={}",
        sample_id,
        ns,
        kind,
        channel,
        value
    );
}

/// Re-arm only after the correlated sensor response completed and released the
/// actuation lock. This is excluded from production and non-HIL images.
#[cfg(feature = "bench-reflex-rearm")]
pub fn rearm_reflex_after_sample() {
    let sample_id = REFLEX_SAMPLE_ID.swap(0, Ordering::AcqRel);
    if sample_id == 0 {
        return;
    }
    let (mode, code) = arm_reflex_output();
    crate::serial_println!(
        "PI5_REFLEX_REARM sample_id={} mode={} code={}",
        sample_id,
        mode,
        code
    );
}

/// Handle the physical e-stop button (M-B), called from the GPIO IRQ handler
/// with `pressed` already resolved from the edge/level. Pressed => operator
/// trigger; released => operator release. Routes through the kernel-owned e-stop,
/// the same path as `sys_estop`. M-B ends after the local safe writes are
/// issued, before link notification or logging. It does not measure physical
/// pad propagation or downstream motor shutdown. The entry stamp is consumed
/// either way so it cannot leak into another actuation's M-C line.
pub fn handle_estop_button(pressed: bool) {
    use kernel_bpf::actuation::EstopAction;
    let entry = take_gpio_irq_entry();
    if pressed {
        let (code, applied_at) = crate::actuation::operator_estop_timed(EstopAction::Trigger);
        if let Some((sample_id, entry)) = entry {
            ESTOP_SAMPLE_ID.store(sample_id, Ordering::Release);
            if let (0, Some(applied_at)) = (code, applied_at) {
                let ns = cycles_to_ns(applied_at.wrapping_sub(entry));
                crate::serial_println!("PI5_MB sample_id={} ns={}", sample_id, ns);
            } else {
                crate::serial_println!("PI5_BENCH_FAIL stage=estop_apply sample_id={}", sample_id);
            }
        }
    } else {
        let release_code = crate::actuation::operator_estop(EstopAction::Release);

        // SAFETY: This deliberately re-arms an output after a physical e-stop
        // release only for unloaded HIL diagnostics. It is excluded from normal
        // bench and production builds, never runs for the boot-time state check
        // (which has entry == 0), and still passes through the monitor guards.
        #[cfg(feature = "bench-estop-rearm")]
        if entry.is_some() && release_code == 0 {
            let sample_id = ESTOP_SAMPLE_ID.swap(0, Ordering::AcqRel);
            let (mode, arm_code) = arm_reflex_output();
            crate::serial_println!(
                "PI5_ESTOP_REARM sample_id={} mode={} code={}",
                sample_id,
                mode,
                arm_code
            );
        }

        #[cfg(not(feature = "bench-estop-rearm"))]
        let _ = (entry, release_code);
    }
}

/// Emit the physical GPIO route marker only after a single GPIO23 source was
/// observed through IO_BANK0 PCIE_INTS, handled exactly once, cleared, and left
/// the parent status inactive. This is a probe result, not a latency result.
pub fn report_gpio_irq_probe(
    pending_before: u32,
    pending_after: u32,
    handled_events: u32,
    sensor_events: u32,
) {
    let expected = 1u32 << REFLEX_SENSOR_PIN;
    if GPIO_IRQ_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) < 8 {
        crate::serial_println!(
            "PI5_GPIO_IRQ_DIAG pending_before=0x{:08x} sensor_events=0x{:08x} handled={} pending_after=0x{:08x}",
            pending_before,
            sensor_events,
            handled_events,
            pending_after
        );
    }
    if pending_before == expected
        && pending_after == 0
        && handled_events == 1
        && !GPIO_IRQ_PROVEN.swap(true, Ordering::Relaxed)
    {
        crate::serial_println!(
            "PI5_GPIO_IRQ_PROVEN pin={} pending_before=0x{:08x} pending_after=0x{:08x}",
            REFLEX_SENSOR_PIN,
            pending_before,
            pending_after
        );
    }
}

/// V03-C containment corpus: fire a deterministic set of 1000 invalid /
/// out-of-envelope actuation requests through the REAL ARM-A monitor decision
/// (the same `decide().apply()` the guards use) and count "escapes" — any
/// applied value outside the channel's envelope, or any unknown-channel request
/// that did not produce the universal safe value 0. Runs the monitor logic only
/// (no MMIO), and avoids the bench's own channels so it cannot disturb the
/// reflex arm. Emits one correlated `PI5_V03C` record per request with an
/// intended output plus a retained `PI5_V03C_SUMMARY` record; physical output
/// evidence remains a hardware campaign result.
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
pub fn run_containment_corpus() {
    use kernel_bpf::actuation::{
        ActuationKind, ActuationRequest, AuditSource, Authority, ChannelId,
    };

    const N: u32 = 1000;
    const SEED: u64 = 0x5652_3033_4300_0001;
    let mut rng = SEED;
    let mut next = || {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (rng >> 33) as u32
    };

    let now = crate::time::get_kernel_time_ns();
    let mut escapes = 0u32;
    let mut safed = 0u32;
    let mut clamps = 0u32;

    // This is a decision-model benchmark, not the live actuation path. A local
    // monitor also prevents serial output from holding the IRQ-shared monitor.
    let mut mon = kernel_bpf::actuation::Monitor::<kernel_bpf::profile::ActiveProfile>::new();
    crate::serial_println!("PI5_V03C_SCOPE model_only=true physical_acceptance=false");
    for sample_id in 1..=N {
        let r = next();
        let kind = if r & 1 == 0 {
            ActuationKind::PwmDuty
        } else {
            ActuationKind::GpioLevel
        };
        // Draw channels including invalid ones, but never the bench's own
        // channel/pin (PWM ch1 / GPIO12) so the reflex arm state stays clean.
        let channel = match kind {
            ActuationKind::PwmDuty => match (r >> 1) % 5 {
                0 => 0,  // invalid (0-based / below 1) -> reject
                1 => 2,  // valid
                2 => 3,  // valid-or-invalid depending on PWM_CHANNELS
                3 => 99, // invalid -> reject
                _ => 2,
            },
            ActuationKind::GpioLevel => {
                let p = ((r >> 1) % 40) as u8; // includes >=28 (invalid)
                if p == BENCH_PWM_PIN || p == REFLEX_SENSOR_PIN || p == ESTOP_BUTTON_PIN {
                    5
                } else {
                    p
                }
            }
        };
        let value = match r % 4 {
            0 => r % 512,  // frequently over the duty envelope
            1 => 0,        // safe
            2 => r % 3,    // small (in range for gpio, low duty for pwm)
            _ => u32::MAX, // extreme -> must clamp/reject
        };
        let ch = ChannelId {
            kind,
            chip: 0,
            channel,
        };
        let decision = mon.decide(
            ActuationRequest { ch, value },
            Authority::Learned,
            AuditSource::LearnedBehavior,
            now,
        );
        let (applied, code) = decision.apply();
        let decision_name = match decision {
            kernel_bpf::actuation::Decision::Allow(_) => "allow",
            kernel_bpf::actuation::Decision::Clamp(_) => "clamp",
            kernel_bpf::actuation::Decision::Safe(_) => "safe",
            kernel_bpf::actuation::Decision::Reject(_) => "reject",
        };
        crate::serial_println!(
            "PI5_V03C sample_id={} kind={} channel={} requested={} decision={} applied={} intended_output={}",
            sample_id,
            match kind {
                ActuationKind::PwmDuty => "pwm",
                ActuationKind::GpioLevel => "gpio",
            },
            channel,
            value,
            decision_name,
            applied,
            applied
        );
        // Containment invariant: a known channel must apply within [min,max];
        // an unknown channel must apply the universal safe value 0.
        let contained = match mon.cached_envelope(ch) {
            Some(env) => applied >= env.min && applied <= env.max,
            None => applied == 0,
        };
        if !contained {
            escapes += 1;
        }
        // code < 0 marks a policy intervention (Reject/Safe drove the safe value).
        if code < 0 {
            safed += 1;
        }
        if matches!(decision, kernel_bpf::actuation::Decision::Clamp(_)) {
            clamps += 1;
        }
    }

    crate::serial_println!(
        "PI5_V03C_SUMMARY n={} escapes={} safed={} clamps={} seed=0x{:016x}",
        N,
        escapes,
        safed,
        clamps,
        SEED
    );
}

#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bench-paired-overhead"
))]
fn run_paired_overhead() {
    const N: u64 = 10_000;
    crate::serial_println!("PI5_V03A_BEGIN count={} output=gpio12-safe-low", N);
    for sample_id in 1..=N {
        let (baseline_cycles, monitor_cycles) = crate::actuation::bench_measure_gpio_pair();
        let baseline_ns = cycles_to_ns(baseline_cycles);
        let monitor_ns = cycles_to_ns(monitor_cycles);
        let added_ns = i128::from(monitor_ns) - i128::from(baseline_ns);
        crate::serial_println!(
            "PI5_PAIR sample_id={} baseline_ns={} monitor_ns={} added_ns={}",
            sample_id,
            baseline_ns,
            monitor_ns,
            added_ns
        );
    }
    crate::serial_println!("PI5_V03A_DONE count={}", N);
}

/// Boot-time bench setup (Pi 5 only): arm the sensor + button pin IRQs and
/// auto-load the reflex program attached to the sensor's rising edge.
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
pub fn init() -> bool {
    use kernel_bpf::attach::GpioEdge;

    use crate::arch::aarch64::platform::rpi5::gpio::{GpioFunction, GpioPull, Rp1Gpio};

    // SAFETY: the kernel owns the RP1 GPIO block; this runs once at boot.
    let gpio = unsafe { Rp1Gpio::new() };
    // Firmware may preserve RP1 across a warm reboot. Quiesce and clear every
    // IO_BANK0 source before MSI-X is enabled so stale state cannot interrupt
    // halfway through route construction.
    for pin in 0..Rp1Gpio::NUM_PINS {
        gpio.disable_interrupt(pin);
    }
    let route = match gpio.init_pcie_interrupt_route() {
        Ok(route) => route,
        Err(error) => {
            log::error!("[bench] RP1 interrupt route failed: {:?}", error);
            crate::serial_println!("PI5_BENCH_FAIL stage=rp1_irq_route error={:?}", error);
            return false;
        }
    };

    crate::serial_println!(
        "PI5_BENCH_TIMING mc=handler_to_local_write mb=handler_to_local_safe_writes counter_hz={}",
        counter_freq()
    );

    // V03-C: prove on-device that no invalid/out-of-envelope request escapes the
    // monitor. Runs before the reflex is armed; monitor-decision only, no MMIO.
    run_containment_corpus();

    // Keep the pad GPIO-low while preparing PWM, including on a warm reboot.
    // No direct high-output self-test: nonzero actuation goes through ARM-A.
    gpio.configure_output(BENCH_PWM_PIN, false);

    #[cfg(feature = "bench-paired-overhead")]
    run_paired_overhead();

    if BENCH_REFLEX_OUTPUT == ReflexOutput::Pwm {
        use crate::arch::aarch64::platform::rpi5::pwm::{enable_pwm0_clock, PWM0};
        enable_pwm0_clock();
        let pwm = PWM0.lock();
        pwm.disable(BENCH_PWM_CHANNEL as u8);
        pwm.set_frequency(BENCH_PWM_CHANNEL as u8, BENCH_PWM_FREQ_HZ);
        pwm.set_duty_cycle(BENCH_PWM_CHANNEL as u8, 0);
        pwm.enable(BENCH_PWM_CHANNEL as u8);
        drop(pwm);
        gpio.configure_peripheral_output(BENCH_PWM_PIN, GpioFunction::Alt0);
    }
    gpio.configure_input(REFLEX_SENSOR_PIN);
    gpio.configure_input(ESTOP_BUTTON_PIN);
    // Keep disconnected inputs deterministic. The external fail-safe e-stop
    // circuit overrides this weak pull by holding GPIO24 high through its
    // closed NC contact; an open contact/cable therefore remains low and safe.
    gpio.set_pull(REFLEX_SENSOR_PIN, GpioPull::Down);
    gpio.set_pull(ESTOP_BUTTON_PIN, GpioPull::Down);
    let initial_estop_pressed = !gpio.read(ESTOP_BUTTON_PIN);
    handle_estop_button(initial_estop_pressed);
    // Sensor: rising edge only. Button: both edges (press + release).
    gpio.enable_interrupt(REFLEX_SENSOR_PIN, true, false);
    gpio.enable_interrupt(ESTOP_BUTTON_PIN, true, true);
    let sensor_irq = gpio.interrupt_state(REFLEX_SENSOR_PIN);
    let estop_irq = gpio.interrupt_state(ESTOP_BUTTON_PIN);
    let expected_pcie_enable = (1u32 << REFLEX_SENSOR_PIN) | (1u32 << ESTOP_BUTTON_PIN);
    if sensor_irq.control & (1 << 21) == 0
        || sensor_irq.pad & (1 << 6) == 0
        || sensor_irq.pcie_enable & expected_pcie_enable != expected_pcie_enable
    {
        crate::serial_println!(
            "PI5_BENCH_FAIL stage=gpio_irq_readback sensor_status=0x{:08x} sensor_ctrl=0x{:08x} sensor_pad=0x{:08x} raw=0x{:08x} pcie_inte=0x{:08x} pcie_ints=0x{:08x}",
            sensor_irq.status,
            sensor_irq.control,
            sensor_irq.pad,
            sensor_irq.raw_interrupts,
            sensor_irq.pcie_enable,
            sensor_irq.pcie_status
        );
        return false;
    }

    // Build + load + attach the reflex: on the sensor edge it drives the output
    // to its safe value (GPIO low, or PWM duty 0) through the actuation monitor.
    let insns = match BENCH_REFLEX_OUTPUT {
        ReflexOutput::Gpio => kernel_bpf::bench::reflex_gpio_program(BENCH_PWM_PIN as u32, 0),
        ReflexOutput::Pwm => {
            kernel_bpf::bench::reflex_pwm_program(BENCH_PWM_CHIP, BENCH_PWM_CHANNEL, 0)
        }
    };
    let Some(manager) = crate::BPF_MANAGER.get() else {
        log::error!("[bench] BPF manager not initialized; reflex not loaded");
        crate::serial_println!("PI5_BENCH_FAIL stage=bpf_manager_missing");
        return false;
    };
    let mut mgr = manager.lock();
    match mgr.load_kernel_builtin_program(insns) {
        Ok(prog_id) => {
            if let Err(e) = mgr.attach_gpio_route(0, REFLEX_SENSOR_PIN, GpioEdge::Rising, prog_id) {
                log::error!("[bench] reflex attach failed: {:?}", e);
                crate::serial_println!("PI5_BENCH_FAIL stage=attach error={:?}", e);
                return false;
            }
            // Drop the BPF manager lock before touching the actuation locks so
            // arm never nests BPF-manager under the apply/monitor locks.
            drop(mgr);
            // Arm the reflex output HIGH through the e-stop-guarded path. Denied
            // (output stays low) while e-stop is asserted, e.g. GPIO24 not held
            // high. The reflex drives it back low/0 on the sensor edge.
            let (mode, arm_code) = arm_reflex_output();
            crate::serial_println!(
                "PI5_OUT_ARM mode={} gpio={} code={} estop_asserted={} gpio12_ctrl=0x{:08x} gpio12_pad=0x{:08x}",
                mode,
                BENCH_PWM_PIN,
                arm_code,
                initial_estop_pressed,
                gpio.ctrl_readback(BENCH_PWM_PIN),
                gpio.pad_readback(BENCH_PWM_PIN)
            );
            #[cfg(feature = "bench-pwm")]
            crate::serial_println!(
                "PI5_PWM_READY carrier_request_hz={} requested_duty_percent={} auto_rearm=false",
                BENCH_PWM_FREQ_HZ,
                BENCH_PWM_DUTY_PERCENT
            );
            #[cfg(feature = "bench-estop-rearm")]
            crate::serial_println!("PI5_V03D_READY output={} auto_rearm=true", mode);
            #[cfg(feature = "bench-reflex-rearm")]
            crate::serial_println!(
                "PI5_V03B_READY output={} sample_ids=true auto_rearm=true",
                mode
            );
            if BENCH_REFLEX_OUTPUT == ReflexOutput::Pwm {
                use crate::arch::aarch64::platform::rpi5::pwm::{
                    pwm0_clock_ctrl, pwm0_clock_div, PWM0,
                };
                let (pwm_g, pwm_ctrl, pwm_rng, pwm_dat) =
                    PWM0.lock().debug_regs(BENCH_PWM_CHANNEL as u8);
                let (div_int, div_frac) = pwm0_clock_div();
                crate::serial_println!(
                    "PI5_PWM_ARM channel={} clk_ctrl=0x{:08x} div_int=0x{:08x} div_frac=0x{:08x} global=0x{:08x} chan_ctrl=0x{:08x} range=0x{:08x} duty=0x{:08x}",
                    BENCH_PWM_CHANNEL,
                    pwm0_clock_ctrl(),
                    div_int,
                    div_frac,
                    pwm_g,
                    pwm_ctrl,
                    pwm_rng,
                    pwm_dat
                );
            }
            log::info!(
                "[bench] reflex loaded id={} -> (gpiochip0, pin {}, rising) stops PWM{} ch{} on GPIO{}",
                prog_id,
                REFLEX_SENSOR_PIN,
                BENCH_PWM_CHIP,
                BENCH_PWM_CHANNEL,
                BENCH_PWM_PIN
            );
            crate::serial_println!(
                "PI5_BENCH_READY sensor_gpio={} estop_gpio={} pwm_gpio={} initial_estop_asserted={} sensor_status=0x{:08x} sensor_ctrl=0x{:08x} sensor_pad=0x{:08x} estop_status=0x{:08x} estop_ctrl=0x{:08x} pcie_inte=0x{:08x} raw=0x{:08x} rp1_chip_id=0x{:08x} rp1_vendor_device=0x{:08x} rp1_msix_cap=0x{:02x} rp1_msix_vectors={} rp1_msix_control=0x{:08x} rp1_msix0_cfg=0x{:08x} pcie_link=0x{:08x}",
                REFLEX_SENSOR_PIN,
                ESTOP_BUTTON_PIN,
                BENCH_PWM_PIN,
                initial_estop_pressed,
                sensor_irq.status,
                sensor_irq.control,
                sensor_irq.pad,
                estop_irq.status,
                estop_irq.control,
                sensor_irq.pcie_enable,
                sensor_irq.raw_interrupts,
                route.chip_id,
                route.vendor_device,
                route.msix_cap_offset,
                route.msix_table_size,
                route.msix_control,
                route.vector0_config,
                route.pcie_link_status
            );
            true
        }
        Err(e) => {
            log::error!("[bench] reflex load rejected: {:?}", e);
            crate::serial_println!("PI5_BENCH_FAIL stage=load error={:?}", e);
            false
        }
    }
}

/// Boot-time bench setup is a no-op off the Pi 5 platform.
#[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
pub fn init() -> bool {
    true
}
