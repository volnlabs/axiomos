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
//!   - GPIO24 = e-stop button (external 10k pull-up to 3V3; press pulls to GND)
//!   - GPIO12 = PWM0 channel 1 physical output to motor-A speed/enable
//!   - PWM0 channel 1 = motor-A speed/enable (driver enable pin)

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Sensor pin: the reflex fires on this pin's rising edge.
pub const REFLEX_SENSOR_PIN: u8 = 23;
/// E-stop button pin (external pull-up; press pulls to GND -> falling edge).
pub const ESTOP_BUTTON_PIN: u8 = 24;
/// PWM controller the reflex and demo drive (PWM0).
/// Reflex-output PWM carrier. At 100% duty this holds GPIO12 high until the
/// reflex writes duty 0, giving V03-B a single GPIO12 falling edge to measure.
pub const BENCH_PWM_FREQ_HZ: u32 = 10_000;
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
pub const BENCH_REFLEX_OUTPUT: ReflexOutput = ReflexOutput::Gpio;

/// True when an actuation targets the local PWM output reserved for Task 11.
#[inline]
pub fn is_bench_pwm_output(chip: u8, channel: u8) -> bool {
    u32::from(chip) == BENCH_PWM_CHIP && u32::from(channel) == BENCH_PWM_CHANNEL
}

/// Cycle stamp captured at GPIO IRQ entry; read at the actuation apply point to
/// compute edge->actuate latency (M-C). 0 means "no GPIO IRQ in flight".
static GPIO_IRQ_ENTRY: AtomicU64 = AtomicU64::new(0);
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
    GPIO_IRQ_ENTRY.store(now_cycles(), Ordering::Relaxed);
}

/// Read and clear the GPIO IRQ-entry stamp (0 if none). Ensures the stamp is
/// consumed exactly once so it can never leak into a later actuation's report.
#[inline]
pub fn take_gpio_irq_entry() -> u64 {
    GPIO_IRQ_ENTRY.swap(0, Ordering::Relaxed)
}

/// Report monitor decision overhead (M-A). Logged on every guarded actuation.
/// Emits a compact serial marker so a host reducer can build the distribution
/// (`log::info` does not reach the Pi UART).
#[inline]
pub fn report_monitor_overhead(decide_cycles: u64) {
    crate::serial_println!("PI5_MA ns={}", cycles_to_ns(decide_cycles));
}

/// Report edge->actuate latency for the GPIO IRQ currently in flight (M-C).
/// No-op outside a GPIO IRQ (when no entry stamp is set); consumes the stamp so
/// a later non-IRQ actuation cannot reuse it.
pub fn report_edge_to_actuate(kind: &str, channel: u8, value: u32) {
    let start = take_gpio_irq_entry();
    if start == 0 {
        return;
    }
    let ns = cycles_to_ns(now_cycles().wrapping_sub(start));
    // Compact serial marker for the V03-B latency distribution (edge -> actuate,
    // M-C). One line per sensor edge; the host reducer parses `ns=`.
    crate::serial_println!("PI5_MC ns={} kind={} ch={} val={}", ns, kind, channel, value);
}

/// Handle the physical e-stop button (M-B), called from the GPIO IRQ handler
/// with `pressed` already resolved from the edge/level. Pressed => operator
/// trigger; released => operator release. Routes through the kernel-owned e-stop,
/// the same path as `sys_estop`. M-B is timed from IRQ entry to "all channels
/// safe", and the IRQ-entry stamp is consumed here either way so it cannot leak
/// into a later actuation's M-C line.
pub fn handle_estop_button(pressed: bool) {
    use kernel_bpf::actuation::EstopAction;
    let entry = take_gpio_irq_entry();
    if pressed {
        crate::actuation::operator_estop(EstopAction::Trigger);
        if entry != 0 {
            let ns = cycles_to_ns(now_cycles().wrapping_sub(entry));
            log::info!("[bench] M-B estop irq-entry->safe latency_ns={}", ns);
        }
    } else {
        crate::actuation::operator_estop(EstopAction::Release);
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
    // Configure the reflex output pin (GPIO12). GPIO mode drives it as a plain
    // GPIO output; PWM mode routes it to the PWM0 peripheral (Alt0).
    match BENCH_REFLEX_OUTPUT {
        ReflexOutput::Gpio => gpio.configure_output(BENCH_PWM_PIN, false),
        ReflexOutput::Pwm => {
            gpio.configure_peripheral_output(BENCH_PWM_PIN, GpioFunction::Alt0)
        }
    }

    // Pad-driver self-test: force the pad high then low via the CTRL override,
    // bypassing PWM. If this toggles the read-back level but the PWM duty test
    // below does not, the pad + readback are fine and the PWM counter/clock is
    // the dead layer. Restores normal (peripheral-driven) output after.
    gpio.force_output_override(BENCH_PWM_PIN, Some(true));
    let pad_drive_high = gpio.interrupt_state(BENCH_PWM_PIN).status;
    gpio.force_output_override(BENCH_PWM_PIN, Some(false));
    let pad_drive_low = gpio.interrupt_state(BENCH_PWM_PIN).status;
    gpio.force_output_override(BENCH_PWM_PIN, None);
    crate::serial_println!(
        "PI5_PAD_SELFTEST drive_high=0x{:08x} drive_low=0x{:08x} toggled={}",
        pad_drive_high,
        pad_drive_low,
        pad_drive_high != pad_drive_low
    );

    // PWM mode only: enable the PWM0 functional clock and the channel (output
    // held LOW), then self-test the output by driving DC high/low. The HIGH arm
    // later goes through the e-stop-guarded actuation path, never a raw write.
    if BENCH_REFLEX_OUTPUT == ReflexOutput::Pwm {
        use crate::arch::aarch64::platform::rpi5::pwm::{enable_pwm0_clock, pwm0_clock_ctrl, PWM0};
        enable_pwm0_clock();
        let pwm = PWM0.lock();
        pwm.set_frequency(BENCH_PWM_CHANNEL as u8, BENCH_PWM_FREQ_HZ);
        pwm.set_duty_cycle(BENCH_PWM_CHANNEL as u8, 0);
        pwm.enable(BENCH_PWM_CHANNEL as u8);

        pwm.set_duty_cycle(BENCH_PWM_CHANNEL as u8, 100);
        let status_high = gpio.interrupt_state(BENCH_PWM_PIN).status;
        pwm.set_duty_cycle(BENCH_PWM_CHANNEL as u8, 0);
        let status_low = gpio.interrupt_state(BENCH_PWM_PIN).status;
        crate::serial_println!(
            "PI5_PWM_SELFTEST clk_ctrl=0x{:08x} status_high=0x{:08x} status_low=0x{:08x} toggled={}",
            pwm0_clock_ctrl(),
            status_high,
            status_low,
            status_high != status_low
        );
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
            let arm_code = match BENCH_REFLEX_OUTPUT {
                ReflexOutput::Gpio => crate::actuation::guard_gpio(BENCH_PWM_PIN, 1),
                ReflexOutput::Pwm => {
                    crate::actuation::guard_pwm(BENCH_PWM_CHIP as u8, BENCH_PWM_CHANNEL as u8, 100)
                }
            };
            let mode = match BENCH_REFLEX_OUTPUT {
                ReflexOutput::Gpio => "gpio",
                ReflexOutput::Pwm => "pwm",
            };
            crate::serial_println!(
                "PI5_OUT_ARM mode={} gpio={} code={} estop_asserted={} gpio12_ctrl=0x{:08x} gpio12_pad=0x{:08x}",
                mode,
                BENCH_PWM_PIN,
                arm_code,
                initial_estop_pressed,
                gpio.ctrl_readback(BENCH_PWM_PIN),
                gpio.pad_readback(BENCH_PWM_PIN)
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
