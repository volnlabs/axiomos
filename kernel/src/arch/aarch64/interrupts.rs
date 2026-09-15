//! ARM64 Interrupt Handling
//!
//! This module handles interrupt initialization and dispatching for ARM64.
//! It uses the GIC (Generic Interrupt Controller) for interrupt management
//! and the ARM generic timer for scheduling.
//!
//! # RP1 GPIO Interrupt Routing
//!
//! On Raspberry Pi 5, RP1 IO_BANK0 is RP1 interrupt/vector 0. PCIe2 uses
//! BCM2712 MIP0 for MSI-X; MIP0 maps vectors 0..63 to GIC SPIs 128..191.
//! Therefore IO_BANK0 arrives at GIC SPI 128, interrupt ID 160. The PCIe2
//! legacy INTA mapping (SPI 229 / ID 261) is not the RP1 MSI-X GPIO path.

#[cfg(all(
    feature = "rpi5",
    feature = "bringup-diagnostics",
    not(feature = "managed-runtime")
))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU8, Ordering};

use kernel_time::periodic::{PeriodicRelease, PeriodicSchedule, ReleaseError, ReleaseStats};
use spin::Mutex;

use super::gic;

/// Non-secure physical timer IRQ number (PPI 14 = IRQ 30)
const TIMER_IRQ: u32 = gic::irq::TIMER_PHYS;

struct TimerState {
    frequency: u64,
    schedule: PeriodicSchedule,
    last_release: Option<PeriodicRelease>,
    completion_misses: u64,
    #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
    last_control: Option<crate::bpf::control::CycleReport>,
    #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
    safe_releases: u64,
}

static TIMER: Mutex<Option<TimerState>> = Mutex::new(None);
// Sticky first failure, including a failed try_lock where TIMER cannot be written.
static TIMER_FAULT: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum TimerFault {
    Busy = 1,
    NotStarted,
    AlreadyStarted,
    InvalidPeriod,
    ClockReversed,
    Exhausted,
    Stopped,
    ManagedControl,
}

impl From<ReleaseError> for TimerFault {
    fn from(error: ReleaseError) -> Self {
        match error {
            ReleaseError::InvalidPeriod => Self::InvalidPeriod,
            ReleaseError::ClockReversed => Self::ClockReversed,
            ReleaseError::Exhausted => Self::Exhausted,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TimerSnapshot {
    pub frequency: u64,
    pub releases: ReleaseStats,
    pub last_release: Option<PeriodicRelease>,
    /// Completion covers timer work before EOI and scheduler dispatch.
    pub completion_misses: u64,
    /// Zero is healthy; otherwise the first TimerFault discriminant.
    pub fault_code: u8,
    #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
    pub(crate) last_control: Option<crate::bpf::control::CycleReport>,
    #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
    pub safe_releases: u64,
}

pub fn timer_snapshot() -> Option<TimerSnapshot> {
    crate::mcore::context::with_interrupts_masked(|| {
        let timer = TIMER.try_lock()?;
        let state = timer.as_ref()?;
        Some(TimerSnapshot {
            frequency: state.frequency,
            releases: state.schedule.stats(),
            last_release: state.last_release,
            completion_misses: state.completion_misses,
            fault_code: TIMER_FAULT.load(Ordering::Relaxed),
            #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
            last_control: state.last_control,
            #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
            safe_releases: state.safe_releases,
        })
    })
}

/// RP1 IO_BANK0 MSI-X vector 0: MIP0 SPI 128 + the GIC SPI base of 32.
#[cfg(feature = "rpi5")]
const RP1_GPIO_IRQ: u32 = 160;

#[cfg(all(
    feature = "rpi5",
    feature = "bringup-diagnostics",
    not(feature = "managed-runtime")
))]
static TIMER_IRQ_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    feature = "rpi5",
    feature = "bringup-diagnostics",
    not(feature = "managed-runtime")
))]
static FIRST_IRQ_MARKER_SENT: AtomicBool = AtomicBool::new(false);

#[cfg(all(
    feature = "rpi5",
    feature = "bringup-diagnostics",
    not(feature = "managed-runtime")
))]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0xFFFF_8010_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

#[cfg(all(
    feature = "rpi5",
    feature = "bringup-diagnostics",
    not(feature = "managed-runtime")
))]
#[inline(always)]
fn dbg_hex_nibble(v: u32) -> u32 {
    match v & 0xF {
        0..=9 => b'0' as u32 + (v & 0xF),
        _ => b'A' as u32 + ((v & 0xF) - 10),
    }
}

/// Initialize interrupt controller and timer
pub fn init() {
    // Initialize the GIC
    gic::init();

    // Enable timer interrupt (PPI 14)
    gic::enable_irq(TIMER_IRQ);
    gic::set_priority(TIMER_IRQ, 0x80);

    // Enable RP1 GPIO interrupt (routed via PCIe2)
    #[cfg(feature = "rpi5")]
    {
        gic::set_edge_triggered(RP1_GPIO_IRQ);
        gic::enable_irq(RP1_GPIO_IRQ);
        gic::set_priority(RP1_GPIO_IRQ, 0x80);
    }

    // The release schedule starts after CPU0 context exists, immediately before
    // main enables IRQs. Early boot initialization is not a running executor.
    clear_timer_interrupt();

    #[cfg(feature = "rpi5")]
    log::info!(
        "ARM interrupts initialized (timer={}, gpio={})",
        TIMER_IRQ,
        RP1_GPIO_IRQ
    );
    #[cfg(not(feature = "rpi5"))]
    log::info!("ARM interrupts initialized (timer={})", TIMER_IRQ);
}

use super::exceptions::ExceptionContext;

/// Handle IRQ interrupt (called from exception vector)
///
/// # Safety
///
/// This function is the IRQ exception handler entry point called from the vector table
/// (via assembly stubs that save register state). It assumes the GIC is initialized
/// and that it's safe to interact with hardware state. It must not unwind.
#[unsafe(no_mangle)]
pub extern "C" fn handle_irq(_ctx: &mut ExceptionContext) {
    // Acknowledge the interrupt and decode the IRQ ID for dispatch.
    // EOIR must receive the raw IAR value, not just the 10-bit ID.
    let iar = gic::acknowledge();
    let irq = gic::irq_id_from_iar(iar);

    // Check for spurious interrupt
    if irq == gic::irq::SPURIOUS {
        return;
    }

    #[cfg(all(
        feature = "rpi5",
        feature = "bringup-diagnostics",
        not(feature = "managed-runtime")
    ))]
    if !FIRST_IRQ_MARKER_SENT.swap(true, Ordering::Relaxed) {
        // Emit "M" + 3 hex nibbles of IRQ ID once (e.g., M01E for IRQ 30).
        dbg_mark(b'M' as u32);
        dbg_mark(dbg_hex_nibble((irq >> 8) & 0xF));
        dbg_mark(dbg_hex_nibble((irq >> 4) & 0xF));
        dbg_mark(dbg_hex_nibble(irq & 0xF));
    }

    // log::info!("Handling IRQ {}", irq);

    // Dispatch based on IRQ number
    if irq == TIMER_IRQ {
        #[cfg(all(
            feature = "rpi5",
            feature = "bringup-diagnostics",
            not(feature = "managed-runtime")
        ))]
        if !TIMER_IRQ_MARKER_SENT.swap(true, Ordering::Relaxed) {
            dbg_mark(b't' as u32);
        }

        let serviced = handle_timer_interrupt(_ctx);
        // Signal end of interrupt for timer
        gic::end_of_interrupt(iar);

        // UART framing and RX remain in the poller. Managed execution captures
        // and queues one pair here; it never drains UART or runs IIO fanout.

        // Trigger scheduler tick (may cause context switch)
        // We do this AFTER EOI so that new tasks don't inherit the active interrupt state
        if serviced {
            #[cfg(not(feature = "managed-runtime"))]
            log::trace!("Calling timer_tick");
            super::cpu::timer_tick();
        }
    } else {
        match irq {
            #[cfg(feature = "rpi5")]
            RP1_GPIO_IRQ => {
                crate::arch::aarch64::platform::rpi5::gpio::handle_interrupt();
            }
            _ => {
                #[cfg(not(feature = "managed-runtime"))]
                log::warn!("Unhandled IRQ: {}", irq);
            }
        }
        // Signal end of interrupt for other IRQs
        gic::end_of_interrupt(iar);
    }
}

/// Handle timer interrupt (without rescheduling)
fn handle_timer_interrupt(_ctx: &ExceptionContext) -> bool {
    clear_timer_interrupt();
    let (release, _frequency) = match set_next_timer() {
        Ok(Some(release)) => release,
        Ok(None) => return false,
        Err(error) => {
            timer_failed(error);
            return false;
        }
    };

    crate::mcore::mtask::scheduler::sleep::TaskSleep::wake_expired(
        crate::time::get_monotonic_time_ns(),
    );

    #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
    {
        let report = match crate::bpf::control::on_release(release, _frequency) {
            Ok(report) => report,
            Err(_) => {
                timer_failed(TimerFault::ManagedControl);
                return false;
            }
        };
        let Some(mut timer) = TIMER.try_lock() else {
            timer_failed(TimerFault::Busy);
            return false;
        };
        let Some(state) = timer.as_mut() else {
            drop(timer);
            timer_failed(TimerFault::NotStarted);
            return false;
        };
        state.last_control = Some(report);
        if report.safe_mode {
            let Some(count) = state.safe_releases.checked_add(1) else {
                drop(timer);
                timer_failed(TimerFault::Exhausted);
                return false;
            };
            state.safe_releases = count;
        }
    }

    // Build the timer context, then resolve the bounded hook snapshot without
    // allocating while the interrupt is active.
    #[cfg(not(feature = "managed-runtime"))]
    {
        // Calculate interrupt latency from vector entry to now
        let mut bpf_ctx = kernel_bpf::execution::BpfContext::empty();

        // Include kernel metrics if available
        if let Some(metrics) = crate::BOOT_METRICS.get() {
            bpf_ctx.set_kernel_metrics(
                metrics.boot_time_ms,
                metrics.kernel_heap_kb,
                metrics.kernel_image_mb,
            );
        }

        unsafe {
            let now: u64;
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) now);
            let latency_ticks = now.saturating_sub(_ctx.vector_entry_timestamp);

            // Convert ticks to nanoseconds: ns = ticks * 1,000,000,000 / freq
            let freq: u64;
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
            bpf_ctx.set_interrupt_latency_ns(
                (latency_ticks as u128 * 1_000_000_000 / freq as u128) as u64,
            );
        }

        let _ = crate::bpf::BpfManager::run_hook_programs(
            crate::bpf::ATTACH_TYPE_TIMER,
            &bpf_ctx,
            "timer",
        );
    }
    #[cfg(all(feature = "rpi5", feature = "bench", not(feature = "managed-runtime")))]
    crate::serial::drain_bench_buffer();

    let completed = physical_counter();
    if completed < release.actual {
        timer_failed(TimerFault::ClockReversed);
        return false;
    }
    if !release.completed_in_time(completed) {
        let Some(mut timer) = TIMER.try_lock() else {
            timer_failed(TimerFault::Busy);
            return false;
        };
        let Some(state) = timer.as_mut() else {
            drop(timer);
            timer_failed(TimerFault::NotStarted);
            return false;
        };
        let Some(misses) = state.completion_misses.checked_add(1) else {
            drop(timer);
            timer_failed(TimerFault::Exhausted);
            return false;
        };
        state.completion_misses = misses;
        drop(timer);
        #[cfg(feature = "managed-runtime")]
        crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
    }
    true
}

/// Clear timer interrupt
fn clear_timer_interrupt() {
    // SAFETY: Writing to CNTP_CTL_EL0 is safe in EL1/EL0. Disabling the timer clears the interrupt.
    unsafe {
        // Disable timer to clear interrupt
        core::arch::asm!("msr cntp_ctl_el0, {}", "isb", in(reg) 0u64);
    }
}

pub(crate) fn physical_counter() -> u64 {
    let count: u64;
    // SAFETY: EL1 can read CNTPCT; it uses the same counter as CNTP_CVAL.
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) count);
    }
    count
}

fn arm_timer(next: u64) {
    // SAFETY: EL1 owns this CPU's physical timer. The caller serializes updates
    // with IRQs masked; the compare uses the physical counter's tick domain.
    unsafe {
        core::arch::asm!("msr cntp_cval_el0, {}", in(reg) next);
        core::arch::asm!("msr cntp_ctl_el0, {}", "isb", in(reg) 1u64);
    }
}

/// No allocation, manager lock, waiting or deadline rebasing in the IRQ.
fn set_next_timer() -> Result<Option<(PeriodicRelease, u64)>, TimerFault> {
    if TIMER_FAULT.load(Ordering::Relaxed) != 0 {
        return Err(TimerFault::Stopped);
    }
    let mut timer = TIMER.try_lock().ok_or(TimerFault::Busy)?;
    let state = timer.as_mut().ok_or(TimerFault::NotStarted)?;
    let release = state.schedule.release(physical_counter())?;
    if release.is_some() {
        state.last_release = release;
    }
    arm_timer(state.schedule.next_deadline());
    Ok(release.map(|release| (release, state.frequency)))
}

fn timer_failed(error: TimerFault) {
    let first = TIMER_FAULT
        .compare_exchange(0, error as u8, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok();
    clear_timer_interrupt();
    // Bounded trusted stop; local enqueue is not remote sink acknowledgement.
    if first {
        crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
    }
}

/// Start once, after CPU0 initialization and immediately before enabling IRQs.
pub fn init_timer() -> Result<(), TimerFault> {
    crate::mcore::context::with_interrupts_masked(|| {
        let mut timer = TIMER.try_lock().ok_or(TimerFault::Busy)?;
        if timer.is_some() || TIMER_FAULT.load(Ordering::Relaxed) != 0 {
            return Err(TimerFault::AlreadyStarted);
        }
        let frequency: u64;
        // SAFETY: EL1 may read the architectural counter frequency.
        unsafe {
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency);
        }
        // Refuse clocks that cannot represent exactly 10 ms in whole ticks.
        if frequency == 0 || frequency % 100 != 0 {
            return Err(TimerFault::InvalidPeriod);
        }
        let schedule = PeriodicSchedule::new(physical_counter(), frequency / 100)?;
        arm_timer(schedule.next_deadline());
        *timer = Some(TimerState {
            frequency,
            schedule,
            last_release: None,
            completion_misses: 0,
            #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
            last_control: None,
            #[cfg(all(feature = "rpi5", feature = "managed-runtime"))]
            safe_releases: 0,
        });
        Ok(())
    })
}

/// End of interrupt (public wrapper)
pub fn end_of_interrupt(irq_id: u32) {
    gic::end_of_interrupt(irq_id);
}
