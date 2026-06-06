//! ARM64 Interrupt Handling
//!
//! This module handles interrupt initialization and dispatching for ARM64.
//! It uses the GIC (Generic Interrupt Controller) for interrupt management
//! and the ARM generic timer for scheduling.
//!
//! # RP1 GPIO Interrupt Routing
//!
//! On Raspberry Pi 5, the RP1 southbridge connects via PCIe2. The RP1 has
//! its own internal interrupt controller that aggregates all peripheral
//! interrupts (GPIO, UART, SPI, etc.) and routes them to the main GIC
//! via PCIe MSI or legacy interrupts.
//!
//! According to the BCM2712 device tree:
//! - PCIe2 INTA -> GIC SPI 229 (IRQ 261)
//! - PCIe2 INTB -> GIC SPI 230 (IRQ 262)
//! - PCIe2 INTC -> GIC SPI 231 (IRQ 263)
//! - PCIe2 INTD -> GIC SPI 232 (IRQ 264)
//!
//! The RP1's GPIO Bank 0 generates internal IRQ 0, which routes through
//! the RP1's interrupt controller to one of these PCIe lines.

#[cfg(feature = "rpi5")]
use core::sync::atomic::{AtomicBool, Ordering};

use super::gic;

/// Non-secure physical timer IRQ number (PPI 14 = IRQ 30)
const TIMER_IRQ: u32 = gic::irq::TIMER_PHYS;

/// RP1 GPIO IRQ number
///
/// The RP1 connects via PCIe2, which uses GIC SPI 229-232 for INTA-D.
/// GIC SPI numbers map to IRQ IDs as: SPI N = IRQ (32 + N).
/// So PCIe2 INTA (SPI 229) = IRQ 261.
///
/// Note: The RP1 has its own internal interrupt controller. GPIO Bank 0
/// is RP1 internal IRQ 0. A full implementation would need to also read
/// the RP1's interrupt status registers to determine which peripheral
/// (GPIO, UART, etc.) raised the interrupt.
#[cfg(feature = "rpi5")]
const RP1_GPIO_IRQ: u32 = 261; // GIC SPI 229 = 32 + 229

#[cfg(feature = "rpi5")]
static TIMER_IRQ_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static FIRST_IRQ_MARKER_SENT: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "rpi5")]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0xFFFF_8010_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

#[cfg(feature = "rpi5")]
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
        gic::enable_irq(RP1_GPIO_IRQ);
        gic::set_priority(RP1_GPIO_IRQ, 0x80);
    }

    // Initialize and start the timer
    init_timer();

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

    #[cfg(feature = "rpi5")]
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
        #[cfg(feature = "rpi5")]
        if !TIMER_IRQ_MARKER_SENT.swap(true, Ordering::Relaxed) {
            dbg_mark(b't' as u32);
        }

        handle_timer_interrupt(_ctx);
        // Signal end of interrupt for timer
        gic::end_of_interrupt(iar);

        // Trigger scheduler tick (may cause context switch)
        // We do this AFTER EOI so that new tasks don't inherit the active interrupt state
        log::trace!("Calling timer_tick");
        super::cpu::timer_tick();
    } else {
        match irq {
            #[cfg(feature = "rpi5")]
            RP1_GPIO_IRQ => {
                crate::arch::aarch64::platform::rpi5::gpio::handle_interrupt();
            }
            _ => {
                log::warn!("Unhandled IRQ: {}", irq);
            }
        }
        // Signal end of interrupt for other IRQs
        gic::end_of_interrupt(iar);
    }
}

/// Handle timer interrupt (without rescheduling)
fn handle_timer_interrupt(ctx: &ExceptionContext) {
    // log::info!("Timer interrupt started");
    // Clear and reset timer for next interrupt
    clear_timer_interrupt();
    set_next_timer();

    // Run BPF hooks (AttachType::Timer = 1)
    //
    // We clone programs and release the lock BEFORE execution so that BPF
    // helpers (e.g. bpf_ringbuf_output) can re-acquire the lock for map
    // operations without deadlocking.
    if let Some(manager) = crate::BPF_MANAGER.get() {
        let programs = manager.lock().get_hook_programs(1);

        // Calculate interrupt latency from vector entry to now
        let mut bpf_ctx = kernel_bpf::execution::BpfContext::empty();

        // Include kernel metrics if available
        if let Some(metrics) = crate::BOOT_METRICS.get() {
            bpf_ctx.boot_time_ms = metrics.boot_time_ms;
            bpf_ctx.kernel_heap_kb = metrics.kernel_heap_kb;
            bpf_ctx.kernel_image_mb = metrics.kernel_image_mb;
        }

        unsafe {
            let now: u64;
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) now);
            let latency_ticks = now.saturating_sub(ctx.vector_entry_timestamp);

            // Convert ticks to nanoseconds: ns = ticks * 1,000,000,000 / freq
            let freq: u64;
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
            bpf_ctx.interrupt_latency_ns =
                (latency_ticks as u128 * 1_000_000_000 / freq as u128) as u64;
        }

        for (prog_id, program) in &programs {
            match crate::bpf::BpfManager::execute_program(program, &bpf_ctx) {
                Ok(_res) => {}
                Err(e) => log::error!("BPF Timer Hook [id={}] failed: {:?}", prog_id, e),
            }
        }
    }
}

/// Clear timer interrupt
fn clear_timer_interrupt() {
    // SAFETY: Writing to CNTP_CTL_EL0 is safe in EL1/EL0. Disabling the timer clears the interrupt.
    unsafe {
        // Disable timer to clear interrupt
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 0u64);
    }
}

/// Set next timer interrupt
fn set_next_timer() {
    // SAFETY: Accessing timer registers (CNTP_*) is safe in EL1. We are configuring the
    // non-secure physical timer for the next scheduler tick.
    unsafe {
        // Read timer frequency
        let cntfrq: u64;
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq);

        // Read current physical counter value. This must match CNTP_* timer state.
        let cntpct: u64;
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) cntpct);

        // Set timer to fire in 10ms (100 Hz)
        let interval = cntfrq / 100;
        let next = cntpct + interval;

        // Write compare value
        core::arch::asm!("msr cntp_cval_el0, {}", in(reg) next);

        // Enable timer (bit 0 = enable, bit 1 = mask output)
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
    }
}

/// Initialize timer
pub fn init_timer() {
    set_next_timer();
    log::debug!("ARM generic timer initialized (100 Hz)");
}

/// End of interrupt (public wrapper)
pub fn end_of_interrupt(irq_id: u32) {
    gic::end_of_interrupt(irq_id);
}
