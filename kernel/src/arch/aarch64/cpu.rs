//! ARM64 Per-CPU Execution Context
//!
//! Provides per-CPU state storage and access for the scheduler and other
//! CPU-local data. Uses TPIDR_EL1 to store a pointer to the CPU context.

use alloc::boxed::Box;

use crate::mcore::context::ExecutionContext;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 4;

/// Initialize the current CPU's context
///
/// Must be called once per CPU during boot.
pub fn init_current_cpu(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID out of range");

    // Create the ExecutionContext for this CPU
    let ctx = ExecutionContext::new(cpu_id);

    // Leak it to ensure it lives for the lifetime of the kernel
    let ctx_ptr = Box::leak(Box::new(ctx));

    // Store context pointer in TPIDR_EL1
    // SAFETY: Writing to TPIDR_EL1 is safe in EL1. We are storing the pointer to
    // the persistent static per-CPU context structure which remains valid for the
    // entire lifetime of the kernel.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el1, {}",
            in(reg) ctx_ptr,
            options(nostack, preserves_flags)
        );
    }

    log::info!("CPU {} context initialized at {:p}", cpu_id, ctx_ptr);
}

/// Get the current CPU's context
///
/// Returns None if not yet initialized.
pub fn try_current() -> Option<&'static ExecutionContext> {
    ExecutionContext::try_load()
}

/// Get the current CPU's context
///
/// # Panics
/// Panics if CPU context is not initialized.
pub fn current() -> &'static ExecutionContext {
    ExecutionContext::load()
}

/// Get the current CPU ID
pub fn cpu_id() -> usize {
    // Read MPIDR_EL1 to get CPU affinity
    let mpidr: usize;
    // SAFETY: Reading MPIDR_EL1 is safe.
    unsafe {
        core::arch::asm!(
            "mrs {}, mpidr_el1",
            out(reg) mpidr,
            options(nostack, preserves_flags)
        );
    }

    // Aff0 contains the CPU ID for Cortex-A76 (RPi5)
    mpidr & 0xFF
}

/// Reschedule on timer interrupt
///
/// Called from the timer interrupt handler.
pub fn timer_tick() {
    if let Some(ctx) = try_current() {
        log::trace!(
            "timer_tick: setting need_reschedule for CPU {}",
            ctx.cpu_id()
        );
        ctx.set_need_reschedule();
    } else {
        log::warn!("timer_tick: no context for current CPU");
    }
}

/// Synchronize I-cache and D-cache for JIT compilation
///
/// This function performs the necessary barriers and cache maintenance
/// to ensure that instructions written to memory are visible to the
/// instruction fetch unit.
///
/// # Safety
///
/// The caller must ensure that the memory range [start, start + len) is
/// valid and belongs to the JIT code region.
#[no_mangle]
pub unsafe extern "C" fn aarch64_jit_sync_cache(start: usize, len: usize) {
    // Get cache line sizes
    let mut ctr_el0: u64;
    core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr_el0);

    // D-cache line size (in 4-byte words, log2)
    // Field DminLine is bits [19:16]
    // Cache line size in bytes = 4 << DminLine
    let dcache_line_shift = (ctr_el0 >> 16) & 0xF;
    let dcache_line_size = 4usize << dcache_line_shift;

    // I-cache line size (in 4-byte words, log2)
    // Field IminLine is bits [3:0]
    // Cache line size in bytes = 4 << IminLine
    let icache_line_shift = ctr_el0 & 0xF;
    let icache_line_size = 4usize << icache_line_shift;

    let end = start + len;

    // 1. Clean D-cache to PoU
    let mut addr = start & !(dcache_line_size - 1);
    while addr < end {
        core::arch::asm!("dc cvau, {}", in(reg) addr);
        addr += dcache_line_size;
    }

    // 2. DSB
    core::arch::asm!("dsb ish");

    // 3. Invalidate I-cache to PoU
    addr = start & !(icache_line_size - 1);
    while addr < end {
        core::arch::asm!("ic ivau, {}", in(reg) addr);
        addr += icache_line_size;
    }

    // 4. DSB
    core::arch::asm!("dsb ish");

    // 5. ISB
    core::arch::asm!("isb");
}
