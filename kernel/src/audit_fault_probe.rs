#![cfg(all(feature = "audit-fault-injection", target_arch = "x86_64"))]

//! Audit-fault-injection boot probe.
//!
//! Runs once after `QEMU_BOOT_OK` and before `mcore::turn_idle()`, gated
//! by the kernel's `audit-fault-injection` feature. Arms the
//! kernel_physical_memory fault controller through three phases to
//! check the facade's behavior under injected failure:
//!
//! 1. `armed(0, alloc)` — fault fires at the entry checkpoint;
//!    `PhysicalMemory::allocate_frame` returns `None`.
//! 2. **Naked** `PhysicalMemory::allocate_frame` call (no outer armed
//!    scope). Proves Phase 1's RAII drop restored `BUDGET` to its
//!    pre-armed value (`u32::MAX`); a leaked `BUDGET=0` would make the
//!    naked call return `None`. The two Drop stores are independent
//!    atomic operations (not a paired state transition); this probe
//!    does NOT observe `DISARMED` restoration directly, but the
//!    single-CPU boot path used by the audit-gate QEMU smoke makes
//!    that acceptable for this scenario.
//! 3. `armed(2, || { a1; a2; })` — proves the budget math: one
//!    `allocate_frame::<Size4KiB>()` consumes two checkpoints
//!    (entry + pre-mark), so the first succeeds and the second's
//!    entry fires.
//!
//! Every successful `PhysFrame` is deallocated inside its `armed`
//! scope to avoid intentional frame leaks.
//!
//! Emits the following markers via `serial_println`:
//!
//! ```text
//! AUDIT_FAULT_PROBE: start
//! AUDIT_FAULT_PROBE: BUDGET=0 result is_some=false
//! AUDIT_FAULT_PROBE: no-fault result is_some=true
//! AUDIT_FAULT_PROBE: BUDGET=2 first=true second=false
//! AUDIT_FAULT_PROBE: done
//! ```
//!
//! What this probe proves:
//! - `PhysicalMemory::allocate_frame` returns `None` under injection
//!   and remains usable after the armed scope exits.
//! - The two-checkpoint-per-allocate budget math holds.
//!
//! What this probe does NOT yet prove:
//! - A higher-level runtime caller (e.g., a syscall that allocates
//!   memory) translates `None` into a clean `ENOMEM` and the next
//!   request succeeds. That requires the next commit's
//!   `map_range_transaction` rollback extraction.

use kernel::mem::phys::PhysicalMemory;
use kernel::serial_println;
use kernel_physical_memory::fault;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

/// Execute the three-phase audit-fault-injection probe. Emits serial
/// markers expected by the audit-gate QEMU smoke step. Must be called
/// after PMM Stage2 handoff so the allocators route through
/// `PhysicalMemoryManager::allocate_frames_impl` (which carries the
/// controller's two checkpoints).
pub fn run_probe() {
    serial_println!("AUDIT_FAULT_PROBE: start");

    // Phase 1: armed(0). The first checkpoint call (entry of
    // allocate_frame) fires; allocate_frame returns None. Inner
    // closure has no allocation that could leak a frame, but the
    // defensive deallocation pattern is preserved in case a future
    // change adds an allocation before the fault fires.
    let phase1_none = fault::armed(0, || {
        let f = PhysicalMemory::allocate_frame::<Size4KiB>();
        let none = f.is_none();
        if let Some(f) = f {
            PhysicalMemory::deallocate_frame::<Size4KiB>(f);
        }
        none
    });
    serial_println!(
        "AUDIT_FAULT_PROBE: BUDGET=0 result is_some={}",
        if phase1_none { "false" } else { "true" }
    );

    // Phase 2: NAKED call. No `armed(...)` wrapper. Proves Phase 1's
    // RAII drop restored `BUDGET` to its pre-armed value
    // (`u32::MAX`); a leaked `BUDGET=0` would make the naked call's
    // first checkpoint fire and return None.
    let f2: Option<PhysFrame<Size4KiB>> = PhysicalMemory::allocate_frame::<Size4KiB>();
    let recovered = f2.is_some();
    if let Some(f) = f2 {
        PhysicalMemory::deallocate_frame::<Size4KiB>(f);
    }
    serial_println!(
        "AUDIT_FAULT_PROBE: no-fault result is_some={}",
        if recovered { "true" } else { "false" }
    );

    // Phase 3: armed(2). Two checkpoint calls per allocate_frame
    // call (entry + pre-mark), so 2 budget is exactly consumed by one
    // successful allocate_frame. The second allocation's entry
    // checkpoint fires, returning None.
    let (first_some, second_none) = fault::armed(2, || {
        let f1: Option<PhysFrame<Size4KiB>> = PhysicalMemory::allocate_frame::<Size4KiB>();
        let first = f1.is_some();
        if let Some(f) = f1 {
            PhysicalMemory::deallocate_frame::<Size4KiB>(f);
        }
        let f2: Option<PhysFrame<Size4KiB>> = PhysicalMemory::allocate_frame::<Size4KiB>();
        let second = f2.is_none();
        if let Some(f) = f2 {
            PhysicalMemory::deallocate_frame::<Size4KiB>(f);
        }
        (first, second)
    });
    serial_println!(
        "AUDIT_FAULT_PROBE: BUDGET=2 first={} second={}",
        if first_some { "true" } else { "false" },
        if second_none { "false" } else { "true" }
    );

    serial_println!("AUDIT_FAULT_PROBE: done");
}
