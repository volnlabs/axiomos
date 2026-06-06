use core::arch::asm;
#[cfg(feature = "rpi5")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "rpi5")]
static PREEMPT_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static SYNC_ENTRY_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static SYNC_DECODE_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static SVC_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static SVC_ENTER_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static SVC_RETURN_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static DATA_ABORT_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static INSTR_ABORT_MARKER_SENT: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "rpi5")]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    const UART_BASE: usize = 0xFFFF_8010_7D00_1000;
    const UART_FR: usize = UART_BASE + 0x18;
    const UART_TXFF: u32 = 1 << 5;
    // SAFETY: Accessing the debug UART registers via the higher-half alias.
    unsafe {
        // Pace writes so marker bursts are not dropped when TX FIFO is full.
        while (UART_FR as *const u32).read_volatile() & UART_TXFF != 0 {}
        (UART_BASE as *mut u32).write_volatile(_ch);
    }
}

#[cfg(feature = "rpi5")]
#[inline(always)]
fn dbg_hex_nibble(v: u64) -> u32 {
    match (v & 0xF) as u8 {
        0..=9 => (b'0' + (v as u8 & 0xF)) as u32,
        10..=15 => (b'A' + ((v as u8 & 0xF) - 10)) as u32,
        _ => b'?' as u32,
    }
}

#[cfg(feature = "rpi5")]
#[inline(always)]
fn dbg_hex_u32(v: u32) {
    for shift in (0..8).rev() {
        dbg_mark(dbg_hex_nibble((v as u64) >> (shift * 4)));
    }
}

#[cfg(feature = "rpi5")]
#[inline(always)]
fn dbg_hex_u64(v: u64) {
    for shift in (0..16).rev() {
        dbg_mark(dbg_hex_nibble(v >> (shift * 4)));
    }
}

#[cfg(feature = "rpi5")]
#[inline(always)]
fn el0_va_to_pa(va: u64) -> Option<usize> {
    let par: u64;
    // SAFETY: AT+PAR_EL1 only probes translation state and does not dereference
    // the provided VA; this avoids taking nested faults while debugging.
    unsafe {
        asm!("at s1e0r, {}", in(reg) va);
        asm!("isb");
        asm!("mrs {}, par_el1", out(reg) par);
    }

    // PAR_EL1[0] == 1 indicates translation fault.
    if (par & 1) != 0 {
        return None;
    }

    // PAR_EL1 provides PA[47:12] on success; preserve original page offset.
    let pa = ((par as usize) & 0x0000_FFFF_FFFF_F000) | ((va as usize) & 0xFFF);
    Some(pa)
}

#[cfg(feature = "rpi5")]
#[inline(always)]
fn read_u32_at_el0_va(va: u64) -> Option<u32> {
    let pa = el0_va_to_pa(va)?;
    let kva = crate::arch::aarch64::mem::phys_to_virt(pa);
    // SAFETY: `kva` is the direct-map alias of translated physical memory.
    // We only use this for crash-time telemetry.
    let word = unsafe { (kva as *const u32).read_volatile() };
    Some(word)
}

#[cfg(feature = "rpi5")]
#[inline(always)]
fn current_ttbr0_el1() -> u64 {
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0);
    }
    ttbr0
}

/// Exception vector table
#[repr(C, align(2048))]
pub struct ExceptionVectorTable {
    // Current EL with SP0
    curr_el_sp0_sync: [u8; 128],
    curr_el_sp0_irq: [u8; 128],
    curr_el_sp0_fiq: [u8; 128],
    curr_el_sp0_serror: [u8; 128],

    // Current EL with SPx
    curr_el_spx_sync: [u8; 128],
    curr_el_spx_irq: [u8; 128],
    curr_el_spx_fiq: [u8; 128],
    curr_el_spx_serror: [u8; 128],

    // Lower EL using AArch64
    lower_el_aarch64_sync: [u8; 128],
    lower_el_aarch64_irq: [u8; 128],
    lower_el_aarch64_fiq: [u8; 128],
    lower_el_aarch64_serror: [u8; 128],

    // Lower EL using AArch32
    lower_el_aarch32_sync: [u8; 128],
    lower_el_aarch32_irq: [u8; 128],
    lower_el_aarch32_fiq: [u8; 128],
    lower_el_aarch32_serror: [u8; 128],
}

/// Initialize exception vector table
pub fn init_exception_vector() {
    // SAFETY: We are writing to the VBAR_EL1 system register to set the exception vector table base address.
    // The address is derived from a valid linker symbol.
    unsafe {
        let vbar = exception_vector_base as *const () as u64;
        log::info!("Initializing AArch64 exception vector table at {:#x}", vbar);
        asm!("msr vbar_el1, {}", in(reg) vbar);
    }
}

// Exception vector base (defined in assembly)
// SAFETY: External symbol defined in assembly (exceptions.S).
unsafe extern "C" {
    fn exception_vector_base();
}

/// Check for preemption and reschedule if necessary
///
/// This is called from the exception return path. Assembly passes `sp`
/// (the exception frame pointer) in x0 to satisfy the ABI, but we do
/// not currently need it.
#[unsafe(no_mangle)]
pub extern "C" fn check_preemption(_frame: *mut ExceptionContext) {
    if let Some(ctx) = crate::arch::aarch64::cpu::try_current() {
        if ctx.check_and_clear_reschedule() {
            #[cfg(feature = "rpi5")]
            if !PREEMPT_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'r' as u32);
            }

            // SAFETY: We are in the exception return path, interrupts are disabled.
            // It is safe to call reschedule here as we haven't started restoring registers yet.
            unsafe {
                ctx.scheduler_mut().reschedule();
            }
        }
    }
}

/// Synchronous exception handler
///
/// # Safety
///
/// This function is the exception handler entry point for synchronous exceptions
/// (SVC, Aborts, etc.). It is called from the vector table with register state
/// saved on the stack. It must not unwind.
#[unsafe(no_mangle)]
pub extern "C" fn handle_sync_exception(ctx: &mut ExceptionContext) {
    #[cfg(feature = "rpi5")]
    if !SYNC_ENTRY_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'j' as u32);
    }

    let esr: u64;
    let elr: u64;
    let far: u64;
    #[allow(unused_variables)]
    let spsr: u64;

    // SAFETY: Reading exception registers (ESR, ELR, FAR) is safe in an exception handler.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr);
        asm!("mrs {}, elr_el1", out(reg) elr);
        asm!("mrs {}, far_el1", out(reg) far);
        asm!("mrs {}, spsr_el1", out(reg) spsr);
    }

    let ec = (esr >> 26) & 0x3F; // Exception class
    let iss = esr & 0x1FFFFFF; // Instruction specific syndrome

    #[cfg(feature = "rpi5")]
    if !SYNC_DECODE_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'k' as u32);
    }

    #[cfg(not(feature = "rpi5"))]
    log::debug!(
        "Sync exception: EC={:#x}, ISS={:#x}, ELR={:#x}, FAR={:#x}",
        ec,
        iss,
        elr,
        far
    );

    match ec {
        0x15 => {
            // SVC instruction execution in AArch64 state
            #[cfg(feature = "rpi5")]
            if !SVC_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'V' as u32);
            }
            #[cfg(feature = "rpi5")]
            if !SVC_ENTER_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'l' as u32);
            }
            crate::arch::aarch64::syscall::handle_syscall(ctx);
            #[cfg(feature = "rpi5")]
            if !SVC_RETURN_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'm' as u32);
            }
        }
        0x20 | 0x21 => {
            // Instruction abort from lower/same EL
            #[cfg(feature = "rpi5")]
            if !INSTR_ABORT_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'I' as u32);
            }
            panic!("Instruction abort at {:#x}, far: {:#x}", elr, far);
        }
        0x24 | 0x25 => {
            // Data abort from lower/same EL
            #[cfg(feature = "rpi5")]
            if !DATA_ABORT_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'D' as u32);
            }
            handle_data_abort(elr, far, iss);
        }
        _ => {
            #[cfg(feature = "rpi5")]
            {
                // Unhandled sync exception class: emit Y + two hex digits of EC.
                dbg_mark(b'Y' as u32);
                dbg_mark(dbg_hex_nibble(ec >> 4));
                dbg_mark(dbg_hex_nibble(ec));

                // Emit full ELR/ESR/SPSR/FAR to avoid ambiguity about EL0 vs EL1 faults.
                dbg_mark(b'E' as u32);
                dbg_hex_u64(elr);
                dbg_mark(b'R' as u32);
                dbg_hex_u64(esr);
                dbg_mark(b'P' as u32);
                dbg_hex_u64(spsr);
                dbg_mark(b'F' as u32);
                dbg_hex_u64(far);

                dbg_mark(b'T' as u32);
                dbg_hex_u64(current_ttbr0_el1());

                if let Some(ctx) = crate::arch::aarch64::cpu::try_current() {
                    let pid = ctx.current_task().process().pid().as_u64();
                    dbg_mark(b'Q' as u32);
                    dbg_hex_u64(pid);
                }

                // Emit instruction words at ELR/ELR+4 and full SP_EL0 from saved context.
                let insn0 = read_u32_at_el0_va(elr).unwrap_or(0xFFFF_FFFF);
                let insn1 = read_u32_at_el0_va(elr.wrapping_add(4)).unwrap_or(0xFFFF_FFFF);
                dbg_mark(b'I' as u32);
                dbg_hex_u32(insn0);
                dbg_mark(b'J' as u32);
                dbg_hex_u32(insn1);
                dbg_mark(b'S' as u32);
                dbg_hex_u64(ctx.sp_el0);

                dbg_mark(b'!' as u32);

                // Stop after first unknown-sync packet so UART output remains analyzable.
                loop {
                    // SAFETY: WFI in exception context is safe for a debug halt loop.
                    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
                }
            }
            #[cfg(not(feature = "rpi5"))]
            panic!(
                "Unhandled synchronous exception: EC={:#x}, ISS={:#x}, ELR={:#x}",
                ec, iss, elr
            );
        }
    }
}

/// Data Fault Status Code (DFSC) - bits [5:0] of ISS
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum DataFaultCode {
    // Translation faults (page not mapped)
    TranslationFaultL0 = 0b000100,
    TranslationFaultL1 = 0b000101,
    TranslationFaultL2 = 0b000110,
    TranslationFaultL3 = 0b000111,

    // Access flag faults
    AccessFlagFaultL1 = 0b001001,
    AccessFlagFaultL2 = 0b001010,
    AccessFlagFaultL3 = 0b001011,

    // Permission faults
    PermissionFaultL1 = 0b001101,
    PermissionFaultL2 = 0b001110,
    PermissionFaultL3 = 0b001111,

    // Alignment fault
    AlignmentFault = 0b100001,

    // Synchronous External Abort
    SyncExternalAbort = 0b010000,
}

impl DataFaultCode {
    fn from_iss(iss: u64) -> Option<Self> {
        let dfsc = (iss & 0x3F) as u8;
        match dfsc {
            0b000100 => Some(Self::TranslationFaultL0),
            0b000101 => Some(Self::TranslationFaultL1),
            0b000110 => Some(Self::TranslationFaultL2),
            0b000111 => Some(Self::TranslationFaultL3),
            0b001001 => Some(Self::AccessFlagFaultL1),
            0b001010 => Some(Self::AccessFlagFaultL2),
            0b001011 => Some(Self::AccessFlagFaultL3),
            0b001101 => Some(Self::PermissionFaultL1),
            0b001110 => Some(Self::PermissionFaultL2),
            0b001111 => Some(Self::PermissionFaultL3),
            0b100001 => Some(Self::AlignmentFault),
            0b010000 => Some(Self::SyncExternalAbort),
            _ => None,
        }
    }

    fn is_translation_fault(&self) -> bool {
        matches!(
            self,
            Self::TranslationFaultL0
                | Self::TranslationFaultL1
                | Self::TranslationFaultL2
                | Self::TranslationFaultL3
        )
    }

    fn is_permission_fault(&self) -> bool {
        matches!(
            self,
            Self::PermissionFaultL1 | Self::PermissionFaultL2 | Self::PermissionFaultL3
        )
    }
}

fn try_handle_copy_on_write_fault(far: u64, is_write: bool) -> Result<bool, &'static str> {
    if !is_write {
        return Ok(false);
    }

    let current_process = crate::mcore::context::ExecutionContext::load().current_process();
    let page_vaddr = crate::arch::types::VirtAddr::new(far).align_down(4096);
    let page =
        crate::arch::types::Page::<crate::arch::types::Size4KiB>::containing_address(page_vaddr);

    let (phys, flags) = current_process
        .with_address_space(|as_| as_.translate_page_flags(page_vaddr))
        .ok_or("fault page not mapped")?;

    if !flags.contains(crate::arch::types::PageTableFlags::COPY_ON_WRITE) {
        return Ok(false);
    }

    let mut writable_flags = flags;
    writable_flags.remove(crate::arch::types::PageTableFlags::COPY_ON_WRITE);
    writable_flags.insert(crate::arch::types::PageTableFlags::WRITABLE);

    let old_frame =
        crate::arch::types::PhysFrame::<crate::arch::types::Size4KiB>::containing_address(phys);

    if crate::mem::phys::PhysicalMemory::frame_ref_count(old_frame) == Some(1) {
        current_process
            .with_address_space(|as_| as_.remap(page, |_| writable_flags))
            .map_err(|_| "failed to upgrade COW page in place")?;
        return Ok(true);
    }

    let new_frame =
        crate::mem::phys::PhysicalMemory::allocate_frame::<crate::arch::types::Size4KiB>()
            .ok_or("out of physical memory during COW fault")?;

    unsafe {
        let src =
            crate::mem::phys_to_virt(old_frame.start_address().as_u64() as usize) as *const u8;
        let dst = crate::mem::phys_to_virt(new_frame.start_address().as_u64() as usize) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, 4096);
    }

    current_process
        .with_address_space(|as_| {
            as_.unmap(page).ok_or("failed to unmap old COW page")?;
            as_.map(page, new_frame, writable_flags)
        })
        .map_err(|_| "failed to remap private writable page after COW fault")?;

    crate::mem::phys::PhysicalMemory::deallocate_frame(old_frame);

    Ok(true)
}

fn handle_data_abort(elr: u64, far: u64, iss: u64) {
    let is_write = (iss & (1 << 6)) != 0; // WnR bit
    let _is_cm = (iss & (1 << 8)) != 0; // Cache maintenance
    let _is_s1ptw = (iss & (1 << 7)) != 0; // Stage 1 page table walk

    let fault_code = DataFaultCode::from_iss(iss);

    #[cfg(feature = "rpi5")]
    {
        // Emit compact abort telemetry so we can decode failures even when panic text is truncated.
        dbg_mark(b'X' as u32); // ELR
        dbg_hex_u64(elr);
        dbg_mark(b'Y' as u32); // FAR
        dbg_hex_u64(far);
        dbg_mark(if is_write { b'W' as u32 } else { b'R' as u32 }); // access type
        dbg_mark(b'Z' as u32); // DFSC (ISS[5:0]) as two hex nibbles
        dbg_mark(dbg_hex_nibble((iss >> 4) & 0xF));
        dbg_mark(dbg_hex_nibble(iss & 0xF));
    }

    log::debug!(
        "Data abort: PC={:#x}, addr={:#x}, write={}, dfsc={:?}",
        elr,
        far,
        is_write,
        fault_code
    );

    // Check if this is a kernel or user address
    let is_kernel_addr = far >= 0xFFFF_0000_0000_0000;

    match fault_code {
        Some(code) if code.is_translation_fault() => {
            // Page not mapped - this is a page fault
            if is_kernel_addr {
                // Kernel page fault - this is fatal
                panic!(
                    "Kernel page fault at PC={:#x}, address={:#x}, write={}",
                    elr, far, is_write
                );
            } else {
                // User page fault - could be demand paging
                // For now, just panic as we don't have userspace yet
                panic!(
                    "User page fault at PC={:#x}, address={:#x}, write={}",
                    elr, far, is_write
                );

                // TODO: Implement demand paging
                // 1. Check if address is in valid VMA
                // 2. Allocate physical page
                // 3. Map page with appropriate permissions
                // 4. Return to faulting instruction
            }
        }
        Some(code) if code.is_permission_fault() => {
            // Permission denied
            if is_kernel_addr {
                panic!(
                    "Kernel permission fault at PC={:#x}, address={:#x}, write={}",
                    elr, far, is_write
                );
            } else {
                match try_handle_copy_on_write_fault(far, is_write) {
                    Ok(true) => return,
                    Ok(false) => {}
                    Err(err) => {
                        log::error!("copy-on-write fault handling failed: {}", err);
                    }
                }

                // Could be copy-on-write
                panic!(
                    "User permission fault at PC={:#x}, address={:#x}, write={}",
                    elr, far, is_write
                );

                // TODO: Implement COW
                // 1. Check if this is a COW page
                // 2. If COW and write, copy page and remap as writable
                // 3. Otherwise, send SIGSEGV to process
            }
        }
        Some(DataFaultCode::AlignmentFault) => {
            panic!("Alignment fault at PC={:#x}, address={:#x}", elr, far);
        }
        Some(DataFaultCode::SyncExternalAbort) => {
            panic!(
                "Synchronous External Abort at PC={:#x}, address={:#x}",
                elr, far
            );
        }
        Some(code) => {
            // Access flag faults - need to set AF bit
            log::warn!(
                "Access flag fault {:?} at PC={:#x}, address={:#x}",
                code,
                elr,
                far
            );
            // For now, panic
            panic!("Access flag fault not yet handled");
        }
        None => {
            let dfsc = iss & 0x3F;
            panic!(
                "Unknown data abort: PC={:#x}, address={:#x}, DFSC={:#x}",
                elr, far, dfsc
            );
        }
    }
}

// IRQ handler is defined in interrupts.rs module
// (Re-exported through assembly vector table)

/// FIQ handler
///
/// # Safety
///
/// This function is the Fast Interrupt Request (FIQ) handler.
/// It is called from the vector table. It must not unwind.
#[unsafe(no_mangle)]
pub extern "C" fn handle_fiq() {
    log::error!("FIQ received! Registers might be in an inconsistent state.");
}

/// SError handler
///
/// # Safety
///
/// This function is the System Error (SError) handler.
/// It is called from the vector table. It must not unwind.
#[unsafe(no_mangle)]
pub extern "C" fn handle_serror() {
    let esr: u64;
    let elr: u64;
    let far: u64;

    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr);
        asm!("mrs {}, elr_el1", out(reg) elr);
        asm!("mrs {}, far_el1", out(reg) far);
    }

    log::error!(
        "SError received! ESR={:#x}, ELR={:#x}, FAR={:#x}",
        esr,
        elr,
        far
    );
    panic!("SError received");
}

/// Invalid exception handler (called for unhandled vectors)
#[unsafe(no_mangle)]
pub extern "C" fn handle_invalid_exception(kind: u64, source: u64) {
    #[cfg(feature = "rpi5")]
    {
        // Invalid vector taken: emit N + kind + source (low nibble each).
        dbg_mark(b'N' as u32);
        dbg_mark(dbg_hex_nibble(kind));
        dbg_mark(dbg_hex_nibble(source));
    }
    let esr: u64;
    let elr: u64;
    let far: u64;

    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr);
        asm!("mrs {}, elr_el1", out(reg) elr);
        asm!("mrs {}, far_el1", out(reg) far);
    }

    log::error!(
        "Invalid exception: kind={}, source={}, ESR={:#x}, ELR={:#x}, FAR={:#x}",
        kind,
        source,
        esr,
        elr,
        far
    );

    panic!(
        "Invalid exception: kind={}, source={}, ESR={:#x}, ELR={:#x}, FAR={:#x}",
        kind, source, esr, elr, far
    );
}

/// Exception context saved on exception entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionContext {
    // General purpose registers
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64, // Frame pointer
    pub x30: u64, // Link register

    // Exception state
    pub elr: u64,    // Exception link register
    pub spsr: u64,   // Saved program status register
    pub sp_el0: u64, // User stack pointer (saved from SP_EL0)

    /// Timestamp captured at the very beginning of the exception vector entry.
    /// Used for interrupt latency benchmarking.
    pub vector_entry_timestamp: u64,
}
