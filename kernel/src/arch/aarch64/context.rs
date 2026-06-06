//! ARM64 Context Switching
//!
//! Implements task context switching for ARM64. Uses a stack-based approach
//! where callee-saved registers are saved to the current stack, then SP is
//! switched to the new task's stack and registers are restored.
//!
//! Callee-saved registers on ARM64 (AAPCS64):
//! - x19-x28: General purpose callee-saved
//! - x29 (FP): Frame pointer
//! - x30 (LR): Link register (return address)
//! - SP: Stack pointer
//! - NZCV flags (in PSTATE, but we don't need to save these explicitly)

use core::arch::asm;

/// Saved register frame on the stack during context switch
///
/// This structure is pushed/popped during switch_context.
/// Must match the assembly in switch_impl exactly.
#[repr(C)]
pub struct SwitchFrame {
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
    pub x30: u64, // Link register (return address)
}

impl SwitchFrame {
    /// Size of the switch frame in bytes
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Perform a context switch from one task to another
///
/// # Arguments
/// * `old_sp_ptr` - Pointer to where the old stack pointer should be saved
/// * `new_sp` - The new stack pointer to load
/// * `new_ttbr0` - The new TTBR0 value (user page table), or 0 to keep current
///
/// # Safety
///
/// The caller must ensure:
/// - `old_sp_ptr` points to valid, writable memory for storing a usize
/// - `new_sp` points to a valid stack with a properly initialized SwitchFrame
/// - `new_ttbr0` is either 0 or a valid page table physical address
/// - This function is only called from the scheduler with proper locking
///
/// `naked` attribute is used because we strictly control the stack layout and
/// register saving/restoring in assembly.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_impl(_old_sp_ptr: *mut usize, _new_sp: usize, _new_ttbr0: usize) {
    // x0 = old_sp_ptr (pointer to save current SP)
    // x1 = new_sp (new stack pointer value)
    // x2 = new_ttbr0 (new page table, 0 = don't switch)
    core::arch::naked_asm!(
        // Save callee-saved registers to current stack
        // We save 12 registers (96 bytes), must be 16-byte aligned
        "stp x29, x30, [sp, #-16]!",
        "stp x27, x28, [sp, #-16]!",
        "stp x25, x26, [sp, #-16]!",
        "stp x23, x24, [sp, #-16]!",
        "stp x21, x22, [sp, #-16]!",
        "stp x19, x20, [sp, #-16]!",
        // Save current SP to *old_sp_ptr
        "mov x9, sp",
        "str x9, [x0]",
        // Load new SP
        "mov sp, x1",
        // Switch page tables if new_ttbr0 != 0
        "cbz x2, 1f",
        "msr ttbr0_el1, x2",
        "isb",
        "tlbi vmalle1is",
        "dsb ish",
        "isb",
        "1:",
        // We ALSO need to switch sp_el0 because it's a system register that
        // is NOT part of the callee-saved set on the stack, but IS task-local.
        // However, sp_el0 is typically saved/restored in the exception entry/exit.
        // If we switch tasks via switch_impl (kernel context switch), we are
        // already in the kernel. The sp_el0 currently in the register belongs
        // to the old task. If we don't save it here, and the new task didn't
        // come from an exception (e.g. it's a new task), it might be wrong.
        // Actually, for AArch64, we rely on the fact that any task that was
        // running in userspace HAS its sp_el0 saved in its ExceptionContext on its
        // kernel stack. When we switch kernel stacks here, we are switching
        // to the new task's kernel stack. When THAT task eventually returns
        // to userspace via eret (in restore_context), it will load its own
        // sp_el0 from its own stack.
        // So switch_impl doesn't strictly NEED to touch sp_el0 if ALL userspace
        // entries/exits go through the exception path.

        // Restore callee-saved registers from new stack
        "ldp x19, x20, [sp], #16",
        "ldp x21, x22, [sp], #16",
        "ldp x23, x24, [sp], #16",
        "ldp x25, x26, [sp], #16",
        "ldp x27, x28, [sp], #16",
        "ldp x29, x30, [sp], #16",
        // Return to new task (x30/LR has the return address)
        "ret",
    );
}

/// Initialize a stack for a new task
///
/// Sets up the initial stack frame so that when switch_impl switches to this
/// task, it will "return" to the entry point.
///
/// # Arguments
/// * `stack_top` - Top of the allocated stack (highest address)
/// * `entry_point` - Function to execute when task starts
/// * `arg` - Argument to pass to the entry function (in x0)
///
/// # Returns
/// The initial stack pointer value to use for this task
pub fn init_task_stack(stack_top: usize, entry_point: usize, arg: usize) -> usize {
    // Stack must be 16-byte aligned
    let stack_top = stack_top & !0xF;

    let frame_ptr = (stack_top - SwitchFrame::SIZE) as *mut SwitchFrame;

    // SAFETY: frame_ptr points to memory within the allocated stack. The stack
    // was allocated with sufficient size and proper alignment. We have exclusive
    // access to this stack memory as it's being initialized for a new task.
    unsafe {
        let frame = &mut *frame_ptr;

        // Zero all callee-saved registers
        frame.x19 = 0;
        frame.x20 = 0;
        frame.x21 = 0;
        frame.x22 = 0;
        frame.x23 = 0;
        frame.x24 = 0;
        frame.x25 = 0;
        frame.x26 = 0;
        frame.x27 = 0;
        frame.x28 = 0;
        frame.x29 = 0; // Frame pointer

        // x30 (LR) = entry point - this is where switch_impl will "return" to
        frame.x30 = entry_point as u64;

        // Store arg in x19 - the trampoline will move it to x0
        frame.x19 = arg as u64;
    }

    frame_ptr as usize
}

/// Task entry trampoline
///
/// This is the first code executed by a new task after context switch.
/// It moves the argument from x19 to x0, sets up the return address (LR)
/// to the exit function (in x21), and jumps to the actual entry point (in x20).
///
/// # Safety
///
/// This function must only be jumped to from a properly initialized SwitchFrame.
///
/// `naked` attribute is used because this is a trampoline that doesn't follow
/// standard C calling convention.
#[unsafe(naked)]
#[cfg(feature = "rpi5")]
pub unsafe extern "C" fn task_entry_trampoline() {
    core::arch::naked_asm!(
        // Marker: reached task entry trampoline.
        "movz x9, #0x1000",
        "movk x9, #0x7d00, lsl #16",
        "movk x9, #0x0010, lsl #32",
        "mov w10, #0x54", // 'T'
        "str w10, [x9]",
        // Enable interrupts
        "msr daifclr, #2",
        // x19 contains the argument
        // x20 contains the actual entry point
        // x21 contains the exit function
        "mov x0, x19",
        "mov x30, x21", // Set LR to exit function
        // Marker: branching to actual task entry point.
        "mov w10, #0x55", // 'U'
        "str w10, [x9]",
        "br x20",
    );
}

#[unsafe(naked)]
#[cfg(not(feature = "rpi5"))]
pub unsafe extern "C" fn task_entry_trampoline() {
    core::arch::naked_asm!(
        // Enable interrupts
        "msr daifclr, #2",
        // x19 contains the argument
        // x20 contains the actual entry point
        // x21 contains the exit function
        "mov x0, x19",
        "mov x30, x21", // Set LR to exit function
        "br x20",
    );
}

/// Initialize a stack for a new task with trampoline
///
/// Like init_task_stack but uses a trampoline to properly pass the argument.
pub fn init_task_stack_with_arg(
    stack_top: usize,
    entry_point: usize,
    arg: usize,
    exit_point: usize,
) -> usize {
    let stack_top = stack_top & !0xF;
    let frame_ptr = (stack_top - SwitchFrame::SIZE) as *mut SwitchFrame;

    // SAFETY: frame_ptr points to memory within the allocated stack. The stack
    // was allocated with sufficient size and proper alignment. We have exclusive
    // access to this stack memory as it's being initialized for a new task.
    unsafe {
        let frame = &mut *frame_ptr;

        // x19 = argument (will be moved to x0 by trampoline)
        frame.x19 = arg as u64;
        // x20 = actual entry point (trampoline will branch to this)
        frame.x20 = entry_point as u64;
        // x21 = exit function (trampoline will set LR to this)
        frame.x21 = exit_point as u64;

        // Zero other registers
        frame.x22 = 0;
        frame.x23 = 0;
        frame.x24 = 0;
        frame.x25 = 0;
        frame.x26 = 0;
        frame.x27 = 0;
        frame.x28 = 0;
        frame.x29 = 0;

        // x30 (LR) = trampoline - switch_impl returns here
        frame.x30 = task_entry_trampoline as *const () as usize as u64;
    }

    frame_ptr as usize
}

/// Enter userspace
///
/// Restores state to enter EL0 (userspace).
///
/// # Safety
/// Caller must ensure `entry_point` and `stack_pointer` are valid for userspace.
pub unsafe fn enter_userspace(entry_point: usize, stack_pointer: usize) -> ! {
    // SPSR_EL1 for EL0 entry:
    // M[3:0] = 0000 (EL0t)
    // DAIF = 0000 (Unmasked) -> Interrupts enabled
    // Note: We MUST ensure we are using EL0t, which is mode 0.
    let spsr: u64 = 0;

    #[cfg(feature = "rpi5")]
    // SAFETY: Marker write to Pi 5 debug UART10 via higher-half alias before ERET.
    unsafe {
        (0xFFFF_8010_7D00_1000 as *mut u32).write_volatile(b'X' as u32);
    }

    core::arch::asm!(
        "msr sp_el0, {sp}",
        "msr elr_el1, {entry}",
        "msr spsr_el1, {spsr}",
        "isb",
        "eret",
        sp = in(reg) stack_pointer,
        entry = in(reg) entry_point,
        spsr = in(reg) spsr,
        options(noreturn)
    );
}

/// Get the current stack pointer
#[inline]
pub fn current_sp() -> usize {
    let sp: usize;
    // SAFETY: Reading the stack pointer register is always safe. The nomem and
    // nostack options tell the compiler this doesn't access memory or modify stack.
    unsafe {
        asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
    }
    sp
}

/// Get the current frame pointer
#[inline]
pub fn current_fp() -> usize {
    let fp: usize;
    // SAFETY: Reading x29 (frame pointer) is always safe. The nomem and nostack
    // options tell the compiler this doesn't access memory or modify stack.
    unsafe {
        asm!("mov {}, x29", out(reg) fp, options(nomem, nostack));
    }
    fp
}

/// Get the current link register (return address)
#[inline]
pub fn current_lr() -> usize {
    let lr: usize;
    // SAFETY: Reading x30 (link register) is always safe. The nomem and nostack
    // options tell the compiler this doesn't access memory or modify stack.
    unsafe {
        asm!("mov {}, x30", out(reg) lr, options(nomem, nostack));
    }
    lr
}

/// Restores user context and returns to userspace.
/// Does not return.
///
/// # Safety
/// Valid pointer to UserContext.
#[unsafe(naked)]
pub unsafe extern "C" fn restore_user_context(ctx: *const crate::arch::UserContext) -> ! {
    core::arch::naked_asm!(
        // x0 points to UserContext
        // UserContext layout:
        // inner: ExceptionContext (offset 0, size 280)
        // sp: u64 (offset 280)
        //
        // ExceptionContext tail:
        // elr: offset 248
        // spsr: offset 256
        // sp_el0: offset 264
        // vector_entry_timestamp: offset 272

        // 1. Restore sp_el0
        "ldr x1, [x0, #280]",
        "msr sp_el0, x1",
        // 2. Restore ELR, SPSR
        // elr is at offset 248, spsr at 256
        "ldp x2, x3, [x0, #248]",
        "msr elr_el1, x2",
        "msr spsr_el1, x3",
        // 3. Restore registers
        "ldp x29, x30, [x0, #232]",
        "ldp x27, x28, [x0, #216]",
        "ldp x25, x26, [x0, #200]",
        "ldp x23, x24, [x0, #184]",
        "ldp x21, x22, [x0, #168]",
        "ldp x19, x20, [x0, #152]",
        "ldp x17, x18, [x0, #136]",
        "ldp x15, x16, [x0, #120]",
        "ldp x13, x14, [x0, #104]",
        "ldp x11, x12, [x0, #88]",
        "ldp x9, x10, [x0, #72]",
        "ldp x7, x8, [x0, #56]",
        "ldp x5, x6, [x0, #40]",
        "ldp x3, x4, [x0, #24]",
        "ldp x1, x2, [x0, #8]",
        "ldr x0, [x0]",
        "eret"
    );
}
