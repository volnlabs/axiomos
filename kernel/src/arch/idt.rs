use core::alloc::Layout;
use core::arch::asm;
use core::arch::x86_64::{_fxrstor, _fxsave};
use core::fmt::{Debug, Formatter};
use core::mem::transmute;
use core::sync::atomic::Ordering::Relaxed;

use kernel_memapi::{Guarded, Location, MemoryApi, UserAccessible};
use log::{error, warn};
use x86_64::instructions::hlt;
use x86_64::registers::control::Cr2;
use x86_64::registers::debug::{Dr6, Dr7};
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, InterruptStackFrameValue, PageFaultErrorCode,
};
use x86_64::PrivilegeLevel;

use crate::arch::gdt;
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::task::{FxArea, Task};
use crate::mem::memapi::LowerHalfMemoryApi;
use crate::syscall::dispatch_syscall;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    /// 32
    Timer = 0x20,
    /// 49
    LapicErr = 0x31,
    Syscall = 0x80,
    /// 255
    Spurious = 0xff,
}

impl InterruptIndex {
    pub fn as_usize(self) -> usize {
        self as usize
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub fn create_idt() -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();

    // SAFETY: Setting up the IDT with valid handler functions and stack indices.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        idt.page_fault
            .set_handler_fn(page_fault_handler)
            .set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
    }

    idt.debug.set_handler_fn(debug_handler);
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.device_not_available
        .set_handler_fn(device_not_available_handler);

    idt.general_protection_fault
        .set_handler_fn(general_protection_fault_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.invalid_tss.set_handler_fn(invalid_tss_handler);
    idt.segment_not_present
        .set_handler_fn(segment_not_present_handler);
    idt.stack_segment_fault
        .set_handler_fn(stack_segment_fault_handler);

    idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);
    idt[InterruptIndex::LapicErr.as_u8()].set_handler_fn(lapic_err_interrupt_handler);
    idt[InterruptIndex::Spurious.as_u8()].set_handler_fn(spurious_interrupt_handler);

    // SAFETY: Setting up the syscall handler with the correct privilege level and interrupt handling.
    // Transmuting to the correct function signature is required for the interrupt handler.
    unsafe {
        idt[InterruptIndex::Syscall.as_u8()]
            .set_handler_fn(transmute::<
                *mut fn(),
                extern "x86-interrupt" fn(InterruptStackFrame),
            >(syscall_handler as *mut fn()))
            .set_privilege_level(PrivilegeLevel::Ring3)
            .disable_interrupts(true);
    }

    idt
}

macro_rules! wrap {
    ($fn:ident => $w:ident) => {
        #[allow(clippy::missing_safety_doc)]
        // SAFETY: This is a naked function used as an interrupt wrapper.
        // It manually saves/restores registers and calls the handler.
        // It is only called by the CPU via the IDT.
        #[unsafe(naked)]
        pub unsafe extern "sysv64" fn $w() {
            core::arch::naked_asm!(
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rsi, rsp", // Arg #2: register list
                "mov rdi, rsp", // Arg #1: interupt frame
                "add rdi, 15 * 8", // Skip 15 registers to point to InterruptStackFrame
                "call {}",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rbp",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rbx",
                "pop rax",
                "iretq",
                sym $fn
            );
        }
    };
}

wrap!(syscall_handler_impl => syscall_handler);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GPRegisters {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rbp: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rbx: usize,
    pub rax: usize,
}

pub type SyscallRegisters = GPRegisters;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UserContext {
    pub regs: GPRegisters,
    pub frame: InterruptStackFrameValue,
}

pub extern "sysv64" fn syscall_handler_impl(
    stack_frame: &mut InterruptStackFrame,
    regs: &mut GPRegisters,
) {
    // The registers order follow the System V ABI convention
    let n = regs.rax;
    let arg1 = regs.rdi;
    let arg2 = regs.rsi;
    let arg3 = regs.rdx;
    let arg4 = regs.rcx;
    let arg5 = regs.r8;
    let arg6 = regs.r9;

    // Construct UserContext for dispatch_syscall (needed for fork)
    // We clone the frame value because InterruptStackFrame is a wrapper around a pointer
    let mut ctx = UserContext {
        regs: *regs,
        frame: **stack_frame,
    };

    let result = dispatch_syscall(&mut ctx, n, arg1, arg2, arg3, arg4, arg5, arg6);

    ctx.regs.rax = result as usize;
    *regs = ctx.regs;

    // SAFETY: `ctx.frame` originated from this interrupt frame and syscall
    // dispatch only applies kernel-validated return-context changes (e.g. execve).
    // The x86_64 API requires volatile mutation so LLVM preserves the writeback.
    unsafe {
        stack_frame.as_mut().update(|frame| *frame = ctx.frame);
    }
}

fn exception_from_user_mode(stack_frame: &InterruptStackFrame) -> bool {
    stack_frame.code_segment.rpl() == PrivilegeLevel::Ring3
}

fn terminate_current_task_on_user_exception(exception: &str, stack_frame: &InterruptStackFrame) {
    if !exception_from_user_mode(stack_frame) {
        return;
    }

    let Some(ctx) = ExecutionContext::try_load() else {
        return;
    };
    let task = ctx.current_task();
    error!(
        "{exception} from user mode in process '{}' task '{}', terminating...\n{stack_frame:#?}",
        task.process().name(),
        task.name(),
    );
    Task::exit();
}

/// Restores the user context and returns to userspace.
///
/// # Safety
/// This function executes an `iretq` instruction with values derived from `ctx`.
/// The caller must ensure `ctx` contains valid values for a return to userspace.
#[unsafe(naked)]
pub unsafe extern "sysv64" fn restore_user_context(ctx: *const UserContext) -> ! {
    core::arch::naked_asm!(
        // rdi holds pointer to UserContext
        // Layout:
        // GPRegisters (15 * 8 = 120 bytes)
        // InterruptStackFrameValue (5 * 8 = 40 bytes)

        // 1. Push InterruptStackFrameValue fields onto stack for iretq
        // We push in reverse order: SS, RSP, RFLAGS, CS, RIP

        // SS (offset 120 + 32)
        "mov rax, [rdi + 152]",
        "push rax",
        // RSP (offset 120 + 24)
        "mov rax, [rdi + 144]",
        "push rax",
        // RFLAGS (offset 120 + 16)
        "mov rax, [rdi + 136]",
        "push rax",
        // CS (offset 120 + 8)
        "mov rax, [rdi + 128]",
        "push rax",
        // RIP (offset 120 + 0)
        "mov rax, [rdi + 120]",
        "push rax",
        // 2. Restore General Purpose Registers
        // Offsets match GPRegisters struct definition
        "mov rax, [rdi + 112]",
        "mov rbx, [rdi + 104]",
        "mov rcx, [rdi + 96]",
        "mov rdx, [rdi + 88]",
        "mov rsi, [rdi + 80]",
        // Skip rdi (72) for now, it holds our pointer
        "mov rbp, [rdi + 64]",
        "mov r8,  [rdi + 56]",
        "mov r9,  [rdi + 48]",
        "mov r10, [rdi + 40]",
        "mov r11, [rdi + 32]",
        "mov r12, [rdi + 24]",
        "mov r13, [rdi + 16]",
        "mov r14, [rdi + 8]",
        "mov r15, [rdi + 0]",
        // Restore rdi last
        "mov rdi, [rdi + 72]",
        // 3. Return to userspace
        "iretq"
    );
}

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // 1. Acknowledge interrupt first
    // SAFETY: We are acknowledging the interrupt to the LAPIC.
    // Safe because we are in an interrupt handler.
    unsafe {
        end_of_interrupt();
    }

    // 2. Resolve the bounded hook snapshot without heap allocation, then run
    // outside the manager lock so map helpers can re-acquire it.
    let bpf_ctx = kernel_bpf::execution::BpfContext::empty();
    let _ =
        crate::bpf::BpfManager::run_hook_programs(crate::bpf::ATTACH_TYPE_TIMER, &bpf_ctx, "timer");

    // 3. Schedule next task
    let ctx = ExecutionContext::load();
    // SAFETY: Rescheduling is safe here as we are in an interrupt handler
    // and the scheduler handles context switching.
    unsafe {
        ctx.scheduler_mut().reschedule();
    }
}

extern "x86-interrupt" fn lapic_err_interrupt_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: LAPIC ERROR\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn spurious_interrupt_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: SPURIOUS INTERRUPT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(stack_frame: InterruptStackFrame, _: u64) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT:\n{stack_frame:#?}");
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    terminate_current_task_on_user_exception("GENERAL PROTECTION FAULT", &stack_frame);
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT:\nerror code: {error_code:#X}\n{}[{}], external: {}\n{stack_frame:#?}",
        match (error_code >> 1) & 0b11 {
            0 => "GDT",
            2 => "LDT",
            _ => "IDT",
        },
        (error_code >> 3) & ((1 << 14) - 1),
        (error_code & 1) > 0
    );
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    terminate_current_task_on_user_exception("INVALID OPCODE", &stack_frame);
    panic!("EXCEPTION: INVALID OPCODE:\n{stack_frame:#?}");
}

extern "x86-interrupt" fn invalid_tss_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    terminate_current_task_on_user_exception("INVALID TSS", &stack_frame);
    panic!("EXCEPTION: INVALID TSS:\nerror code: {error_code:#X}\n{stack_frame:#?}");
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let accessed_address = Cr2::read().ok();

    // Record process telemetry when multitasking is available and preserve a
    // kernel-stack guard fault as a kernel panic, never as userspace teardown.
    if let Some(addr) = accessed_address {
        if let Some(ctx) = ExecutionContext::try_load() {
            let task = ctx.current_task();
            task.process().telemetry().page_faults.fetch_add(1, Relaxed);

            if !exception_from_user_mode(&stack_frame)
                && task
                    .kstack()
                    .as_ref()
                    .is_some_and(|stack| stack.guard_page().contains(addr))
            {
                panic!(
                    "KERNEL STACK OVERFLOW DETECTED in process '{}' task '{}':\n{stack_frame:#?}",
                    task.process().name(),
                    task.name(),
                );
            }
        }
    }

    // Lazy/file-backed fault resolution is not implemented yet. Returning to
    // the same user instruction would just fault forever, so fail the task.
    terminate_current_task_on_user_exception("PAGE FAULT", &stack_frame);

    panic!(
        "EXCEPTION: PAGE FAULT:\naccessed address: {accessed_address:?}\nerror code: {error_code:#?}\n{stack_frame:#?}"
    );
}

extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    let error_code = SelectorErrorCode::from(error_code);
    panic!("EXCEPTION: SEGMENT NOT PRESENT:\nerror code: {error_code:#?}\n{stack_frame:#?}");
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("EXCEPTION: STACK SEGMENT FAULT:\nerror code: {error_code:#?}\n{stack_frame:#?}");
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    warn!("BREAKPOINT:\n{stack_frame:#?}");
    warn!("halting...");
    loop {
        hlt();
    }
}

extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    warn!("DEBUG:\n{stack_frame:#?}");
    let dr6_flags = Dr6::read();
    warn!("DR6 flags: {dr6_flags:#?}");
    let dr7_flags = Dr7::read();
    warn!("DR7 flags: {dr7_flags:#?}");
}

extern "x86-interrupt" fn device_not_available_handler(_stack_frame: InterruptStackFrame) {
    let cx = ExecutionContext::load();
    let current_task = cx.current_task();

    let mut guard = current_task.fx_area().write();
    let (fresh, fx_area) = if let Some(fx_area) = &*guard {
        (false, fx_area)
    } else {
        let process = current_task.process();
        let mut memapi = LowerHalfMemoryApi::new(process.clone());
        let fx_area = memapi
            .allocate(
                Location::Anywhere,
                Layout::new::<FxArea>(),
                UserAccessible::Yes,
                Guarded::No,
            )
            .expect("should be able to allocate fx area");

        (true, guard.insert(fx_area) as &_)
    };

    let fx_area_ptr = fx_area.start().as_mut_ptr::<u8>();
    drop(guard); // _fxrstor could trigger #NM again, so we must drop the guard before calling it

    // SAFETY: Clearing the Task Switched flag in CR0.
    unsafe { asm!("clts") };

    // saving is done every time we switch tasks, so we can only restore it here
    if fresh {
        // SAFETY: Initializing FPU and saving state.
        unsafe {
            asm!("finit");
            _fxsave(fx_area_ptr);
        }
    }
    // SAFETY: Restoring FPU state.
    unsafe { _fxrstor(fx_area_ptr) };
}

/// Notifies the LAPIC that the interrupt has been handled.
///
/// # Safety
/// This is unsafe since it writes to an LAPIC register.
#[inline]
pub unsafe fn end_of_interrupt() {
    let ctx = ExecutionContext::load();
    // SAFETY: Forwarding to LAPIC driver which handles the register write.
    unsafe { ctx.lapic().lock().end_of_interrupt() };
}

#[repr(transparent)]
struct SelectorErrorCode(u32);

impl From<u32> for SelectorErrorCode {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<u64> for SelectorErrorCode {
    fn from(value: u64) -> Self {
        let value = u32::try_from(value).unwrap();
        value.into()
    }
}

impl SelectorErrorCode {
    fn external(&self) -> bool {
        (self.0 & 1) > 0
    }

    fn tbl(&self) -> u8 {
        ((self.0 >> 1) & 0b11) as u8
    }

    fn index(&self) -> u16 {
        ((self.0 >> 3) & ((1 << 14) - 1)) as u16
    }
}

impl Debug for SelectorErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SelectorErrorCode")
            .field("index", &self.index())
            .field(
                "tbl",
                &match self.tbl() {
                    0b00 => "GDT",
                    0b01 | 0b11 => "IDT",
                    0b10 => "LDT",
                    _ => unreachable!(),
                },
            )
            .field("external", &self.external())
            .finish()
    }
}
