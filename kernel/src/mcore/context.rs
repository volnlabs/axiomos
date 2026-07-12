use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
#[cfg(target_arch = "x86_64")]
use spin::Mutex;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::model_specific::KernelGsBase;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::gdt::GlobalDescriptorTable;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::idt::InterruptDescriptorTable;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::tss::TaskStateSegment;

#[cfg(target_arch = "x86_64")]
use crate::arch::gdt::Selectors;
#[cfg(target_arch = "x86_64")]
use crate::mcore::lapic::Lapic;
use crate::mcore::mtask::process::Process;
use crate::mcore::mtask::scheduler::Scheduler;
use crate::mcore::mtask::task::Task;

struct BpfCpuStack {
    data: UnsafeCell<Box<[u8]>>,
    in_use: AtomicBool,
}

impl BpfCpuStack {
    fn new() -> Self {
        Self {
            data: UnsafeCell::new(
                alloc::vec![0u8; <ActiveProfile as PhysicalProfile>::MAX_STACK_SIZE]
                    .into_boxed_slice(),
            ),
            in_use: AtomicBool::new(false),
        }
    }

    fn with_mut<R>(&self, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        if self
            .in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }

        struct Reset<'a>(&'a AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _reset = Reset(&self.in_use);

        // SAFETY: this stack belongs to one CPU context and the atomic guard
        // rejects nested execution on that CPU before forming a second borrow.
        Some(f(unsafe { &mut **self.data.get() }))
    }
}

impl fmt::Debug for BpfCpuStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfCpuStack")
            .field("len", &<ActiveProfile as PhysicalProfile>::MAX_STACK_SIZE)
            .field("in_use", &self.in_use.load(Ordering::Relaxed))
            .finish()
    }
}

#[derive(Debug)]
pub struct ExecutionContext {
    cpu_id: usize,
    #[cfg(target_arch = "x86_64")]
    lapic_id: usize,

    #[cfg(target_arch = "x86_64")]
    lapic: Mutex<Lapic>,

    #[cfg(target_arch = "x86_64")]
    _gdt: &'static GlobalDescriptorTable,
    #[cfg(target_arch = "x86_64")]
    sel: Selectors,
    #[cfg(target_arch = "x86_64")]
    _idt: &'static InterruptDescriptorTable,
    #[cfg(target_arch = "x86_64")]
    tss: UnsafeCell<&'static mut TaskStateSegment>,

    scheduler: UnsafeCell<Scheduler>,
    current_pid: AtomicU64,
    bpf_stack: BpfCpuStack,
    #[cfg(target_arch = "aarch64")]
    need_reschedule: core::sync::atomic::AtomicBool,
}

impl ExecutionContext {
    #[cfg(target_arch = "x86_64")]
    pub fn new(
        cpu: &limine::mp::Cpu,
        gdt: &'static GlobalDescriptorTable,
        sel: Selectors,
        idt: &'static InterruptDescriptorTable,
        tss: &'static mut TaskStateSegment,
        lapic: Lapic,
    ) -> Self {
        ExecutionContext {
            cpu_id: cpu.id as usize,
            lapic_id: cpu.lapic_id as usize,
            lapic: Mutex::new(lapic),
            _gdt: gdt,
            sel,
            _idt: idt,
            tss: UnsafeCell::new(tss),
            scheduler: UnsafeCell::new(Scheduler::new_cpu_local()),
            current_pid: AtomicU64::new(0),
            bpf_stack: BpfCpuStack::new(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn new(cpu_id: usize) -> Self {
        ExecutionContext {
            cpu_id,
            scheduler: UnsafeCell::new(Scheduler::new_cpu_local()),
            current_pid: AtomicU64::new(0),
            bpf_stack: BpfCpuStack::new(),
            need_reschedule: core::sync::atomic::AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn try_load() -> Option<&'static Self> {
        #[cfg(target_arch = "x86_64")]
        {
            let ctx = KernelGsBase::read();
            if ctx.is_null() {
                None
            } else {
                // SAFETY: We checked that the pointer is not null.
                // The KernelGsBase register contains a pointer to the thread-local ExecutionContext.
                Some(unsafe { &*ctx.as_ptr() })
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ctx_ptr: usize;
            // SAFETY: Reading TPIDR_EL1 is safe.
            unsafe {
                core::arch::asm!(
                    "mrs {}, tpidr_el1",
                    out(reg) ctx_ptr,
                    options(nostack, preserves_flags)
                );
            }

            if ctx_ptr == 0 {
                None
            } else {
                // SAFETY: If TPIDR_EL1 is non-zero, it must contain a valid pointer to a
                // static ExecutionContext.
                Some(unsafe { &*(ctx_ptr as *const Self) })
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        None
    }

    /// # Panics
    /// This function panics if the execution context could not be loaded.
    /// This could happen if no execution context exists yet, or the pointer
    /// or its memory in `KernelGSBase` is invalid.
    #[must_use]
    pub fn load() -> &'static Self {
        Self::try_load().expect("could not load cpu context")
    }

    #[must_use]
    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }

    #[cfg(target_arch = "x86_64")]
    pub fn lapic_id(&self) -> usize {
        self.lapic_id
    }

    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn lapic(&self) -> &Mutex<Lapic> {
        &self.lapic
    }

    #[cfg(target_arch = "x86_64")]
    pub fn selectors(&self) -> &Selectors {
        &self.sel
    }

    /// Creates and returns a mutable reference to the scheduler.
    ///
    /// # Safety
    /// The caller must ensure that only one mutable reference
    /// to the scheduler exists at any time.
    #[allow(clippy::mut_from_ref)]
    // SAFETY: The caller must ensure exclusivity.
    pub unsafe fn scheduler_mut(&self) -> &mut Scheduler {
        // SAFETY: The UnsafeCell access is guarded by the caller's guarantee of exclusivity.
        unsafe { &mut *self.scheduler.get() }
    }

    /// Prepare a scheduler transition under an exclusive borrow, end that
    /// borrow, and only then transfer control to the incoming task.
    ///
    /// # Safety
    /// The caller must ensure interrupts are disabled for the complete call.
    pub unsafe fn reschedule(&self) {
        let context_switch = {
            // SAFETY: The caller guarantees this CPU cannot re-enter scheduler
            // access while the short preparation borrow is live.
            let scheduler = unsafe { self.scheduler_mut() };
            // SAFETY: Forwarding the same interrupt/exclusivity guarantee.
            unsafe { scheduler.prepare_context_switch() }
        };

        if let Some(context_switch) = context_switch {
            // SAFETY: The scheduler borrow ended above. Its pinned outgoing and
            // incoming task storage remains owned by the scheduler.
            unsafe { context_switch.execute() };
        }
    }

    pub fn scheduler(&self) -> &Scheduler {
        // SAFETY: We are accessing the scheduler immutably.
        // This is safe because everything in the context is cpu-local and we are not
        // concurrently modifying it from this thread unless via scheduler_mut which requires unsafe.
        unsafe {
            // SAFETY: this is safe because either:
            // * there is a mutable reference that is used for rescheduling, in which case we are
            //   not currently executing this
            // * there is no mutable reference, in which case we are safe because we're not modifying
            // * someone else has a mutable reference, in which case he violates the safety contract
            //   if this is executed
            //
            // The above is true because everything in the context is cpu-local.
            &*self.scheduler.get()
        }
    }

    pub fn pid(&self) -> u64 {
        self.current_pid.load(Ordering::Relaxed)
    }

    pub fn set_current_pid(&self, pid: u64) {
        self.current_pid.store(pid, Ordering::Relaxed);
    }

    pub fn with_bpf_stack<R>(&self, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        self.bpf_stack.with_mut(f)
    }

    pub fn current_task(&self) -> &Task {
        self.scheduler().current_task()
    }

    pub fn current_process(&self) -> &Arc<Process> {
        self.current_task().process()
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_tss_rsp0(&self, rsp: u64) {
        // SAFETY: We have exclusive access to the TSS for this CPU (it's CPU-local).
        // The UnsafeCell is used because the TSS is mutated during context switches
        // while the ExecutionContext is effectively static/shared (though accessed per-cpu).
        unsafe {
            let tss = &mut *self.tss.get();
            use x86_64::VirtAddr;
            tss.privilege_stack_table[0] = VirtAddr::new(rsp);
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_need_reschedule(&self) {
        self.need_reschedule
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(target_arch = "aarch64")]
    pub fn check_and_clear_reschedule(&self) -> bool {
        self.need_reschedule
            .swap(false, core::sync::atomic::Ordering::Relaxed)
    }
}
