use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::fmt;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

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

static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static ONLINE_LAPIC_IDS: [AtomicU32; 64] = [const { AtomicU32::new(u32::MAX) }; 64];

fn cpu_bit(cpu_id: usize) -> u64 {
    1u64.checked_shl(u32::try_from(cpu_id).expect("CPU id must fit u32"))
        .filter(|bit| *bit != 0)
        .expect("axiomos supports at most 64 tracked CPUs")
}

pub fn online_cpu_mask() -> u64 {
    ONLINE_CPU_MASK.load(Ordering::Acquire)
}

#[cfg(target_arch = "x86_64")]
pub fn online_lapic_id(cpu_id: usize) -> Option<u32> {
    let lapic_id = ONLINE_LAPIC_IDS.get(cpu_id)?.load(Ordering::Acquire);
    (lapic_id != u32::MAX).then_some(lapic_id)
}

struct BpfCpuStack {
    data: UnsafeCell<Box<[u8]>>,
    in_use: AtomicBool,
}

struct SchedulerSlot {
    value: UnsafeCell<Scheduler>,
    borrowed: AtomicBool,
}

impl SchedulerSlot {
    fn new(value: Scheduler) -> Self {
        Self {
            value: UnsafeCell::new(value),
            borrowed: AtomicBool::new(false),
        }
    }

    fn with<R>(&self, f: impl for<'scheduler> FnOnce(&'scheduler Scheduler) -> R) -> R {
        self.with_mut(|scheduler| f(scheduler))
    }

    fn with_mut<R>(&self, f: impl for<'scheduler> FnOnce(&'scheduler mut Scheduler) -> R) -> R {
        assert!(
            self.borrowed
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok(),
            "reentrant scheduler access"
        );

        struct Reset<'a>(&'a AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _reset = Reset(&self.borrowed);

        // SAFETY: the atomic guard permits exactly one scoped borrow. The HRTB
        // callback cannot return a reference tied to `scheduler` through `R`.
        f(unsafe { &mut *self.value.get() })
    }
}

impl fmt::Debug for SchedulerSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchedulerSlot")
            .field("borrowed", &self.borrowed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
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

    scheduler: SchedulerSlot,
    current_pid: AtomicU64,
    bpf_stack: BpfCpuStack,
    bpf_execution: AtomicPtr<()>,
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
            scheduler: SchedulerSlot::new(Scheduler::new_cpu_local()),
            current_pid: AtomicU64::new(0),
            bpf_stack: BpfCpuStack::new(),
            bpf_execution: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn new(cpu_id: usize) -> Self {
        ExecutionContext {
            cpu_id,
            scheduler: SchedulerSlot::new(Scheduler::new_cpu_local()),
            current_pid: AtomicU64::new(0),
            bpf_stack: BpfCpuStack::new(),
            bpf_execution: AtomicPtr::new(core::ptr::null_mut()),
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

    pub fn mark_online(&self) {
        #[cfg(target_arch = "x86_64")]
        ONLINE_LAPIC_IDS[self.cpu_id].store(
            u32::try_from(self.lapic_id).expect("LAPIC id must fit u32"),
            Ordering::Relaxed,
        );
        ONLINE_CPU_MASK.fetch_or(cpu_bit(self.cpu_id), Ordering::Release);
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

    /// Prepare a scheduler transition under an exclusive borrow, end that
    /// borrow, and only then transfer control to the incoming task.
    ///
    /// # Safety
    /// The caller must ensure interrupts are disabled for the complete call.
    pub unsafe fn reschedule(&self) -> bool {
        let context_switch = {
            self.scheduler.with_mut(|scheduler| {
                // SAFETY: The caller guarantees interrupts remain disabled and
                // SchedulerSlot provides the exclusive preparation borrow.
                unsafe { scheduler.prepare_context_switch() }
            })
        };

        if let Some(context_switch) = context_switch {
            // SAFETY: The scheduler borrow ended above. Its pinned outgoing and
            // incoming task storage remains owned by the scheduler.
            unsafe { context_switch.execute() };
            true
        } else {
            false
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

    pub(crate) fn with_bpf_execution<R>(
        &self,
        execution: *mut (),
        f: impl FnOnce() -> R,
    ) -> Option<R> {
        if execution.is_null()
            || self
                .bpf_execution
                .compare_exchange(
                    core::ptr::null_mut(),
                    execution,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return None;
        }

        struct Reset<'a>(&'a AtomicPtr<()>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(core::ptr::null_mut(), Ordering::Release);
            }
        }
        let _reset = Reset(&self.bpf_execution);
        Some(f())
    }

    pub(crate) fn current_bpf_execution(&self) -> *mut () {
        self.bpf_execution.load(Ordering::Acquire)
    }

    pub(crate) fn with_interrupts_masked<R>(&self, f: impl FnOnce() -> R) -> R {
        #[cfg(target_arch = "x86_64")]
        {
            return x86_64::instructions::interrupts::without_interrupts(f);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let daif: u64;
            // SAFETY: DAIF is CPU-local interrupt state. The guard restores the
            // IRQ mask to its entry state after the scoped scheduler access.
            unsafe {
                core::arch::asm!("mrs {}, daif", out(reg) daif, options(nostack, preserves_flags));
                core::arch::asm!("msr daifset, #2", options(nostack, preserves_flags));
            }
            struct RestoreIrq(bool);
            impl Drop for RestoreIrq {
                fn drop(&mut self) {
                    if self.0 {
                        // SAFETY: Restore IRQ delivery only when it was enabled
                        // at entry; other DAIF mask bits remain unchanged.
                        unsafe {
                            core::arch::asm!("msr daifclr, #2", options(nostack, preserves_flags));
                        }
                    }
                }
            }
            let _restore = RestoreIrq((daif & (1 << 7)) == 0);
            return f();
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        f()
    }

    pub fn with_current_task<R>(&self, f: impl for<'task> FnOnce(&'task Task) -> R) -> R {
        self.with_interrupts_masked(|| self.scheduler.with(|scheduler| f(scheduler.current_task())))
    }

    pub fn current_process(&self) -> Arc<Process> {
        self.with_current_task(|task| task.process().clone())
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
