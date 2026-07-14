use alloc::boxed::Box;
use core::arch::asm;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_fxsave;
use core::cell::UnsafeCell;
use core::mem::swap;
use core::pin::Pin;
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
use core::sync::atomic::{AtomicBool, Ordering};

use cleanup::TaskCleanup;
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::interrupts;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::model_specific::FsBase;

#[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
use crate::arch::aarch64::Aarch64 as Arch;
#[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
use crate::arch::traits::Architecture;
use crate::mcore::context::ExecutionContext;
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
use crate::mcore::mtask::process::Process;
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
use crate::mcore::mtask::scheduler::sleep::TaskSleep;
use crate::mcore::mtask::scheduler::switch::switch_impl;
use crate::mcore::mtask::task::{State, Task};

pub mod cleanup;
pub mod run_queue;
mod run_queue_policy;
pub mod sleep;
mod switch;

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static SCHED_SWITCH_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static SCHED_SWITCH_TARGET_MARKER_SENT: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
#[inline(always)]
fn dbg_hex_nibble(n: u8) -> u32 {
    let v = n & 0x0F;
    if v < 10 {
        (b'0' + v) as u32
    } else {
        (b'a' + (v - 10)) as u32
    }
}

#[derive(Debug)]
pub struct Scheduler {
    /// The task that is currently executing in this scheduler.
    current_task: Pin<Box<Task>>,
    /// The task this scheduler last switched away from. We need this to
    /// eliminate the race condition between re-queueing a task and
    /// actually switching away from it.
    zombie_task: Option<Pin<Box<Task>>>,
    /// A dummy location that is a placeholder for the switch code to write the old stack
    /// pointer to if the old task is terminated.
    dummy_old_stack_ptr: UnsafeCell<usize>,
}

/// Raw context-switch inputs prepared while the scheduler is exclusively
/// borrowed, then consumed only after that Rust borrow has ended.
pub(crate) struct ContextSwitch {
    old_stack_ptr: *mut usize,
    new_stack_ptr: usize,
    new_cr3_value: usize,
}

impl ContextSwitch {
    /// Perform the architecture context switch.
    ///
    /// # Safety
    /// The scheduler that produced this value must remain alive, interrupts
    /// must remain disabled, and this switch must be executed exactly once.
    pub(crate) unsafe fn execute(self) {
        // SAFETY: `prepare_context_switch` derives both stack pointers from
        // pinned tasks retained by the scheduler and records the target page
        // table value before ending its exclusive borrow.
        unsafe {
            switch_impl(
                self.old_stack_ptr,
                self.new_stack_ptr as *const u8,
                self.new_cr3_value,
            );
        }
    }
}

impl Scheduler {
    #[must_use]
    pub fn new_cpu_local(cpu_id: usize) -> Self {
        // SAFETY: We are creating a task representing the current CPU execution state.
        // This is done once per CPU during initialization.
        let current_task = Box::pin(unsafe { Task::create_current(cpu_id) });
        Self {
            current_task,
            zombie_task: None,
            dummy_old_stack_ptr: UnsafeCell::new(0),
        }
    }

    /// Mutate scheduler state and prepare a context switch without executing it.
    ///
    /// Ending the `&mut Scheduler` borrow before [`ContextSwitch::execute`] is
    /// essential: the incoming task may access this CPU's scheduler before the
    /// outgoing task eventually resumes and returns from the assembly switch.
    ///
    /// # Safety
    /// Interrupts must be disabled and the returned switch must be executed at
    /// most once before interrupts are re-enabled.
    pub(crate) unsafe fn prepare_context_switch(&mut self) -> Option<ContextSwitch> {
        // log::info!("reschedule: entering");
        #[cfg(target_arch = "x86_64")]
        assert!(!interrupts::are_enabled());
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
        assert!(!Arch::are_interrupts_enabled());

        // in theory, we could move this to the end of this function, but I'd rather not do this right now
        if let Some(zombie_task) = self.zombie_task.take() {
            // log::info!("reschedule: cleaning up zombie task {}", zombie_task.id());
            if zombie_task.should_terminate() {
                TaskCleanup::enqueue(zombie_task);
            } else if zombie_task.state() == State::Sleeping {
                TaskSleep::enqueue(zombie_task);
            } else {
                zombie_task.mark_ready();
                RunQueues::enqueue(zombie_task);
            }
        }

        let (next_task, cr3_value) = {
            let next_task_opt = self.next_task();
            if next_task_opt.is_none() {
                // log::info!("reschedule: no next task, staying on current task {}", self.current_task.id());
            }
            let Some(next_task) = next_task_opt else {
                return None;
            };

            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            if !SCHED_SWITCH_MARKER_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b's' as u32);
            }
            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            if !SCHED_SWITCH_TARGET_MARKER_SENT.swap(true, Ordering::Relaxed) {
                // k: switched to root-process kernel task
                // j: switched to non-root process task (expected for /bin/init)
                if next_task.process().pid() == Process::root().pid() {
                    dbg_mark(b'k' as u32);
                } else {
                    dbg_mark(b'j' as u32);
                }

                // Emit target PID low byte as two hex chars: Zhh
                let pid = (next_task.process().pid().as_u64() & 0xFF) as u8;
                dbg_mark(b'Z' as u32);
                dbg_mark(dbg_hex_nibble(pid >> 4));
                dbg_mark(dbg_hex_nibble(pid));
            }

            log::trace!("reschedule: switching to task {}", next_task.id());
            next_task.set_last_cpu(ExecutionContext::load().cpu_id());
            next_task.mark_running();

            next_task
                .process()
                .mark_address_space_resident(ExecutionContext::load().cpu_id());

            #[cfg(target_arch = "x86_64")]
            let cr3_value = next_task
                .process()
                .with_address_space(|as_| as_.cr3_value());
            #[cfg(target_arch = "x86_64")]
            {
                if let Some(kstack) = next_task.kstack() {
                    let segment = kstack.mapped_segment();
                    let rsp0 = (segment.start + segment.len).as_u64();
                    ExecutionContext::load().set_tss_rsp0(rsp0);
                }
            }
            #[cfg(target_arch = "aarch64")]
            let cr3_value = next_task
                .process()
                .with_address_space(|as_| as_.ttbr0_value());

            // log::info!("reschedule: switching to task {} with ttbr0={:#x}", next_task.id(), cr3_value);

            let sched_ctx = kernel_bpf::execution::SchedSwitchContext {
                cpu_id: ExecutionContext::load().cpu_id() as u64,
                prev_pid: self.current_task.process().pid().as_u64(),
                prev_tid: self.current_task.id().as_u64(),
                next_pid: next_task.process().pid().as_u64(),
                next_tid: next_task.id().as_u64(),
            };
            let bpf_ctx = kernel_bpf::execution::BpfContext::from_struct(&sched_ctx);
            let _ = crate::bpf::BpfManager::run_hook_programs(
                crate::bpf::ATTACH_TYPE_SCHED_SWITCH,
                &bpf_ctx,
                "sched_switch",
            );

            (next_task, cr3_value)
        };

        let mut old_task = self.swap_current_task(next_task);
        // log::trace!("reschedule: swapped current task, old task was {}", old_task.id());
        let old_stack_ptr = if old_task.should_terminate() {
            self.dummy_old_stack_ptr.get()
        } else {
            old_task.last_stack_ptr() as *mut usize
        };

        #[cfg(target_arch = "x86_64")]
        if let Some(mut guard) = old_task.fx_area().try_write() {
            if let Some(fx_area) = guard.as_mut() {
                // SAFETY: We are disabling task switching (FPU context) via CR0.TS.
                unsafe { asm!("clts") };
                // SAFETY: Safe because we hold a mutable reference to the fx_area
                unsafe {
                    _fxsave(fx_area.start().as_mut_ptr::<u8>());
                }
            }
        }

        if let Some(guard) = self.current_task.tls().try_read() {
            if let Some(tls) = guard.as_ref() {
                #[cfg(target_arch = "x86_64")]
                FsBase::write(tls.start());
                #[cfg(target_arch = "aarch64")]
                // SAFETY: Writing to TPIDR_EL0 is safe in EL1.
                unsafe {
                    let val = tls.start().as_u64();
                    asm!("msr tpidr_el0, {}", in(reg) val);
                }
            }
        }

        assert!(self.zombie_task.is_none());
        self.zombie_task = Some(old_task);

        ExecutionContext::load().set_current_pid(self.current_task.process().pid().as_u64());

        Some(ContextSwitch {
            old_stack_ptr,
            new_stack_ptr: *self.current_task.last_stack_ptr(),
            new_cr3_value: cr3_value,
        })
    }

    #[must_use]
    pub fn current_task(&self) -> &Task {
        &self.current_task
    }

    fn swap_current_task(&mut self, next_task: Pin<Box<Task>>) -> Pin<Box<Task>> {
        let mut next_task = next_task;
        swap(&mut self.current_task, &mut next_task);
        next_task
    }

    #[allow(clippy::unused_self)]
    fn next_task(&self) -> Option<Pin<Box<Task>>> {
        RunQueues::dequeue()
    }
}
