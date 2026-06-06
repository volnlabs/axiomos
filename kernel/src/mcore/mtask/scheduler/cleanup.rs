use alloc::boxed::Box;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
use core::sync::atomic::{AtomicBool as Rpi5AtomicBool, Ordering as Rpi5Ordering};

use conquer_once::spin::OnceCell;

use crate::mcore::mtask::process::Process;
use crate::mcore::mtask::scheduler::global::GlobalTaskQueue;
use crate::mcore::mtask::task::{Task, TaskQueue};

static CLEANUP_QUEUE: OnceCell<TaskQueue> = OnceCell::uninit();
static CLEANUP_WORKER_SCHEDULED: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static CLEANUP_RUN_MARKER_SENT: Rpi5AtomicBool = Rpi5AtomicBool::new(false);

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

fn cleanup_queue() -> &'static TaskQueue {
    CLEANUP_QUEUE.get().expect("TaskCleanup not initialized")
}

pub struct TaskCleanup;

impl TaskCleanup {
    pub fn init() {
        CLEANUP_QUEUE.init_once(TaskQueue::new);
    }

    fn ensure_worker_scheduled() {
        if !CLEANUP_WORKER_SCHEDULED.swap(true, Ordering::AcqRel) {
            let task = Task::create_new(Process::root(), Self::run, ptr::null_mut())
                .expect("should be able to create task cleanup");
            GlobalTaskQueue::enqueue(Box::pin(task));
        }
    }

    pub fn enqueue(task: Pin<Box<Task>>) {
        cleanup_queue().enqueue(task);
        Self::ensure_worker_scheduled();
    }

    extern "C" fn run(_arg: *mut core::ffi::c_void) {
        #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
        if !CLEANUP_RUN_MARKER_SENT.swap(true, Rpi5Ordering::Relaxed) {
            dbg_mark(b'c' as u32);
        }

        // log::info!("TaskCleanup: running");
        loop {
            while let Some(task) = cleanup_queue().dequeue() {
                // log::trace!("TaskCleanup: cleaning up task {}", task.id());
                drop(task);
            }

            #[cfg(target_arch = "x86_64")]
            x86_64::instructions::hlt();
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfi");
            }
        }
    }
}
