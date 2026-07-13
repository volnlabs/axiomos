use alloc::boxed::Box;
use core::pin::Pin;

use conquer_once::spin::OnceCell;
use kernel_time::DeadlineQueue;
use spin::Mutex;

use crate::mcore::mtask::scheduler::global::GlobalTaskQueue;
use crate::mcore::mtask::task::{SleepWakeReason, Task};

const MAX_SLEEPING_TASKS: usize = 1024;

static SLEEP_QUEUE: OnceCell<Mutex<DeadlineQueue<Pin<Box<Task>>, MAX_SLEEPING_TASKS>>> =
    OnceCell::uninit();

fn sleep_queue() -> &'static Mutex<DeadlineQueue<Pin<Box<Task>>, MAX_SLEEPING_TASKS>> {
    SLEEP_QUEUE.get().expect("TaskSleep not initialized")
}

fn with_sleep_queue<R>(
    f: impl FnOnce(&mut DeadlineQueue<Pin<Box<Task>>, MAX_SLEEPING_TASKS>) -> R,
) -> R {
    let access = || f(&mut sleep_queue().lock());
    if let Some(context) = crate::mcore::context::ExecutionContext::try_load() {
        context.with_interrupts_masked(access)
    } else {
        access()
    }
}

pub struct TaskSleep;

impl TaskSleep {
    pub fn init() {
        SLEEP_QUEUE.init_once(|| Mutex::new(DeadlineQueue::new()));
    }

    pub fn enqueue(task: Pin<Box<Task>>) {
        debug_assert_eq!(task.state(), crate::mcore::mtask::task::State::Sleeping);
        let deadline_ns = task.sleep_deadline_ns();
        let enqueue_result = with_sleep_queue(|queue| {
            if task.sleep_interrupt_requested() {
                assert!(task.finish_sleep());
                Err((task, SleepWakeReason::Interrupted))
            } else {
                queue.push(deadline_ns, task).map_err(|task| {
                    let _ = task.finish_sleep();
                    (task, SleepWakeReason::Interrupted)
                })
            }
        });
        if let Err((task, reason)) = enqueue_result {
            task.wake_from_sleep(reason);
            GlobalTaskQueue::enqueue(task);
        }
    }

    /// Move every expired task back to the runnable queue.
    ///
    /// This is called from timer interrupt context and performs no allocation.
    pub fn wake_expired(now_ns: u64) {
        loop {
            let wake = with_sleep_queue(|queue| {
                queue.pop_expired(now_ns).map(|entry| {
                    let task = entry.into_value();
                    let reason = if task.finish_sleep() {
                        SleepWakeReason::Interrupted
                    } else {
                        SleepWakeReason::Deadline
                    };
                    (task, reason)
                })
            });
            let Some((task, reason)) = wake else {
                break;
            };
            task.wake_from_sleep(reason);
            GlobalTaskQueue::enqueue(task);
        }
    }

    /// Cancel a process's sleeping task and make it runnable with `EINTR`.
    pub fn interrupt_process(process: &crate::mcore::mtask::process::Process) -> bool {
        let result = with_sleep_queue(|queue| {
            if !process.request_sleep_interrupt() {
                return None;
            }
            let task = queue
                .cancel(|entry| entry.value().process().pid() == process.pid())
                .map(kernel_time::DeadlineEntry::into_value);
            if let Some(task) = task.as_ref() {
                assert!(task.finish_sleep());
            }
            Some(task)
        });
        let Some(task) = result else {
            return false;
        };
        if let Some(task) = task {
            task.wake_from_sleep(SleepWakeReason::Interrupted);
            GlobalTaskQueue::enqueue(task);
        }
        true
    }
}
