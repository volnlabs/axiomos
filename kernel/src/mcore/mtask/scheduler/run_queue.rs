use alloc::boxed::Box;
use core::pin::Pin;

use conquer_once::spin::OnceCell;
use kernel_run_queue::RunQueueSet;

use crate::mcore::context::{online_cpu_mask, ExecutionContext};
use crate::mcore::mtask::task::Task;

pub const MAX_SCHEDULER_CPUS: usize = 64;

static RUN_QUEUES: OnceCell<RunQueueSet<Task>> = OnceCell::uninit();

fn queues() -> &'static RunQueueSet<Task> {
    RUN_QUEUES.get().expect("run queues not initialized")
}

pub struct RunQueues;

impl RunQueues {
    pub fn init() {
        RUN_QUEUES
            .init_once(|| RunQueueSet::new(MAX_SCHEDULER_CPUS, || Box::pin(Task::create_stub())));
    }

    pub fn enqueue(task: Pin<Box<Task>>) {
        let target_cpu = task.last_cpu();
        queues().enqueue_on(target_cpu, task);
    }

    #[must_use]
    pub fn dequeue() -> Option<Pin<Box<Task>>> {
        let current_cpu = ExecutionContext::load().cpu_id();
        queues().try_take_from(current_cpu, online_cpu_mask)
    }
}
