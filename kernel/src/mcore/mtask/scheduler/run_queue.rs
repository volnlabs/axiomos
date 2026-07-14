use alloc::boxed::Box;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};

use conquer_once::spin::OnceCell;

use crate::mcore::context::{online_cpu_mask, ExecutionContext};
use crate::mcore::mtask::scheduler::run_queue_policy::{victim_at, MAX_STEAL_ATTEMPTS};
use crate::mcore::mtask::task::{Task, TaskQueue};

pub const MAX_SCHEDULER_CPUS: usize = 64;

static RUN_QUEUES: OnceCell<Box<[TaskQueue]>> = OnceCell::uninit();
static STEAL_CURSORS: [AtomicUsize; MAX_SCHEDULER_CPUS] =
    [const { AtomicUsize::new(0) }; MAX_SCHEDULER_CPUS];

fn queues() -> &'static [TaskQueue] {
    RUN_QUEUES.get().expect("run queues not initialized")
}

fn queue(cpu_id: usize) -> &'static TaskQueue {
    queues()
        .get(cpu_id)
        .expect("CPU id exceeds scheduler queue capacity")
}

pub struct RunQueues;

impl RunQueues {
    pub fn init() {
        RUN_QUEUES.init_once(|| {
            let mut queues = Vec::with_capacity(MAX_SCHEDULER_CPUS);
            queues.resize_with(MAX_SCHEDULER_CPUS, TaskQueue::new);
            queues.into_boxed_slice()
        });
    }

    pub fn enqueue(task: Pin<Box<Task>>) {
        let target_cpu = task.last_cpu();
        queue(target_cpu).enqueue(task);
    }

    #[must_use]
    pub fn dequeue() -> Option<Pin<Box<Task>>> {
        let current_cpu = ExecutionContext::load().cpu_id();
        if let Some(task) = queue(current_cpu).try_take() {
            return Some(task);
        }

        let cursor = STEAL_CURSORS[current_cpu].fetch_add(1, Ordering::Relaxed);
        let online = online_cpu_mask();
        let local_bit = 1u64 << current_cpu;
        let victim_count = (online & !local_bit).count_ones() as usize;
        for ordinal in 0..MAX_STEAL_ATTEMPTS.min(victim_count) {
            let Some(victim) = victim_at(online, current_cpu, cursor + ordinal) else {
                break;
            };
            if let Some(task) = queue(victim).try_take() {
                return Some(task);
            }
        }
        None
    }
}
