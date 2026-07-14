use alloc::boxed::Box;
use alloc::sync::Arc;
use core::pin::Pin;

use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
use crate::mcore::mtask::scheduler::wait_protocol::{DrainGate, WaitEpoch};
use crate::mcore::mtask::task::{Task, TaskQueue};

#[derive(Debug)]
pub struct WaitChannel {
    generation: WaitEpoch,
    drain_gate: DrainGate,
    waiters: TaskQueue,
}

impl WaitChannel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            generation: WaitEpoch::new(),
            drain_gate: DrainGate::new(),
            waiters: TaskQueue::new(),
        }
    }

    #[must_use]
    fn subscribe(self: &Arc<Self>) -> WaitRegistration {
        WaitRegistration {
            channel: self.clone(),
            generation: self.generation.observe(),
        }
    }

    /// Publish a condition change and wake every task registered before it.
    ///
    /// This path does not allocate or acquire a blocking lock, so it can be
    /// called by interrupt-side event publishers.
    pub fn wake_all(&self) {
        self.generation.publish();
        self.drain_waiters();
    }

    fn drain_waiters(&self) {
        if !self.drain_gate.request() {
            return;
        }

        loop {
            self.drain_gate.begin_pass();
            while let Some(task) = self.waiters.try_take() {
                task.wake_from_wait();
                RunQueues::enqueue(task);
            }
            if !self.drain_gate.finish_pass() {
                break;
            }
        }
    }

    fn park(&self, task: Pin<Box<Task>>, observed_generation: u64) {
        if self.generation.changed_since(observed_generation) {
            task.wake_from_wait();
            RunQueues::enqueue(task);
            return;
        }

        self.waiters.enqueue(task);

        // If a wake raced publication, either its consumer took this task or
        // this producer observes the generation change and completes the drain.
        if self.generation.changed_since(observed_generation) {
            self.drain_waiters();
        }
    }
}

impl Default for WaitChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub(crate) struct WaitRegistration {
    channel: Arc<WaitChannel>,
    generation: u64,
}

impl WaitRegistration {
    pub(crate) fn park(self, task: Pin<Box<Task>>) {
        self.channel.park(task, self.generation);
    }
}

pub struct TaskWait;

impl TaskWait {
    /// Register the current task, release the condition lock, and reschedule.
    ///
    /// The caller must check its condition while holding the producer's lock
    /// and move that guard into `release_condition`. The callback only releases
    /// ownership; it must not acquire another lock or block.
    pub fn block_current(channel: &Arc<WaitChannel>, release_condition: impl FnOnce()) -> bool {
        let context = ExecutionContext::load();
        context.with_interrupts_masked(|| {
            let registration = channel.subscribe();
            context.with_current_task_mut(|task| task.begin_wait(registration));
            release_condition();

            // SAFETY: interrupts remain masked for the complete scheduler transition.
            if unsafe { context.reschedule() } {
                true
            } else {
                context.with_current_task_mut(Task::abort_wait_before_switch);
                false
            }
        })
    }
}
