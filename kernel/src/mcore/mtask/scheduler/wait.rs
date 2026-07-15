//! Production `WaitChannel<TaskQueue>` wrapper.
//!
//! The generic algorithm lives in `wait_channel.rs`. This file holds
//! only the production specialization: a type alias
//! `pub type WaitChannel = WaitChannel<TaskQueue>`, a `TaskQueue`
//! adapter that implements the `WaiterSink` trait (delegating to the
//! MPSC's interior mutability and providing the wake side effect
//! `Task::wake_from_wait` + `RunQueues::enqueue`), a `new()`
//! constructor on the `TaskQueue` specialization, a concrete
//! `WaitRegistration` that owns an `Arc<WaitChannel>` (matching the
//! pre-refactor API surface), and the `TaskWait::block_current`
//! helper that integrates with the scheduler.
//!
//! Call sites are byte-identical at the source level: `WaitChannel::new()`
//! resolves through the type alias, and the call sites in
//! `kernel/src/file/pipe.rs` and `kernel/src/mcore/mtask/process/mod.rs`
//! are unchanged.
//!
//! Drop behavior: the production specialization preserves the
//! same fields and the same declaration order as the pre-refactor
//! `WaitChannel`. The compiler-generated `core::ptr::drop_glue`
//! drops each field in declaration order; the refactor does not
//! add or alter this. No prior `Drop` impl existed; the
//! `TaskQueue` production specialization retains the same
//! compiler-generated field drop behavior.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::pin::Pin;

use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
use crate::mcore::mtask::scheduler::wait_channel::{WaitChannel as GenericWaitChannel, WaiterSink};
use crate::mcore::mtask::task::{Task, TaskQueue};

/// Production type alias. Every call site uses `WaitChannel` (no
/// generic parameter at the use site).
pub type WaitChannel = GenericWaitChannel<TaskQueue>;

/// Production `WaiterSink` adapter for `TaskQueue`. The MPSC's
/// interior mutability makes `enqueue` and `try_take` work through
/// `&self`; `on_wake` performs the production wake side effect
/// (`Task::wake_from_wait` + `RunQueues::enqueue`).
impl WaiterSink for TaskQueue {
    type Item = Pin<Box<Task>>;

    fn enqueue(&self, item: Self::Item) {
        // The pre-refactor code did `self.waiters.enqueue(task)`,
        // which resolved through `Deref<Target = MpscQueue<Task>>`.
        // The MPSC's `enqueue` is `&self` and takes
        // `T::Handle = Pin<Box<Task>>`, matching `Self::Item`.
        let mpsc: &cordyceps::mpsc_queue::MpscQueue<Task> = &**self;
        mpsc.enqueue(item);
    }

    fn try_take(&self) -> Option<Self::Item> {
        // The pre-refactor code did `self.waiters.try_take()`,
        // which resolved to `TaskQueue::try_take` (a method on
        // `impl TaskQueue` that delegates to the MPSC's
        // `try_dequeue`).
        TaskQueue::try_take(self)
    }

    fn on_wake(&self, item: Self::Item) {
        // The pre-refactor code did `task.wake_from_wait()` and
        // `RunQueues::enqueue(task)`. Both are preserved:
        // `wake_from_wait` takes `&self` (interior mutability);
        // `RunQueues::enqueue` is a static call that consumes
        // its argument.
        item.wake_from_wait();
        RunQueues::enqueue(item);
    }
}

impl WaitChannel {
    /// Production constructor: creates a `WaitChannel<TaskQueue>` with
    /// a fresh `TaskQueue`. The pre-refactor constructor initialized
    /// `Self { generation, drain_gate, waiters: TaskQueue::new() }`;
    /// the post-refactor constructor delegates to `with_sink` for
    /// identical field initialization.
    #[must_use]
    pub fn new() -> Self {
        Self::with_sink(TaskQueue::new())
    }
}

impl Default for WaitChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Production `WaitRegistration`: owns an `Arc<WaitChannel>`
/// (matching the pre-refactor storage in `Task::wait_registration`).
/// Drop the registration to release the Arc without parking; call
/// `park` to actually park the task.
#[derive(Debug)]
pub(crate) struct WaitRegistration {
    channel: Arc<WaitChannel>,
    generation: u64,
}

impl WaitRegistration {
    /// Subscribe to the channel. The returned registration holds an
    /// `Arc<WaitChannel>` clone, matching the pre-refactor API.
    pub(crate) fn subscribe(channel: &Arc<WaitChannel>) -> Self {
        Self {
            channel: channel.clone(),
            generation: channel.subscribe_observed_generation(),
        }
    }

    pub(crate) fn park(self, task: Pin<Box<Task>>) {
        // The pre-refactor code did
        // `self.channel.park(task, self.generation)`. The post-refactor
        // generic `WaitChannel::park` has the same signature.
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
            let registration = WaitRegistration::subscribe(channel);
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
