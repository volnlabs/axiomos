use alloc::boxed::Box;
use core::fmt::{Debug, Formatter};
use core::pin::Pin;

use kernel_run_queue::RunQueue;

use crate::mcore::mtask::task::Task;

pub struct TaskQueue {
    inner: RunQueue<Task>,
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RunQueue::new(Box::pin(Task::create_stub())),
        }
    }

    pub fn enqueue(&self, task: Pin<Box<Task>>) {
        self.inner.enqueue(task);
    }

    pub fn dequeue(&self) -> Option<Pin<Box<Task>>> {
        self.inner.dequeue()
    }

    /// Attempt one nonblocking dequeue. Competing consumers and in-progress
    /// producers are treated as a miss so scheduler stealing remains bounded.
    pub fn try_take(&self) -> Option<Pin<Box<Task>>> {
        self.inner.try_take()
    }
}

impl Debug for TaskQueue {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskQueue").finish_non_exhaustive()
    }
}
