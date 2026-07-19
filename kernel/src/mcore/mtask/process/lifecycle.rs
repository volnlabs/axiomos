use alloc::sync::Arc;

use spin::RwLock;

use super::tree::process_tree;
use super::Process;
use crate::mcore::mtask::scheduler::wait::WaitChannel;

impl Process {
    pub fn exit_code(&self) -> &RwLock<Option<i32>> {
        &self.exit_code
    }

    pub(crate) fn child_exit_wait(&self) -> &Arc<WaitChannel> {
        self.child_exit_wait
            .get_or_init(|| Arc::new(WaitChannel::new()))
    }

    /// Publish process exit while holding the same tree lock used by waiters.
    pub(crate) fn mark_exited(&self, status: i32) {
        let _tree = process_tree().write();
        let mut exit_code = self.exit_code.write();
        if exit_code.is_some() {
            return;
        }
        *exit_code = Some(status);
        drop(exit_code);

        // Publish the status before closing descriptors so an endpoint wakeup
        // cannot expose a zombie whose exit code is still absent. Detach the
        // table under its lock, then run endpoint destructors without that lock:
        // pipe close callbacks may wake tasks and enqueue scheduler work.
        let detached_descriptors = {
            let mut descriptors = self.file_descriptors.write();
            core::mem::take(&mut *descriptors)
        };
        drop(detached_descriptors);

        if let Some(parent_exit_wait) = self.parent_exit_wait.as_ref() {
            parent_exit_wait.wake_all();
        }
    }

    pub(crate) fn begin_interruptible_sleep(&self) -> u64 {
        self.interruptible_sleep_state.begin()
    }

    #[must_use]
    pub(crate) fn request_sleep_interrupt(&self) -> bool {
        self.interruptible_sleep_state.request_interrupt()
    }

    #[must_use]
    pub(crate) fn sleep_interrupt_requested(&self, generation: u64) -> bool {
        self.interruptible_sleep_state
            .interrupt_requested(generation)
    }

    /// Complete one exact sleep generation and report whether interruption won.
    pub(crate) fn finish_interruptible_sleep(&self, generation: u64) -> bool {
        self.interruptible_sleep_state.finish(generation)
    }
}
