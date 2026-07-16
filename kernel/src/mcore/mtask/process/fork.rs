use alloc::boxed::Box;
use alloc::sync::Arc;

use thiserror::Error;

use super::mem::MemoryCloneError;
use super::Process;
use crate::arch::UserContext;
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
use crate::mcore::mtask::task::{StackAllocationError, Task};

#[derive(Debug, Error)]
pub enum ProcessForkError {
    #[error("failed to clone process memory: {0}")]
    Memory(#[from] MemoryCloneError),
    #[error("failed to clone executable data")]
    CloneExecutableData,
    #[error("failed to clone executable ELF segment")]
    CloneExecutableSegment,
    #[error("failed to clone read-only ELF segment")]
    CloneReadonlySegment,
    #[error("failed to clone writable ELF segment")]
    CloneWritableSegment,
    #[error("failed to allocate the child task: {0}")]
    ChildTask(#[from] StackAllocationError),
}

impl Process {
    /// Forks the process, creating a exact copy of memory and file descriptors.
    ///
    /// # Errors
    /// Returns an error if memory allocation fails.
    pub fn fork(
        self: &Arc<Self>,
        current_task: &Task,
        ctx: &UserContext,
    ) -> Result<Arc<Self>, ProcessForkError> {
        let name = self.name.clone();
        let executable_path = self.executable_path.clone();

        // 1. Create basics (this creates new AS, VMM, PID)
        let child = Self::create_new(
            self, // Parent is self. (Self is the parent of the child)
            name,
            executable_path.as_ref(),
            self.bpf_capabilities(),
        );

        // 2. Clone File Descriptors
        {
            let parent_fds = self.file_descriptors.read();
            let mut child_fds = child.file_descriptors.write();
            *child_fds = parent_fds.clone();
        }

        // 3. Clone Memory Regions (Heap, mmap)
        {
            let cloned_regions = self.memory_regions.clone_to_process(&child)?;
            // We need to replace the child's empty regions with the cloned ones.
            child.memory_regions.replace_from(cloned_regions);
        }

        // 4. Clone Executable Data
        {
            let parent_exec = self.executable_file_data.read();
            if let Some(alloc) = parent_exec.as_ref() {
                let cloned = alloc
                    .clone_to_process(child.clone())
                    .ok_or(ProcessForkError::CloneExecutableData)?;
                *child.executable_file_data.write() = Some(cloned);
            }
        }

        // 4b. Clone ELF Segment Allocations (code, rodata, data loaded by ELF loader)
        {
            let parent_segs = self.elf_segments.read();
            let mut child_segs = child.elf_segments.write();
            for alloc in &parent_segs.executable {
                child_segs.executable.push(
                    alloc
                        .clone_to_process(child.clone())
                        .ok_or(ProcessForkError::CloneExecutableSegment)?,
                );
            }
            for alloc in &parent_segs.readonly {
                child_segs.readonly.push(
                    alloc
                        .clone_to_process(child.clone())
                        .ok_or(ProcessForkError::CloneReadonlySegment)?,
                );
            }
            for alloc in &parent_segs.writable {
                child_segs.writable.push(
                    alloc
                        .clone_to_process(child.clone())
                        .ok_or(ProcessForkError::CloneWritableSegment)?,
                );
            }
        }

        // 5. Build the task before publishing the child. Any earlier failure
        // drops the unpublished process and rolls back all cloned allocations.
        let child_task = Task::fork(&child, current_task, ctx)?;

        // 6. Atomically publish the fully constructed child, then make it runnable.
        self.publish_child(child.clone());
        RunQueues::enqueue(Box::pin(child_task));

        Ok(child)
    }
}
