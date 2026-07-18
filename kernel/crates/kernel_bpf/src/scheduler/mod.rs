//! BPF Program Scheduler
//!
//! This module provides profile-aware scheduling for BPF program execution.
//! The scheduler determines when and how BPF programs run based on the
//! active profile's constraints.
//!
//! # Profile Differences
//!
//! | Feature       | Cloud          | Embedded         |
//! |---------------|----------------|------------------|
//! | Policy        | Throughput     | Deadline (EDF)   |
//! | Preemption    | Cooperative    | Preemptive       |
//! | Priority      | Fair share     | Priority ceiling |
//! | WCET          | Soft bounds    | Hard bounds      |
//!
//! # Compile-Time Erasure
//!
//! The `ThroughputPolicy` is only available in cloud builds.
//! The `DeadlinePolicy` with hard WCET enforcement is only
//! available in embedded builds.

extern crate alloc;

mod policy;
mod queue;

#[cfg(feature = "cloud-profile")]
mod throughput;

#[cfg(feature = "embedded-profile")]
mod deadline;

use alloc::sync::Arc;

#[cfg(feature = "embedded-profile")]
pub use deadline::{Deadline, DeadlinePolicy};
pub use policy::{BpfPolicy, ExecPriority, SchedResult};
pub use queue::{BpfQueue, QueuedProgram};
#[cfg(feature = "cloud-profile")]
pub use throughput::ThroughputPolicy;

use crate::bytecode::program::BpfProgram;
use crate::execution::BpfContext;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Unique identifier for a scheduled BPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgId(pub u32);

/// Execution request for a BPF program.
///
/// Contains all information needed to schedule and execute a program.
pub struct BpfExecRequest<P: PhysicalProfile = ActiveProfile> {
    /// Unique program identifier
    pub id: ProgId,
    /// The program to execute
    pub program: Arc<BpfProgram<P>>,
    /// Execution context
    pub context: BpfContext<'static>,
    /// Priority level
    pub priority: ExecPriority,
    /// Deadline (embedded profile only)
    #[cfg(feature = "embedded-profile")]
    pub deadline: Option<Deadline>,
}

impl<P: PhysicalProfile> BpfExecRequest<P> {
    /// Create a new execution request.
    #[cfg(feature = "cloud-profile")]
    pub fn new(id: ProgId, program: Arc<BpfProgram<P>>, context: BpfContext<'static>) -> Self {
        Self {
            id,
            program,
            context,
            priority: ExecPriority::Normal,
        }
    }

    /// Create a new execution request.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    pub fn new(id: ProgId, program: Arc<BpfProgram<P>>, context: BpfContext<'static>) -> Self {
        Self {
            id,
            program,
            context,
            priority: ExecPriority::Normal,
            deadline: None,
        }
    }

    /// Set the execution priority.
    pub fn with_priority(mut self, priority: ExecPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set a deadline (embedded profile only).
    #[cfg(feature = "embedded-profile")]
    pub fn with_deadline(mut self, deadline: Deadline) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

/// BPF program scheduler.
///
/// The scheduler manages a queue of pending BPF program executions
/// and determines execution order based on the active profile's policy.
///
/// This type uses `ActiveProfile` directly since the scheduling policy
/// is determined at compile time by the profile feature.
pub struct BpfScheduler {
    /// Program queue
    queue: BpfQueue<ActiveProfile>,
    /// Scheduling policy
    #[cfg(feature = "cloud-profile")]
    policy: ThroughputPolicy,
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    policy: DeadlinePolicy,
}

impl BpfScheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        Self {
            queue: BpfQueue::new(),
            #[cfg(feature = "cloud-profile")]
            policy: ThroughputPolicy::new(),
            #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
            policy: DeadlinePolicy::new(),
        }
    }

    /// Submit a program for execution.
    pub fn submit(&mut self, request: BpfExecRequest<ActiveProfile>) -> SchedResult<()> {
        let queued = QueuedProgram::from_request(request);
        self.queue.enqueue(queued)
    }

    /// Get the next program to execute.
    ///
    /// Returns `None` if the queue is empty.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<QueuedProgram<ActiveProfile>> {
        self.policy.select(&mut self.queue)
    }

    /// Check if there are pending programs.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Get the number of pending programs.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Cancel a pending program by ID.
    pub fn cancel(&mut self, id: ProgId) -> bool {
        self.queue.remove(id)
    }

    /// Update the current time (embedded profile only).
    #[cfg(feature = "embedded-profile")]
    pub fn update_time(&mut self, now_ns: u64) {
        self.policy.update_time(now_ns);
    }

    /// Get execution statistics.
    pub fn exec_count(&self) -> u64 {
        self.policy.exec_count()
    }

    /// Get deadline miss count (embedded profile only).
    #[cfg(feature = "embedded-profile")]
    pub fn deadline_misses(&self) -> u64 {
        self.policy.deadline_misses()
    }
}

impl Default for BpfScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::insn::BpfInsn;
    use crate::bytecode::program::{BpfProgType, ProgramBuilder};

    fn create_test_program() -> Arc<BpfProgram<ActiveProfile>> {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");
        Arc::new(program)
    }

    #[test]
    fn scheduler_creation() {
        let sched = BpfScheduler::new();
        assert!(!sched.has_pending());
        assert_eq!(sched.pending_count(), 0);
    }

    #[test]
    fn submit_and_retrieve() {
        let mut sched = BpfScheduler::new();
        let program = create_test_program();
        let ctx = BpfContext::empty();

        let request = BpfExecRequest::new(ProgId(1), program, ctx);
        sched.submit(request).expect("submit");

        assert!(sched.has_pending());
        assert_eq!(sched.pending_count(), 1);

        let next = sched.next().expect("should have program");
        assert_eq!(next.id, ProgId(1));

        assert!(!sched.has_pending());
    }

    #[test]
    fn cancel_pending() {
        let mut sched = BpfScheduler::new();
        let program = create_test_program();

        let request = BpfExecRequest::new(ProgId(42), program, BpfContext::empty());
        sched.submit(request).expect("submit");

        assert!(sched.cancel(ProgId(42)));
        assert!(!sched.has_pending());

        // Canceling non-existent ID should return false
        assert!(!sched.cancel(ProgId(99)));
    }

    #[test]
    fn priority_ordering() {
        let mut sched = BpfScheduler::new();
        let program = create_test_program();

        // Submit low priority first
        let req1 = BpfExecRequest::new(ProgId(1), Arc::clone(&program), BpfContext::empty())
            .with_priority(ExecPriority::Low);
        sched.submit(req1).expect("submit");

        // Submit high priority second
        let req2 = BpfExecRequest::new(ProgId(2), Arc::clone(&program), BpfContext::empty())
            .with_priority(ExecPriority::High);
        sched.submit(req2).expect("submit");

        // High priority should come first
        let next = sched.next().expect("should have program");
        assert_eq!(next.id, ProgId(2));
    }
}
