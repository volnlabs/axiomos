//! Ready Queue for BPF Programs
//!
//! This module implements the ready queue that holds pending BPF
//! program execution requests.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::marker::PhantomData;

use super::policy::{ExecPriority, SchedError, SchedResult};
use super::{BpfExecRequest, ProgId};
use crate::bytecode::program::BpfProgram;
use crate::execution::BpfContext;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Maximum queue size for embedded profile.
#[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
const MAX_QUEUE_SIZE: usize = 32;

/// Maximum queue size for cloud profile.
#[cfg(feature = "cloud-profile")]
const MAX_QUEUE_SIZE: usize = 1024;

/// A program queued for execution.
pub struct QueuedProgram<P: PhysicalProfile = ActiveProfile> {
    /// Unique program identifier
    pub id: ProgId,
    /// The program to execute
    pub program: Arc<BpfProgram<P>>,
    /// Execution context
    pub context: BpfContext<'static>,
    /// Priority level
    pub priority: ExecPriority,
    /// Submission timestamp (monotonic counter)
    pub submitted_at: u64,
    /// Deadline (embedded profile only)
    #[cfg(feature = "embedded-profile")]
    pub deadline: Option<super::deadline::Deadline>,
}

impl<P: PhysicalProfile> QueuedProgram<P> {
    /// Create a queued program from an execution request.
    #[cfg(feature = "cloud-profile")]
    pub fn from_request(request: BpfExecRequest<P>) -> Self {
        static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        Self {
            id: request.id,
            program: request.program,
            context: request.context,
            priority: request.priority,
            submitted_at: COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Create a queued program from an execution request.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    pub fn from_request(request: BpfExecRequest<P>) -> Self {
        static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        Self {
            id: request.id,
            program: request.program,
            context: request.context,
            priority: request.priority,
            submitted_at: COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            deadline: request.deadline,
        }
    }
}

/// Ready queue for BPF programs.
///
/// The queue holds programs waiting to be executed. The maximum
/// size is profile-dependent.
pub struct BpfQueue<P: PhysicalProfile = ActiveProfile> {
    /// Queued programs
    programs: VecDeque<QueuedProgram<P>>,
    /// Profile marker
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> BpfQueue<P> {
    /// Create a new empty queue.
    pub fn new() -> Self {
        Self {
            programs: VecDeque::with_capacity(MAX_QUEUE_SIZE),
            _profile: PhantomData,
        }
    }

    /// Add a program to the queue.
    pub fn enqueue(&mut self, program: QueuedProgram<P>) -> SchedResult<()> {
        if self.programs.len() >= MAX_QUEUE_SIZE {
            return Err(SchedError::QueueFull);
        }
        self.programs.push_back(program);
        Ok(())
    }

    /// Remove and return the program at the front.
    pub fn dequeue(&mut self) -> Option<QueuedProgram<P>> {
        self.programs.pop_front()
    }

    /// Remove a specific program by ID.
    pub fn remove(&mut self, id: ProgId) -> bool {
        if let Some(pos) = self.programs.iter().position(|p| p.id == id) {
            self.programs.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    /// Get the number of programs in the queue.
    pub fn len(&self) -> usize {
        self.programs.len()
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.programs.len() >= MAX_QUEUE_SIZE
    }

    /// Get a reference to all queued programs.
    pub fn iter(&self) -> impl Iterator<Item = &QueuedProgram<P>> {
        self.programs.iter()
    }

    /// Get the index of the highest priority program.
    pub fn find_highest_priority(&self) -> Option<usize> {
        if self.programs.is_empty() {
            return None;
        }

        let mut best_idx = 0;
        let mut best_priority = self.programs[0].priority;
        let mut best_time = self.programs[0].submitted_at;

        for (idx, prog) in self.programs.iter().enumerate().skip(1) {
            // Higher priority wins
            if prog.priority > best_priority {
                best_idx = idx;
                best_priority = prog.priority;
                best_time = prog.submitted_at;
            } else if prog.priority == best_priority && prog.submitted_at < best_time {
                // Same priority, earlier submission wins (FIFO within priority)
                best_idx = idx;
                best_time = prog.submitted_at;
            }
        }

        Some(best_idx)
    }

    /// Remove and return the program at a specific index.
    pub fn remove_at(&mut self, index: usize) -> Option<QueuedProgram<P>> {
        self.programs.remove(index)
    }

    /// Find the index of the program with the earliest deadline (embedded only).
    #[cfg(feature = "embedded-profile")]
    pub fn find_earliest_deadline(&self) -> Option<usize> {
        if self.programs.is_empty() {
            return None;
        }

        let mut best_idx = None;
        let mut best_deadline = u64::MAX;

        for (idx, prog) in self.programs.iter().enumerate() {
            if let Some(deadline) = prog
                .deadline
                .as_ref()
                .filter(|d| d.absolute_ns < best_deadline)
            {
                best_deadline = deadline.absolute_ns;
                best_idx = Some(idx);
            }
        }

        // If no deadlines, fall back to priority
        best_idx.or_else(|| self.find_highest_priority())
    }
}

impl<P: PhysicalProfile> Default for BpfQueue<P> {
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

    fn create_queued_program(id: u32, priority: ExecPriority) -> QueuedProgram<ActiveProfile> {
        let request = BpfExecRequest::new(ProgId(id), create_test_program(), BpfContext::empty())
            .with_priority(priority);
        QueuedProgram::from_request(request)
    }

    #[test]
    fn queue_operations() {
        let mut queue = BpfQueue::<ActiveProfile>::new();

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue
            .enqueue(create_queued_program(1, ExecPriority::Normal))
            .expect("enqueue");

        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 1);

        let prog = queue.dequeue().expect("dequeue");
        assert_eq!(prog.id, ProgId(1));
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_remove_by_id() {
        let mut queue = BpfQueue::<ActiveProfile>::new();

        queue
            .enqueue(create_queued_program(1, ExecPriority::Normal))
            .expect("enqueue");
        queue
            .enqueue(create_queued_program(2, ExecPriority::Normal))
            .expect("enqueue");
        queue
            .enqueue(create_queued_program(3, ExecPriority::Normal))
            .expect("enqueue");

        assert!(queue.remove(ProgId(2)));
        assert_eq!(queue.len(), 2);

        // First should be 1
        let p1 = queue.dequeue().expect("dequeue");
        assert_eq!(p1.id, ProgId(1));

        // Second should be 3 (2 was removed)
        let p3 = queue.dequeue().expect("dequeue");
        assert_eq!(p3.id, ProgId(3));
    }

    #[test]
    fn find_highest_priority() {
        let mut queue = BpfQueue::<ActiveProfile>::new();

        queue
            .enqueue(create_queued_program(1, ExecPriority::Low))
            .expect("enqueue");
        queue
            .enqueue(create_queued_program(2, ExecPriority::Critical))
            .expect("enqueue");
        queue
            .enqueue(create_queued_program(3, ExecPriority::Normal))
            .expect("enqueue");

        let idx = queue.find_highest_priority().expect("find");
        assert_eq!(idx, 1); // Program 2 has Critical priority
    }

    #[test]
    fn priority_fifo_within_same_level() {
        let mut queue = BpfQueue::<ActiveProfile>::new();

        // All same priority, should be FIFO
        queue
            .enqueue(create_queued_program(1, ExecPriority::Normal))
            .expect("enqueue");
        queue
            .enqueue(create_queued_program(2, ExecPriority::Normal))
            .expect("enqueue");
        queue
            .enqueue(create_queued_program(3, ExecPriority::Normal))
            .expect("enqueue");

        let idx = queue.find_highest_priority().expect("find");
        assert_eq!(idx, 0); // First submitted
    }
}
