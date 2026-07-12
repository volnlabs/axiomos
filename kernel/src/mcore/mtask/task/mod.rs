use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::ffi::c_void;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::Relaxed;

use cordyceps::mpsc_queue::Links;
use cordyceps::Linked;
use log::trace;
use spin::RwLock;

use crate::arch::UserContext;
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::Process;
use crate::mem::memapi::{LowerHalfAllocation, Writable};
use crate::U64Ext;

mod id;
pub use id::*;
mod queue;
pub use queue::*;
mod stack;
pub use stack::*;
mod state;
pub use state::*;

#[derive(Debug)]
pub struct Task {
    /// The unique identifier of the task.
    tid: TaskId,
    /// The name of the task, not necessarily unique.
    name: String,
    /// The parent process that this task belongs to.
    /// If upon rescheduling, the parent process is not alive, the task will be terminated.
    process: Arc<Process>,
    /// Whether this task should be terminated upon the next reschedule.
    /// This can be set at any point.
    should_terminate: AtomicBool,
    /// The stack pointer of the task at the time of the last context switch.
    /// If this task is currently running, then this value is not the current stack pointer.
    /// This must be set during the context switch.
    last_stack_ptr: Pin<Box<usize>>,
    state: State,
    /// The kernel stack of the task. Every task starts with a stack in the higher half.
    /// Userspace tasks will then allocate a stack in the lower half, which will be stored in
    /// `ustack`.
    kstack: Option<HigherHalfStack>,

    /// The user stack of the task. This is only set if the task is a userspace task.
    ustack: RwLock<Option<LowerHalfAllocation<Writable>>>,
    tls: RwLock<Option<LowerHalfAllocation<Writable>>>,
    fx_area: RwLock<Option<LowerHalfAllocation<Writable>>>,

    links: Links<Self>,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
pub(crate) struct FxArea {
    data: [u8; 512],
}

impl Unpin for Task {}

// SAFETY: Task implements Linked for the intrusive linked list used by the scheduler.
unsafe impl Linked<Links<Self>> for Task {
    type Handle = Pin<Box<Self>>;

    fn into_ptr(r: Self::Handle) -> NonNull<Self> {
        NonNull::from(Box::leak(Pin::into_inner(r)))
    }

    // SAFETY: Required by Linked trait. Reconstructs the handle from a raw pointer.
    unsafe fn from_ptr(ptr: NonNull<Self>) -> Self::Handle {
        // SAFETY: We reconstruct the Pin<Box<Self>> from the raw pointer.
        // The pointer must have been created by `into_ptr`.
        unsafe { Pin::new(Box::from_raw(ptr.as_ptr())) }
    }

    // SAFETY: Required by Linked trait. Returns the pointer to the links field.
    unsafe fn links(ptr: NonNull<Self>) -> NonNull<Links<Self>> {
        // SAFETY: We are accessing the links field of the task.
        // The pointer is valid as guaranteed by the caller.
        let links = unsafe { &raw mut (*ptr.as_ptr()).links };
        // SAFETY: The links field is not null.
        unsafe { NonNull::new_unchecked(links) }
    }
}

impl Task {
    /// Creates a new stack in the specified process. Stack will be allocated immediately in the
    /// current address space.
    ///
    /// # Errors
    /// Returns an error if the stack could not be allocated.
    pub fn create_new(
        process: &Arc<Process>,
        entry_point: extern "C" fn(*mut c_void),
        arg: *mut c_void,
    ) -> Result<Self, StackAllocationError> {
        let stack = HigherHalfStack::allocate(16, entry_point, arg, Self::exit)?;
        Ok(Self::create_with_stack(process, stack))
    }

    pub fn create_with_stack(process: &Arc<Process>, stack: HigherHalfStack) -> Self {
        let tid = TaskId::new();
        let name = format!("task-{tid}");
        let process = process.clone();
        let should_terminate = AtomicBool::new(false);
        let state = State::Ready;
        let last_stack_ptr = Box::pin(stack.initial_rsp().as_u64().into_usize());
        let links = Links::default();
        Self {
            tid,
            name,
            process,
            should_terminate,
            last_stack_ptr,
            state,
            kstack: Some(stack),
            ustack: RwLock::new(None),
            tls: RwLock::new(None),
            fx_area: RwLock::new(None),
            links,
        }
    }

    pub(in crate::mcore::mtask) fn create_stub() -> Self {
        let tid = TaskId::new();
        let name = "stub".to_string();
        let process = Process::root().clone();
        let should_terminate = AtomicBool::new(false);
        let last_stack_ptr = Box::pin(0);
        let state = State::Finished;
        let links = Links::new_stub();
        Self {
            tid,
            name,
            process,
            should_terminate,
            last_stack_ptr,
            state,
            kstack: None,
            ustack: RwLock::new(None),
            tls: RwLock::new(None),
            fx_area: RwLock::new(None),
            links,
        }
    }

    pub(crate) extern "C" fn exit() {
        let task = ExecutionContext::load().current_task();
        trace!("exiting task {}", task.name());

        // Known entry/trampoline call sites do not hold these task-local locks,
        // so normal lock acquisition is the sound teardown.
        let _ = task.fx_area.write().take();
        let _ = task.tls.write().take();
        let _ = task.ustack.write().take();
        task.set_should_terminate(true);

        // AArch64 switches away immediately once the task is marked dead.
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
        {
            use crate::arch::traits::Architecture;
            crate::arch::aarch64::Aarch64::disable_interrupts();
            unsafe {
                ExecutionContext::load().scheduler_mut().reschedule();
            }
        }
        loop {
            #[cfg(target_arch = "x86_64")]
            // The timer interrupt performs the eventual scheduler switch.
            x86_64::instructions::interrupts::enable_and_hlt();
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfi");
            }
        }
    }

    /// Creates a Task struct for the current state of the CPU.
    /// The task is inactive, and its values must be set by the scheduler
    /// first.
    ///
    /// The resulting task will belong to the root process.
    ///
    /// # Safety
    /// The caller must ensure that this is only called once per core.
    #[must_use]
    // SAFETY: Creates a fake task representing the current execution context.
    pub unsafe fn create_current() -> Self {
        let tid = TaskId::new();
        let name = format!("task-{tid}");
        let process = Process::root().clone();
        let should_terminate = AtomicBool::new(false);

        // Get the current stack pointer
        #[cfg(target_arch = "aarch64")]
        let current_sp = {
            let sp: usize;
            core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
            sp
        };
        #[cfg(not(target_arch = "aarch64"))]
        let current_sp = 0;

        let last_stack_ptr = Box::pin(current_sp);
        let state = State::Running;
        Self {
            tid,
            name,
            process,
            should_terminate,
            last_stack_ptr,
            state,
            kstack: None,
            ustack: RwLock::new(None),
            tls: RwLock::new(None),
            fx_area: RwLock::new(None),
            links: Links::default(),
        }
    }

    pub fn id(&self) -> TaskId {
        self.tid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn process(&self) -> &Arc<Process> {
        &self.process
    }

    pub fn should_terminate(&self) -> bool {
        self.should_terminate.load(Relaxed)
    }

    pub fn set_should_terminate(&self, should_terminate: bool) {
        self.should_terminate.store(should_terminate, Relaxed);
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn kstack(&self) -> &Option<HigherHalfStack> {
        &self.kstack
    }

    /// Forks the current task into a new process.
    ///
    /// This creates a new task that is a copy of the current one, but running in the context
    /// of the new process.
    pub fn fork(
        process: &Arc<Process>,
        parent_task: &Task,
        user_context: &UserContext,
    ) -> Result<Self, StackAllocationError> {
        // 1. Allocate kernel stack for the new task
        // We use allocate_fork which sets up the stack to return to userspace via restore_user_context
        let stack = HigherHalfStack::allocate_fork(16, user_context)?;

        let tid = TaskId::new();
        let name = format!("task-{tid}");
        let should_terminate = AtomicBool::new(false);
        let state = State::Ready;
        let last_stack_ptr = Box::pin(stack.initial_rsp().as_u64().into_usize());
        let links = Links::default();

        // 2. Clone user stack if present
        let ustack = {
            let parent_ustack = parent_task.ustack.read();
            if let Some(alloc) = parent_ustack.as_ref() {
                let cloned = alloc
                    .clone_to_process(process.clone())
                    .ok_or(StackAllocationError::OutOfPhysicalMemory)?;
                Some(cloned)
            } else {
                None
            }
        };

        // 3. Clone TLS if present
        let tls = {
            let parent_tls = parent_task.tls.read();
            if let Some(alloc) = parent_tls.as_ref() {
                let cloned = alloc
                    .clone_to_process(process.clone())
                    .ok_or(StackAllocationError::OutOfPhysicalMemory)?;
                Some(cloned)
            } else {
                None
            }
        };

        // 4. Clone FPU area if present
        let fx_area = {
            let parent_fx_area_guard = parent_task.fx_area.write();
            if let Some(alloc) = parent_fx_area_guard.as_ref() {
                // Force save FPU state if on x86_64 to ensure we copy the latest state
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: We are writing to the FPU save area which we own and have locked.
                    // The allocation is guaranteed to be 16-byte aligned.
                    unsafe {
                        let ptr = alloc.start().as_mut_ptr::<u8>();
                        core::arch::x86_64::_fxsave(ptr);
                    }
                }

                let cloned = alloc
                    .clone_to_process(process.clone())
                    .ok_or(StackAllocationError::OutOfPhysicalMemory)?;
                Some(cloned)
            } else {
                None
            }
        };

        Ok(Self {
            tid,
            name,
            process: process.clone(),
            should_terminate,
            last_stack_ptr,
            state,
            kstack: Some(stack),
            ustack: RwLock::new(ustack),
            tls: RwLock::new(tls),
            fx_area: RwLock::new(fx_area),
            links,
        })
    }

    pub fn ustack(&self) -> &RwLock<Option<LowerHalfAllocation<Writable>>> {
        &self.ustack
    }

    pub fn tls(&self) -> &RwLock<Option<LowerHalfAllocation<Writable>>> {
        &self.tls
    }

    pub fn fx_area(&self) -> &RwLock<Option<LowerHalfAllocation<Writable>>> {
        &self.fx_area
    }

    pub fn last_stack_ptr(&mut self) -> &mut usize {
        self.last_stack_ptr.as_mut().get_mut()
    }
}
