use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::fmt::{Debug, Formatter};
use core::ptr;
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};

use conquer_once::spin::OnceCell;
use kernel_elfloader::{ElfFile, ElfLoader};
use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible};
use kernel_vfs::path::{AbsoluteOwnedPath, AbsolutePath, ROOT};
use kernel_vfs::Stat;
use kernel_virtual_memory::VirtualMemoryManager;
use log::debug;
use spin::RwLock;
use thiserror::Error;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::model_specific::FsBase;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::rflags::RFlags;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::idt::InterruptStackFrameValue;

use crate::arch::{PageSize, Size4KiB, VirtAddr};
#[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
use crate::dbg_mark;
use crate::file::{vfs, OpenFileDescription};
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::fd::{FdNum, FileDescriptor, FileDescriptorFlags};
use crate::mcore::mtask::process::mem::MemoryRegions;
use crate::mcore::mtask::process::telemetry::Telemetry;
use crate::mcore::mtask::process::tree::process_tree;
use crate::mcore::mtask::task::{HigherHalfStack, StackAllocationError, Task};
use crate::mem::address_space::AddressSpace;
use crate::mem::memapi::{Executable, LowerHalfAllocation, LowerHalfMemoryApi};
use crate::{U64Ext, UsizeExt};

mod credentials;
pub mod fd;
pub use credentials::{BpfCapabilities, Credentials};
mod executable;
use executable::executable_layout;
mod image;
#[cfg(target_arch = "aarch64")]
use image::with_process_address_space_active;
pub(crate) use image::ExecImage;
use image::{read_executable_file_into, trampoline_load_elf, ElfSegments};
mod id;
pub use id::*;
pub mod mem;
pub mod telemetry;

use crate::arch::UserContext;
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
use crate::mcore::mtask::scheduler::wait::WaitChannel;
use crate::mem::virt::VirtualMemoryAllocator;

pub mod tree;

static ROOT_PROCESS: OnceCell<Arc<Process>> = OnceCell::uninit();

#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_OPEN_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_READ_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_ELF_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_ENTER_USER_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_TTBR0_STAGE_SENT: AtomicBool = AtomicBool::new(false);

pub struct Process {
    pid: ProcessId,
    name: String,

    ppid: RwLock<ProcessId>,

    credentials: RwLock<Credentials>,

    exit_code: RwLock<Option<i32>>,
    child_exit_wait: OnceCell<Arc<WaitChannel>>,
    parent_exit_wait: Option<Arc<WaitChannel>>,
    interruptible_sleep_state: AtomicU64,

    executable_path: Option<AbsoluteOwnedPath>,
    executable_file_data: RwLock<Option<LowerHalfAllocation<Executable>>>,
    current_working_directory: RwLock<AbsoluteOwnedPath>,

    address_space: RwLock<Option<AddressSpace>>,
    lower_half_memory: Arc<RwLock<VirtualMemoryManager>>,

    telemetry: Telemetry,

    memory_regions: MemoryRegions,

    file_descriptors: RwLock<BTreeMap<FdNum, FileDescriptor>>,

    elf_segments: RwLock<ElfSegments>,
}

impl Process {
    pub fn root() -> &'static Arc<Process> {
        ROOT_PROCESS.get_or_init(|| {
            let pid = ProcessId::new();
            let root = Arc::new(Self {
                pid,
                name: "root".to_string(),
                ppid: RwLock::new(pid),
                credentials: RwLock::new(Credentials::kernel()),
                exit_code: RwLock::new(None),
                child_exit_wait: OnceCell::uninit(),
                parent_exit_wait: None,
                interruptible_sleep_state: AtomicU64::new(0),
                executable_path: None,
                executable_file_data: RwLock::new(None),
                current_working_directory: RwLock::new(ROOT.to_owned()),
                address_space: RwLock::new(None),
                lower_half_memory: Arc::new(RwLock::new(VirtualMemoryManager::new(
                    VirtAddr::new(0x00),
                    #[cfg(target_arch = "x86_64")]
                    0x0000_7FFF_FFFF_FFFF,
                    #[cfg(target_arch = "aarch64")]
                    0x0000_FFFF_FFFF_FFFF, // 48-bit user space
                ))),
                telemetry: Telemetry::default(),
                memory_regions: MemoryRegions::new(),
                file_descriptors: RwLock::new(BTreeMap::new()),
                elf_segments: RwLock::new(ElfSegments::new()),
            });
            process_tree().write().processes.insert(pid, root.clone());
            root
        })
    }

    fn create_new(
        parent: &Arc<Process>,
        name: String,
        executable_path: Option<impl AsRef<AbsolutePath>>,
        allowed_bpf_capabilities: BpfCapabilities,
    ) -> Arc<Self> {
        let pid = ProcessId::new();
        let parent_pid = parent.pid;
        let mut credentials = Credentials::inherit(parent.credentials());
        credentials.restrict_bpf_capabilities(allowed_bpf_capabilities);
        let address_space = AddressSpace::new();

        let process = Self {
            pid,
            name,
            ppid: RwLock::new(parent_pid),
            credentials: RwLock::new(credentials),
            exit_code: RwLock::new(None),
            child_exit_wait: OnceCell::uninit(),
            parent_exit_wait: Some(parent.child_exit_wait().clone()),
            interruptible_sleep_state: AtomicU64::new(0),
            executable_path: executable_path.map(|x| x.as_ref().to_owned()),
            executable_file_data: RwLock::new(None),
            current_working_directory: RwLock::new(parent.current_working_directory.read().clone()),
            address_space: RwLock::new(Some(address_space)),
            lower_half_memory: Arc::new(RwLock::new(VirtualMemoryManager::new(
                #[cfg(target_arch = "x86_64")]
                VirtAddr::new(0xF000),
                #[cfg(target_arch = "aarch64")]
                VirtAddr::new(0x2_0000_0000), // Start Location::Anywhere allocations at 8GB to leave 4GB (0x1_0000_0000) for Fixed ELF load segments
                #[cfg(target_arch = "x86_64")]
                0x0000_7FFF_FFFF_0FFF,
                #[cfg(target_arch = "aarch64")]
                0x0000_007E_0000_0000, // Size adjusted
            ))),
            telemetry: Telemetry::default(),
            memory_regions: MemoryRegions::new(),
            file_descriptors: RwLock::new(BTreeMap::new()),
            elf_segments: RwLock::new(ElfSegments::new()),
        };

        Arc::new(process)
    }

    // TODO: add documentation
    #[allow(clippy::missing_errors_doc)]
    pub fn create_from_executable(
        parent: &Arc<Process>,
        path: impl AsRef<AbsolutePath>,
    ) -> Result<Arc<Self>, CreateProcessError> {
        Self::create_from_executable_with_bpf_capabilities(parent, path, BpfCapabilities::NONE)
    }

    /// Create the first userspace process with the fixed, non-actuating init policy.
    pub fn create_userspace_init(
        parent: &Arc<Process>,
        path: impl AsRef<AbsolutePath>,
    ) -> Result<Arc<Self>, CreateProcessError> {
        Self::create_from_executable_with_bpf_capabilities(
            parent,
            path,
            BpfCapabilities::USERSPACE_INIT,
        )
    }

    /// Create a child whose BPF authority is restricted before it becomes runnable.
    pub(crate) fn create_from_executable_with_bpf_capabilities(
        parent: &Arc<Process>,
        path: impl AsRef<AbsolutePath>,
        allowed: BpfCapabilities,
    ) -> Result<Arc<Self>, CreateProcessError> {
        // TODO: validate that the executable exists and is a valid executable file

        let path = path.as_ref();
        let process = Self::create_new(parent, path.to_string(), Some(path), allowed);
        {
            // register STDIN, STDOUT and STDERR
            let mut fds = process.file_descriptors().write();

            for (i, path) in ["/dev/stdin", "/dev/stdout", "/dev/stderr"]
                .iter()
                .map(|v| AbsolutePath::try_new(v).unwrap())
                .enumerate()
            {
                let node = vfs()
                    .write()
                    .open(path)
                    .expect("should be able to open stdin");
                let ofd = OpenFileDescription::from(node);
                let fd_num = FdNum::from(i as i32);
                let fd = FileDescriptor::new(fd_num, FileDescriptorFlags::empty(), ofd.into());
                fds.insert(fd_num, fd);
            }
        }

        let kstack = HigherHalfStack::allocate(16, trampoline, ptr::null_mut(), Task::exit)?;
        let main_task = Task::create_with_stack(&process, kstack);
        parent.publish_child(process.clone());
        RunQueues::enqueue(Box::pin(main_task));

        Ok(process)
    }

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
        if let Some(parent_exit_wait) = self.parent_exit_wait.as_ref() {
            parent_exit_wait.wake_all();
        }
    }

    pub(crate) fn begin_interruptible_sleep(&self) -> u64 {
        const INACTIVE: u64 = 0;
        const ACTIVE: u64 = 1;
        loop {
            let current = self.interruptible_sleep_state.load(Ordering::Acquire);
            assert_eq!(
                current & 3,
                INACTIVE,
                "process already has an interruptible sleeper"
            );
            let generation = (current >> 2).wrapping_add(1);
            let next = (generation << 2) | ACTIVE;
            if self
                .interruptible_sleep_state
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return generation;
            }
        }
    }

    #[must_use]
    pub(crate) fn request_sleep_interrupt(&self) -> bool {
        const ACTIVE: u64 = 1;
        const INTERRUPT_REQUESTED: u64 = 2;
        let current = self.interruptible_sleep_state.load(Ordering::Acquire);
        current & 3 == ACTIVE
            && self
                .interruptible_sleep_state
                .compare_exchange(
                    current,
                    (current & !3) | INTERRUPT_REQUESTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    #[must_use]
    pub(crate) fn sleep_interrupt_requested(&self, generation: u64) -> bool {
        const INTERRUPT_REQUESTED: u64 = 2;
        self.interruptible_sleep_state.load(Ordering::Acquire)
            == (generation << 2) | INTERRUPT_REQUESTED
    }

    /// Complete one exact sleep generation and report whether interruption won.
    pub(crate) fn finish_interruptible_sleep(&self, generation: u64) -> bool {
        const INACTIVE: u64 = 0;
        const ACTIVE: u64 = 1;
        const INTERRUPT_REQUESTED: u64 = 2;
        loop {
            let current = self.interruptible_sleep_state.load(Ordering::Acquire);
            assert_eq!(current >> 2, generation, "sleep generation changed");
            assert!(
                matches!(current & 3, ACTIVE | INTERRUPT_REQUESTED),
                "sleep generation completed twice"
            );
            if self
                .interruptible_sleep_state
                .compare_exchange(
                    current,
                    (generation << 2) | INACTIVE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return current & 3 == INTERRUPT_REQUESTED;
            }
        }
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    pub fn ppid(&self) -> ProcessId {
        *self.ppid.read()
    }

    /// Return an immutable snapshot of the process credentials.
    #[must_use]
    pub fn credentials(&self) -> Credentials {
        *self.credentials.read()
    }

    #[must_use]
    pub fn bpf_capabilities(&self) -> BpfCapabilities {
        self.credentials().bpf_capabilities()
    }

    /// Permanently restrict this process to a subset of its current BPF capabilities.
    pub fn restrict_bpf_capabilities(&self, allowed: BpfCapabilities) -> BpfCapabilities {
        self.credentials.write().restrict_bpf_capabilities(allowed)
    }

    /// Permanently remove BPF capabilities from this process.
    pub fn drop_bpf_capabilities(&self, removed: BpfCapabilities) -> BpfCapabilities {
        self.credentials.write().drop_bpf_capabilities(removed)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn file_descriptors(&self) -> &RwLock<BTreeMap<FdNum, FileDescriptor>> {
        &self.file_descriptors
    }

    pub fn with_address_space<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&AddressSpace) -> R,
    {
        let guard = self.address_space.read();
        let as_ref = guard.as_ref().unwrap_or(AddressSpace::kernel());

        #[cfg(target_arch = "x86_64")]
        {
            // x86_64 page-table operations use the recursive mapping, which only
            // points at the process page tables while that CR3 is active.
            as_ref.with_active(f)
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            f(as_ref)
        }
    }

    pub(crate) fn mark_address_space_resident(&self, cpu_id: usize) {
        let guard = self.address_space.read();
        guard
            .as_ref()
            .unwrap_or(AddressSpace::kernel())
            .mark_cpu_resident(cpu_id);
    }

    pub fn vmm(self: &Arc<Self>) -> impl VirtualMemoryAllocator {
        self.lower_half_memory.clone()
    }

    pub fn current_working_directory(&self) -> &RwLock<AbsoluteOwnedPath> {
        &self.current_working_directory
    }

    pub fn memory_regions(&self) -> &MemoryRegions {
        &self.memory_regions
    }

    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    /// Forks the process, creating a exact copy of memory and file descriptors.
    ///
    /// # Errors
    /// Returns an error if memory allocation fails.
    pub fn fork(
        self: &Arc<Self>,
        current_task: &Task,
        ctx: &UserContext,
    ) -> Result<Arc<Self>, &'static str> {
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
                    .ok_or("Failed to clone executable data")?;
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
                        .ok_or("Failed to clone executable ELF segment")?,
                );
            }
            for alloc in &parent_segs.readonly {
                child_segs.readonly.push(
                    alloc
                        .clone_to_process(child.clone())
                        .ok_or("Failed to clone readonly ELF segment")?,
                );
            }
            for alloc in &parent_segs.writable {
                child_segs.writable.push(
                    alloc
                        .clone_to_process(child.clone())
                        .ok_or("Failed to clone writable ELF segment")?,
                );
            }
        }

        // 5. Build the task before publishing the child. Any earlier failure
        // drops the unpublished process and rolls back all cloned allocations.
        let child_task = Task::fork(&child, current_task, ctx)
            .map_err(|_| "Failed to allocate stack for child task")?;

        // 6. Atomically publish the fully constructed child, then make it runnable.
        self.publish_child(child.clone());
        RunQueues::enqueue(Box::pin(child_task));

        Ok(child)
    }

    /// Replaces the current process image with a preflight-validated executable.
    ///
    /// # Errors
    /// Returns an error if the executable cannot be loaded or memory allocation fails.
    pub(crate) fn execve(
        self: &Arc<Self>,
        file_content: Vec<u8>,
        _argv: &[String],
        _envp: &[String],
    ) -> Result<ExecImage, &'static str> {
        // Clear process allocations
        *self.executable_file_data.write() = None;

        // Clear ELF segment allocations (unmaps from current AS before reset)
        self.elf_segments.write().clear();

        // Clear memory regions (Deallocates physical frames)
        self.memory_regions.clear();

        // 3. Reset Address Space and VMM
        {
            let mut as_guard = self.address_space.write();
            let mut vmm_guard = self.lower_half_memory.write();

            // Create fresh AddressSpace and VMM
            *as_guard = Some(AddressSpace::new());
            as_guard
                .as_ref()
                .expect("exec address space was just installed")
                .activate();

            *vmm_guard = VirtualMemoryManager::new(
                #[cfg(target_arch = "x86_64")]
                VirtAddr::new(0xF000),
                #[cfg(target_arch = "aarch64")]
                VirtAddr::new(0x1_0000_0000),
                #[cfg(target_arch = "x86_64")]
                0x0000_7FFF_FFFF_0FFF,
                #[cfg(target_arch = "aarch64")]
                0x0000_007F_0000_0000,
            );
        }

        // 4. Load the new executable
        // We use the same self reference, but now it points to the new AS/VMM
        let mut memapi = LowerHalfMemoryApi::new(self.clone());

        // Need to verify it's a valid ELF first. Surface the typed
        // ElfParseError so a malformed binary (audit H-05) is
        // diagnosable from logs instead of a generic "Invalid ELF
        // file" line.
        let elf_file = ElfFile::try_parse(&file_content).map_err(|e| {
            log::error!("execve: ELF parse error: {e}");
            "Invalid ELF file"
        })?;

        let elf_image = ElfLoader::new(memapi.clone()).load(elf_file).map_err(|e| {
            log::error!("execve: ELF load error: {e}");
            "Failed to load ELF"
        })?;

        let entry_point = elf_image.entry_point() as usize;
        let (exec_allocs, mut ro_allocs, wr_allocs, tls_master) = elf_image.into_inner();

        // 5. Setup TLS if present
        let tls_allocation = if let Some(ref master_tls) = tls_master {
            let mut tls_alloc = memapi
                .allocate(
                    Location::Anywhere,
                    master_tls.layout(),
                    UserAccessible::Yes,
                    Guarded::No,
                )
                .ok_or("Failed to allocate TLS")?;

            let slice = tls_alloc.as_mut();
            slice.copy_from_slice(master_tls.as_ref());
            Some(tls_alloc)
        } else {
            None
        };

        // 6. Allocate new User Stack
        let ustack_allocation = memapi
            .allocate(
                Location::Anywhere,
                Layout::from_size_align(
                    Size4KiB::SIZE.into_usize() * 256, // 1MB stack
                    Size4KiB::SIZE.into_usize(),
                )
                .unwrap(),
                UserAccessible::Yes,
                Guarded::Yes,
            )
            .ok_or("Failed to allocate user stack")?;

        let ustack_rsp = ustack_allocation.start() + ustack_allocation.len().into_u64();

        // Store ELF segment allocations so they aren't dropped
        {
            let mut segs = self.elf_segments.write();
            segs.executable = exec_allocs;
            if let Some(tls) = tls_master {
                ro_allocs.push(tls);
            }
            segs.readonly = ro_allocs;
            segs.writable = wr_allocs;
        }

        Ok(ExecImage {
            entry_point,
            stack_pointer: ustack_rsp.as_u64().into_usize(),
            tls: tls_allocation,
            user_stack: ustack_allocation,
        })
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut ds = f.debug_struct("Process");
        ds.field("pid", &self.pid)
            .field("ppid", &*self.ppid.read())
            .field("name", &self.name);
        self.with_address_space(|as_| ds.field("address_space", as_));
        ds.finish_non_exhaustive()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(address_space) = self.address_space.get_mut().as_ref() {
            #[cfg(target_arch = "x86_64")]
            address_space.with_active(|active| self.memory_regions.release_all_in(active));

            #[cfg(not(target_arch = "x86_64"))]
            self.memory_regions.release_all_in(address_space);
        }

        let my_ppid = *self.ppid.read();
        let mut guard = process_tree().write();
        if guard.processes.remove(&self.pid).is_none() {
            return;
        }
        if let Some(children) = guard.children.remove(&self.pid) {
            for child in children {
                *child.ppid.write() = my_ppid;
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum CreateProcessError {
    #[error("failed to allocate stack")]
    StackAllocationError(#[from] StackAllocationError),
}

extern "C" fn trampoline(_arg: *mut c_void) {
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'u' as u32);
    }

    log::info!("Trampoline started");
    let ctx = ExecutionContext::load();
    log::info!("Trampoline: context loaded");
    let current_process = ctx.current_process();
    log::info!("Trampoline: current process got");

    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_OPEN_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'q' as u32);
    }

    let executable_path = current_process
        .executable_path
        .as_ref()
        .expect("should have an executable path");
    log::info!("Trampoline: opening executable {:?}", executable_path);
    let node = vfs()
        .write()
        .open(executable_path)
        .unwrap_or_else(|_| Task::terminate_current(1, "failed to open executable"));
    log::info!("Trampoline: executable opened");
    let stat = {
        let mut stat = Stat::default();
        node.stat(&mut stat)
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to stat executable"));
        stat
    };
    log::info!("Trampoline: executable stated, size={}", stat.size);
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_READ_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'r' as u32);
    }

    let mut memapi = LowerHalfMemoryApi::new(current_process.clone());

    log::info!("Trampoline: allocating memory for executable");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'A' as u32);
    let layout = executable_layout(stat.size)
        .unwrap_or_else(|error| Task::terminate_current(1, error.message()));
    let mut executable_file_allocation = memapi
        .allocate(Location::Anywhere, layout, UserAccessible::Yes, Guarded::No)
        .unwrap_or_else(|| Task::terminate_current(1, "failed to allocate executable file"));
    log::info!("Trampoline: memory allocated");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'B' as u32);

    #[cfg(target_arch = "aarch64")]
    with_process_address_space_active(&current_process, || {
        let buf = executable_file_allocation.as_mut();
        read_executable_file_into(&node, buf, stat.size, "Trampoline")
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to read executable file"));
    });
    #[cfg(not(target_arch = "aarch64"))]
    {
        let buf = executable_file_allocation.as_mut();
        read_executable_file_into(&node, buf, stat.size, "Trampoline")
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to read executable file"));
    }
    log::info!("Trampoline: executable read into memory");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'C' as u32);

    // Parse and load ELF while the file allocation is still writable (readable).
    // make_executable is deferred until after into_inner() releases the borrow.
    log::info!("Trampoline: parsing ELF");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'D' as u32);

    #[cfg(target_arch = "aarch64")]
    let (code_ptr, exec_allocs, mut ro_allocs, wr_allocs, tls_master) =
        match with_process_address_space_active(&current_process, || {
            // Keep all borrowed ELF reads in the active process address space.
            trampoline_load_elf(executable_file_allocation.as_ref(), memapi.clone())
        }) {
            Ok((code_ptr, (exec_allocs, ro_allocs, wr_allocs, tls_master))) => {
                log::info!("Trampoline: ELF loaded");
                (code_ptr, exec_allocs, ro_allocs, wr_allocs, tls_master)
            }
            Err(err) => {
                log::error!("Trampoline: {err}");
                Task::terminate_current(1, "ELF load failed");
            }
        };
    #[cfg(not(target_arch = "aarch64"))]
    let (code_ptr, exec_allocs, mut ro_allocs, wr_allocs, tls_master) =
        match trampoline_load_elf(executable_file_allocation.as_ref(), memapi.clone()) {
            Ok((code_ptr, (exec_allocs, ro_allocs, wr_allocs, tls_master))) => {
                log::info!("Trampoline: ELF loaded");
                (code_ptr, exec_allocs, ro_allocs, wr_allocs, tls_master)
            }
            Err(err) => {
                log::error!("Trampoline: {err}");
                Task::terminate_current(1, "ELF load failed");
            }
        };
    #[cfg(all(
        not(target_arch = "aarch64"),
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    dbg_mark(b'E' as u32);
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_ELF_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b's' as u32);
    }

    // Now that the ELF borrow is released, make the file allocation executable for storage.
    #[cfg(target_arch = "aarch64")]
    let executable_file_allocation = with_process_address_space_active(&current_process, || {
        memapi
            .make_executable(executable_file_allocation)
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to protect executable file"))
    });
    #[cfg(not(target_arch = "aarch64"))]
    let executable_file_allocation = memapi
        .make_executable(executable_file_allocation)
        .unwrap_or_else(|_| Task::terminate_current(1, "failed to protect executable file"));

    if let Some(ref master_tls) = tls_master {
        log::info!("Trampoline: setting up TLS");
        let mut tls_alloc = memapi
            .allocate(
                Location::Anywhere,
                master_tls.layout(),
                UserAccessible::Yes,
                Guarded::No,
            )
            .unwrap_or_else(|| Task::terminate_current(1, "failed to allocate executable TLS"));

        #[cfg(target_arch = "aarch64")]
        with_process_address_space_active(&current_process, || {
            let slice = tls_alloc.as_mut();
            slice.copy_from_slice(master_tls.as_ref());
        });
        #[cfg(not(target_arch = "aarch64"))]
        {
            let slice = tls_alloc.as_mut();
            slice.copy_from_slice(master_tls.as_ref());
        }

        #[cfg(target_arch = "x86_64")]
        FsBase::write(tls_alloc.start());
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Writing to TPIDR_EL0 is safe in EL1.
            unsafe {
                let val = tls_alloc.start().as_u64();
                core::arch::asm!("msr tpidr_el0, {}", in(reg) val);
            }
        }

        {
            ctx.with_current_task(|task| {
                let mut guard = task.tls().write();
                assert!(guard.is_none(), "TLS should not exist yet");
                *guard = Some(tls_alloc);
            });
        }
    }

    // Store ELF segment allocations in the process so they survive and can be cloned during fork
    {
        let mut segs = current_process.elf_segments.write();
        segs.executable = exec_allocs;
        if let Some(tls) = tls_master {
            ro_allocs.push(tls);
        }
        segs.readonly = ro_allocs;
        segs.writable = wr_allocs;
    }

    log::info!("Trampoline: allocating user stack");
    let mut memapi = LowerHalfMemoryApi::new(current_process.clone());
    let ustack_allocation = memapi
        .allocate(
            Location::Anywhere,
            Layout::from_size_align(
                Size4KiB::SIZE.into_usize() * 256,
                Size4KiB::SIZE.into_usize(),
            )
            .unwrap(),
            UserAccessible::Yes,
            Guarded::Yes,
        )
        .unwrap_or_else(|| Task::terminate_current(1, "failed to allocate userspace stack"));

    let ustack_rsp = ustack_allocation.start() + ustack_allocation.len().into_u64();
    log::info!(
        "Trampoline: ustack_rsp={:#x}, entry_point={:#x}",
        ustack_rsp.as_u64(),
        code_ptr
    );
    {
        ctx.with_current_task(|task| {
            let mut ustack_guard = task.ustack().write();
            assert!(ustack_guard.is_none(), "ustack should not exist yet");
            *ustack_guard = Some(ustack_allocation);
        });
    }
    // assert!(ustack_rsp.is_aligned(16_u64));

    #[cfg(target_arch = "x86_64")]
    let sel = ctx.selectors();

    let _ = current_process
        .executable_file_data
        .write()
        .insert(executable_file_allocation);

    debug!("stack_ptr: {:p}", ustack_rsp.as_ptr::<u8>());
    debug!("code_ptr: {:p}", code_ptr as *const u8);

    {
        let mut guard = current_process.file_descriptors.write();

        let devnull = vfs()
            .read()
            .open(AbsolutePath::try_new("/dev/null").unwrap())
            .expect("should be able to open /dev/null");
        let devnull_ofd = Arc::new(OpenFileDescription::from(devnull));
        guard.insert(
            0.into(),
            FileDescriptor::new(0.into(), FileDescriptorFlags::empty(), devnull_ofd.clone()),
        );

        let devserial = vfs()
            .read()
            .open(AbsolutePath::try_new("/dev/serial").unwrap())
            .expect("should be able to open /dev/serial");
        let devserial_ofd = Arc::new(OpenFileDescription::from(devserial));
        guard.insert(
            1.into(),
            FileDescriptor::new(
                1.into(),
                FileDescriptorFlags::empty(),
                devserial_ofd.clone(),
            ),
        );
        guard.insert(
            2.into(),
            FileDescriptor::new(
                2.into(),
                FileDescriptorFlags::empty(),
                devserial_ofd.clone(),
            ),
        );
    }

    #[cfg(target_arch = "x86_64")]
    {
        let isfv = InterruptStackFrameValue::new(
            VirtAddr::new(code_ptr as u64),
            sel.user_code,
            RFlags::INTERRUPT_FLAG,
            ustack_rsp,
            sel.user_data,
        );
        // SAFETY: We have set up the user stack and code pointer correctly, and we are
        // performing a return to userspace (Ring 3) to start the process execution.
        unsafe { isfv.iretq() };
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: We have set up the user stack and code pointer correctly.
        // We are entering userspace (EL0).
        // Before entering, we must ensure the process's address space is active.
        unsafe {
            #[cfg(all(
                target_arch = "aarch64",
                feature = "rpi5",
                feature = "bringup-diagnostics"
            ))]
            if !TRAMPOLINE_ENTER_USER_STAGE_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b't' as u32);
            }
            #[cfg(all(
                target_arch = "aarch64",
                feature = "rpi5",
                feature = "bringup-diagnostics"
            ))]
            if !TRAMPOLINE_TTBR0_STAGE_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'0' as u32);
            }

            let ttbr0 = current_process.with_address_space(|as_| as_.ttbr0_value());
            crate::arch::aarch64::paging::set_ttbr0(ttbr0);

            #[cfg(all(
                target_arch = "aarch64",
                feature = "rpi5",
                feature = "bringup-diagnostics"
            ))]
            dbg_mark(b'Q' as u32);

            crate::arch::aarch64::context::enter_userspace(code_ptr, ustack_rsp.as_u64() as usize);
        }
    }
}
