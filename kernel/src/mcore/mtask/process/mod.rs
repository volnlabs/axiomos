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
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
use core::sync::atomic::{AtomicBool, Ordering};

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
#[cfg(feature = "rpi5")]
use crate::dbg_mark;
use crate::file::{vfs, OpenFileDescription};
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::fd::{FdNum, FileDescriptor, FileDescriptorFlags};
use crate::mcore::mtask::process::mem::MemoryRegions;
use crate::mcore::mtask::process::telemetry::Telemetry;
use crate::mcore::mtask::process::tree::process_tree;
use crate::mcore::mtask::task::{HigherHalfStack, StackAllocationError, Task};
use crate::mem::address_space::AddressSpace;
use crate::mem::memapi::{Executable, LowerHalfAllocation, LowerHalfMemoryApi, Readonly, Writable};
use crate::{U64Ext, UsizeExt};

pub mod fd;
mod id;
pub use id::*;
pub mod mem;
pub mod telemetry;

use crate::arch::UserContext;
use crate::mcore::mtask::scheduler::global::GlobalTaskQueue;
use crate::mem::virt::VirtualMemoryAllocator;

pub mod tree;

struct ElfSegments {
    executable: Vec<LowerHalfAllocation<Executable>>,
    readonly: Vec<LowerHalfAllocation<Readonly>>,
    writable: Vec<LowerHalfAllocation<Writable>>,
}

impl ElfSegments {
    fn new() -> Self {
        Self {
            executable: Vec::new(),
            readonly: Vec::new(),
            writable: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.executable.clear();
        self.readonly.clear();
        self.writable.clear();
    }
}

static ROOT_PROCESS: OnceCell<Arc<Process>> = OnceCell::uninit();

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static TRAMPOLINE_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static TRAMPOLINE_OPEN_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static TRAMPOLINE_READ_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static TRAMPOLINE_ELF_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static TRAMPOLINE_ENTER_USER_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
static TRAMPOLINE_TTBR0_STAGE_SENT: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn with_process_address_space_active<T, F>(process: &Arc<Process>, f: F) -> T
where
    F: FnOnce() -> T,
{
    // SAFETY: While TTBR0 is temporarily switched via with_active(), keep IRQs masked
    // because the rpi5 scheduler path does not currently save/restore TTBR0 on switch.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nostack, preserves_flags));
    }
    let current_ttbr0 = crate::arch::aarch64::paging::get_ttbr0();
    let target_ttbr0 = {
        let guard = process.address_space.read();
        guard
            .as_ref()
            .expect("process should have an address space")
            .ttbr0_value()
    };

    if target_ttbr0 != current_ttbr0 {
        // SAFETY: target_ttbr0 is the process's L0 page table root.
        unsafe {
            crate::arch::aarch64::paging::set_ttbr0(target_ttbr0);
        }
    }

    let out = f();

    if target_ttbr0 != current_ttbr0 {
        // SAFETY: Restore the original TTBR0 after scoped access.
        unsafe {
            crate::arch::aarch64::paging::set_ttbr0(current_ttbr0);
        }
    }

    // SAFETY: Restore normal IRQ state after finishing user-AS memory access.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nostack, preserves_flags));
    }
    out
}

pub struct Process {
    pid: ProcessId,
    name: String,

    ppid: RwLock<ProcessId>,

    exit_code: RwLock<Option<i32>>,

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
                exit_code: RwLock::new(None),
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
    ) -> Arc<Self> {
        let pid = ProcessId::new();
        let parent_pid = parent.pid;
        let address_space = AddressSpace::new();

        let process = Self {
            pid,
            name,
            ppid: RwLock::new(parent_pid),
            exit_code: RwLock::new(None),
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

        let res = Arc::new(process);
        process_tree().write().processes.insert(pid, res.clone());
        res
    }

    // TODO: add documentation
    #[allow(clippy::missing_errors_doc)]
    pub fn create_from_executable(
        parent: &Arc<Process>,
        path: impl AsRef<AbsolutePath>,
    ) -> Result<Arc<Self>, CreateProcessError> {
        // TODO: validate that the executable exists and is a valid executable file

        let path = path.as_ref();
        let process = Self::create_new(parent, path.to_string(), Some(path));
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
        GlobalTaskQueue::enqueue(Box::pin(main_task));

        Ok(process)
    }

    pub fn exit_code(&self) -> &RwLock<Option<i32>> {
        &self.exit_code
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    pub fn ppid(&self) -> ProcessId {
        *self.ppid.read()
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
        f(as_ref)
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

        // 5. Register child in process tree
        self.children_mut().insert(child.clone());

        // 6. Fork the Task
        let child_task = Task::fork(&child, current_task, ctx)
            .map_err(|_| "Failed to allocate stack for child task")?;
        GlobalTaskQueue::enqueue(Box::pin(child_task));

        Ok(child)
    }
    /// Replaces the current process image with a new executable.
    ///
    /// # Errors
    /// Returns an error if the executable cannot be loaded or memory allocation fails.
    pub fn execve(
        self: &Arc<Self>,
        current_task: &Task,
        path: &AbsolutePath,
        _argv: &[String],
        _envp: &[String],
    ) -> Result<(usize, usize), &'static str> {
        // 1. Open and read the executable file
        // We do this first before destroying the current process state
        let node = vfs()
            .write()
            .open(path)
            .map_err(|_| "Failed to open executable")?;

        let mut stat = Stat::default();
        node.stat(&mut stat)
            .map_err(|_| "Failed to stat executable")?;

        // Read file into a temporary kernel buffer
        // TODO: This might be too large for kernel heap.
        // For now, we assume reasonable executable sizes.
        let mut file_content = alloc::vec![0u8; stat.size];
        let mut offset = 0;
        loop {
            let read = node
                .read(&mut file_content[offset..], offset)
                .map_err(|_| "Failed to read executable")?;
            if read == 0 {
                break;
            }
            offset += read;
        }

        // 2. Clear existing process state

        // Clear task-specific allocations (User stack, TLS)
        // These allocations (LowerHalfAllocation) will try to unmap from the *current* address space on Drop.
        // This is what we want.
        *current_task.ustack().write() = None;
        *current_task.tls().write() = None;

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

        // Need to verify it's a valid ELF first
        let elf_file = ElfFile::try_parse(&file_content).map_err(|_| "Invalid ELF file")?;

        let elf_image = ElfLoader::new(memapi.clone())
            .load(elf_file)
            .map_err(|_| "Failed to load ELF")?;

        let entry_point = elf_image.entry_point() as usize;
        let (exec_allocs, mut ro_allocs, wr_allocs, tls_master) = elf_image.into_inner();

        // 5. Setup TLS if present
        if let Some(ref master_tls) = tls_master {
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

            #[cfg(target_arch = "x86_64")]
            FsBase::write(tls_alloc.start());
            #[cfg(target_arch = "aarch64")]
            {
                unsafe {
                    let val = tls_alloc.start().as_u64();
                    core::arch::asm!("msr tpidr_el0, {}", in(reg) val);
                }
            }

            *current_task.tls().write() = Some(tls_alloc);
        }

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
        *current_task.ustack().write() = Some(ustack_allocation);

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

        Ok((entry_point, ustack_rsp.as_u64().into_usize()))
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
        let my_ppid = *self.ppid.read();
        let mut guard = process_tree().write();
        guard
            .processes
            .remove(&self.pid)
            .expect("process should be in process tree");
        if let Some(children) = guard.children.remove(&self.pid) {
            for child in children {
                *child.ppid.write() = my_ppid;
            }
        }

        // TODO: deallocate all physical frames that are not part of a shared mapping
    }
}

#[derive(Debug, Error)]
pub enum CreateProcessError {
    #[error("failed to allocate stack")]
    StackAllocationError(#[from] StackAllocationError),
}

extern "C" fn trampoline(_arg: *mut c_void) {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    if !TRAMPOLINE_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'u' as u32);
    }

    log::info!("Trampoline started");
    let ctx = ExecutionContext::load();
    log::info!("Trampoline: context loaded");
    let current_task = ctx.scheduler().current_task();
    log::info!("Trampoline: current task got");
    let current_process = current_task.process().clone();
    log::info!("Trampoline: current process got");

    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
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
        .expect("should be able to open executable");
    log::info!("Trampoline: executable opened");
    let stat = {
        let mut stat = Stat::default();
        node.stat(&mut stat)
            .expect("should be able to stat executable");
        stat
    };
    log::info!("Trampoline: executable stated, size={}", stat.size);
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    if !TRAMPOLINE_READ_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'r' as u32);
    }

    let mut memapi = LowerHalfMemoryApi::new(current_process.clone());

    log::info!("Trampoline: allocating memory for executable");
    #[cfg(feature = "rpi5")]
    dbg_mark(b'A' as u32);
    let mut executable_file_allocation = memapi
        .allocate(
            Location::Anywhere,
            Layout::from_size_align(stat.size, Size4KiB::SIZE.into_usize()).unwrap(),
            UserAccessible::Yes,
            Guarded::No,
        )
        .expect("should be able to allocate memory for executable file");
    log::info!("Trampoline: memory allocated");
    #[cfg(feature = "rpi5")]
    dbg_mark(b'B' as u32);

    #[cfg(target_arch = "aarch64")]
    with_process_address_space_active(&current_process, || {
        let buf = executable_file_allocation.as_mut();
        let mut offset = 0;
        loop {
            let read = node
                .read(&mut buf[offset..], offset)
                .expect("should be able to read");
            if read == 0 {
                break;
            }
            offset += read;
        }
    });
    #[cfg(not(target_arch = "aarch64"))]
    {
        let buf = executable_file_allocation.as_mut();
        let mut offset = 0;
        loop {
            let read = node
                .read(&mut buf[offset..], offset)
                .expect("should be able to read");
            if read == 0 {
                break;
            }
            offset += read;
        }
    }
    log::info!("Trampoline: executable read into memory");
    #[cfg(feature = "rpi5")]
    dbg_mark(b'C' as u32);

    // Parse and load ELF while the file allocation is still writable (readable).
    // make_executable is deferred until after into_inner() releases the borrow.
    log::info!("Trampoline: parsing ELF");
    #[cfg(feature = "rpi5")]
    dbg_mark(b'D' as u32);

    #[cfg(target_arch = "aarch64")]
    let (code_ptr, exec_allocs, mut ro_allocs, wr_allocs, tls_master) =
        with_process_address_space_active(&current_process, || {
            // Keep all borrowed ELF reads in the active process address space.
            let elf_file = ElfFile::try_parse(executable_file_allocation.as_ref())
                .expect("should be able to parse elf binary");
            let code_ptr = elf_file.entry();
            log::info!("Trampoline: ELF parsed, loading...");
            #[cfg(feature = "rpi5")]
            dbg_mark(b'E' as u32);
            let elf_image = ElfLoader::new(memapi.clone())
                .load(elf_file)
                .expect("should be able to load elf file");
            let (exec_allocs, ro_allocs, wr_allocs, tls_master) = elf_image.into_inner();
            (code_ptr, exec_allocs, ro_allocs, wr_allocs, tls_master)
        });
    #[cfg(not(target_arch = "aarch64"))]
    let elf_file = ElfFile::try_parse(executable_file_allocation.as_ref())
        .expect("should be able to parse elf binary");
    #[cfg(not(target_arch = "aarch64"))]
    let code_ptr = elf_file.entry();
    #[cfg(not(target_arch = "aarch64"))]
    log::info!("Trampoline: ELF parsed, loading...");
    #[cfg(all(not(target_arch = "aarch64"), feature = "rpi5"))]
    dbg_mark(b'E' as u32);
    #[cfg(not(target_arch = "aarch64"))]
    let elf_image = ElfLoader::new(memapi.clone())
        .load(elf_file)
        .expect("should be able to load elf file");
    #[cfg(not(target_arch = "aarch64"))]
    let (exec_allocs, mut ro_allocs, wr_allocs, tls_master) = elf_image.into_inner();
    log::info!("Trampoline: ELF loaded");
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    if !TRAMPOLINE_ELF_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b's' as u32);
    }

    // Now that the ELF borrow is released, make the file allocation executable for storage.
    #[cfg(target_arch = "aarch64")]
    let executable_file_allocation = with_process_address_space_active(&current_process, || {
        memapi
            .make_executable(executable_file_allocation)
            .expect("should be able to make allocation executable")
    });
    #[cfg(not(target_arch = "aarch64"))]
    let executable_file_allocation = memapi
        .make_executable(executable_file_allocation)
        .expect("should be able to make allocation executable");

    if let Some(ref master_tls) = tls_master {
        log::info!("Trampoline: setting up TLS");
        let mut tls_alloc = memapi
            .allocate(
                Location::Anywhere,
                master_tls.layout(),
                UserAccessible::Yes,
                Guarded::No,
            )
            .expect("should be able to allocate TLS data");

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
            let mut guard = current_task.tls().write();
            assert!(guard.is_none(), "TLS should not exist yet");
            *guard = Some(tls_alloc);
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
        .expect("should be able to allocate userspace stack");

    let ustack_rsp = ustack_allocation.start() + ustack_allocation.len().into_u64();
    log::info!(
        "Trampoline: ustack_rsp={:#x}, entry_point={:#x}",
        ustack_rsp.as_u64(),
        code_ptr
    );
    {
        let mut ustack_guard = current_task.ustack().write();
        assert!(ustack_guard.is_none(), "ustack should not exist yet");
        *ustack_guard = Some(ustack_allocation);
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
            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            if !TRAMPOLINE_ENTER_USER_STAGE_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b't' as u32);
            }
            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            if !TRAMPOLINE_TTBR0_STAGE_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'0' as u32);
            }

            let ttbr0 = current_process.with_address_space(|as_| as_.ttbr0_value());
            crate::arch::aarch64::paging::set_ttbr0(ttbr0);

            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            dbg_mark(b'Q' as u32);

            crate::arch::aarch64::context::enter_userspace(code_ptr, ustack_rsp.as_u64() as usize);
        }
    }
}
