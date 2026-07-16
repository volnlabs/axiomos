use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::ptr;

use conquer_once::spin::OnceCell;
use kernel_vfs::path::{AbsolutePath, ROOT};
use kernel_virtual_memory::VirtualMemoryManager;
use spin::RwLock;

use super::fd::{FdNum, FileDescriptor, FileDescriptorFlags};
use super::image::ElfSegments;
use super::mem::MemoryRegions;
use super::sleep_state::InterruptibleSleepState;
use super::telemetry::Telemetry;
use super::tree::process_tree;
use super::{trampoline, BpfCapabilities, CreateProcessError, Credentials, Process, ProcessId};
use crate::arch::VirtAddr;
use crate::file::{vfs, OpenFileDescription};
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
use crate::mcore::mtask::task::{HigherHalfStack, Task};
use crate::mem::address_space::AddressSpace;

static ROOT_PROCESS: OnceCell<Arc<Process>> = OnceCell::uninit();

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
                interruptible_sleep_state: InterruptibleSleepState::new(),
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

    pub(super) fn create_new(
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
            interruptible_sleep_state: InterruptibleSleepState::new(),
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
}
