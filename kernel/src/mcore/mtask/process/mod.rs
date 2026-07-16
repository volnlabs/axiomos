use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::{Debug, Formatter};

use conquer_once::spin::OnceCell;
use kernel_vfs::path::AbsoluteOwnedPath;
use kernel_virtual_memory::VirtualMemoryManager;
use spin::RwLock;
use thiserror::Error;

use crate::mcore::mtask::process::fd::{FdNum, FileDescriptor};
use crate::mcore::mtask::process::mem::MemoryRegions;
use crate::mcore::mtask::process::telemetry::Telemetry;
use crate::mcore::mtask::process::tree::process_tree;
use crate::mcore::mtask::task::StackAllocationError;
use crate::mem::address_space::AddressSpace;
use crate::mem::memapi::{Executable, LowerHalfAllocation};

mod credentials;
pub mod fd;
pub use credentials::{BpfCapabilities, Credentials};
mod construction;
mod executable;
mod execve;
mod image;
use image::ElfSegments;
pub(crate) use image::{ExecImage, ExecveError};
mod id;
pub use id::*;
mod fork;
mod lifecycle;
pub mod mem;
mod sleep_state;
use sleep_state::InterruptibleSleepState;
pub mod telemetry;
mod trampoline;

use crate::mcore::mtask::scheduler::wait::WaitChannel;
use crate::mem::virt::VirtualMemoryAllocator;

pub mod tree;

pub struct Process {
    pid: ProcessId,
    name: String,

    ppid: RwLock<ProcessId>,

    credentials: RwLock<Credentials>,

    exit_code: RwLock<Option<i32>>,
    child_exit_wait: OnceCell<Arc<WaitChannel>>,
    parent_exit_wait: Option<Arc<WaitChannel>>,
    interruptible_sleep_state: InterruptibleSleepState,

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
