use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::fmt::{Debug, Formatter};
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
use core::sync::atomic::AtomicBool;

use conquer_once::spin::OnceCell;
use kernel_elfloader::{ElfFile, ElfLoader};
use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible};
use kernel_vfs::path::{AbsoluteOwnedPath, AbsolutePath};
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
use crate::mcore::mtask::task::{StackAllocationError, Task};
use crate::mem::address_space::AddressSpace;
use crate::mem::memapi::{Executable, LowerHalfAllocation, LowerHalfMemoryApi};
use crate::{U64Ext, UsizeExt};

mod credentials;
pub mod fd;
pub use credentials::{BpfCapabilities, Credentials};
mod construction;
mod executable;
use executable::executable_layout;
mod image;
#[cfg(target_arch = "aarch64")]
use image::with_process_address_space_active;
use image::{read_executable_file_into, trampoline_load_elf, ElfSegments};
pub(crate) use image::{ExecImage, ExecveError};
mod id;
pub use id::*;
mod fork;
mod lifecycle;
pub mod mem;
mod sleep_state;
use sleep_state::InterruptibleSleepState;
pub mod telemetry;

use crate::mcore::mtask::scheduler::wait::WaitChannel;
use crate::mem::virt::VirtualMemoryAllocator;

pub mod tree;

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

    /// Replaces the current process image with a preflight-validated executable.
    ///
    /// # Errors
    /// Returns a typed [`ExecveError`] if the executable cannot be
    /// loaded, a segment allocation fails, the TLS copy fails to
    /// allocate, or the user-stack allocation fails. On any
    /// failure, the local segment / TLS / stack allocations are
    /// dropped, which releases the underlying physical frames via
    /// the `LowerHalfAllocation` `Drop` impl. The process's
    /// tracked `elf_segments` / `executable_file_data` /
    /// `memory_regions` are only rewritten on success, so a
    /// failed `execve` does not leave the process pointing at a
    /// half-installed image.
    pub(crate) fn execve(
        self: &Arc<Self>,
        file_content: Vec<u8>,
        _argv: &[String],
        _envp: &[String],
    ) -> Result<ExecImage, ExecveError> {
        // Stage 1: parse the ELF. No allocations are made yet, so
        // a parse failure leaves the process untouched.
        let elf_file = ElfFile::try_parse(&file_content).map_err(|e| {
            log::error!("execve: ELF parse error: {e}");
            ExecveError::Parse(e)
        })?;

        // Stage 2: clear the old process state. From this point on
        // we MUST build the new image successfully or the process
        // is in a "reset" state. The build itself is
        // failure-recovering via Drop on the local segment / TLS /
        // stack allocations.
        *self.executable_file_data.write() = None;
        self.elf_segments.write().clear();
        self.memory_regions.clear();

        // Reset Address Space and VMM. The new AS is "staged" but
        // not yet tracked in `process.elf_segments` — the loader
        // installs segments into the new AS via `LowerHalfMemoryApi`,
        // and on failure the local `ElfImage` is dropped, which
        // unmaps those segments and releases the underlying frames.
        let mut memapi = {
            let mut as_guard = self.address_space.write();
            let mut vmm_guard = self.lower_half_memory.write();

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

            LowerHalfMemoryApi::new(self.clone())
        };

        // Stage 3: load the new executable. `ElfImage` owns the
        // segment allocations; on `?` it is dropped, which unmap +
        // release each segment.
        let elf_image = ElfLoader::new(memapi.clone()).load(elf_file).map_err(|e| {
            log::error!("execve: ELF load error: {e}");
            ExecveError::Load(e)
        })?;

        let entry_point = elf_image.entry_point() as usize;
        let (exec_allocs, mut ro_allocs, wr_allocs, tls_master) = elf_image.into_inner();

        // Stage 4: TLS copy. `tls_alloc` is dropped on the
        // `?`-branch, which releases the TLS frame.
        let tls_allocation = if let Some(ref master_tls) = tls_master {
            let mut tls_alloc = memapi
                .allocate(
                    Location::Anywhere,
                    master_tls.layout(),
                    UserAccessible::Yes,
                    Guarded::No,
                )
                .ok_or(ExecveError::Enomem { stage: "tls" })?;

            let slice = tls_alloc.as_mut();
            slice.copy_from_slice(master_tls.as_ref());
            Some(tls_alloc)
        } else {
            None
        };

        // Stage 5: user stack. `ustack_allocation` is dropped on
        // the `?`-branch, which releases the stack frames.
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
            .ok_or(ExecveError::Enomem {
                stage: "user_stack",
            })?;

        let ustack_rsp = ustack_allocation.start() + ustack_allocation.len().into_u64();

        // Stage 6: commit. Move the new segment / TLS allocations
        // into the process's tracked state. After this point, the
        // local `exec_allocs` / `ro_allocs` / `wr_allocs` /
        // `tls_allocation` / `ustack_allocation` are owned by the
        // process and live for the lifetime of the new image.
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
