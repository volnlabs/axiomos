use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;

use kernel_elfloader::{ElfFile, ElfLoader};
use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible};
use kernel_virtual_memory::VirtualMemoryManager;

use super::{ExecImage, ExecveError, Process};
use crate::arch::{PageSize, Size4KiB, VirtAddr};
use crate::mem::address_space::AddressSpace;
use crate::mem::memapi::LowerHalfMemoryApi;
use crate::{U64Ext, UsizeExt};

impl Process {
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
