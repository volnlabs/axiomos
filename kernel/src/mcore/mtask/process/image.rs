#[cfg(target_arch = "aarch64")]
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};

use kernel_elfloader::{ElfFile, ElfLoader, LoadElfError};
use kernel_vfs::node::VfsNode;
use kernel_vfs::path::AbsolutePath;
use kernel_vfs::Stat;
use thiserror::Error;

use super::executable::{
    advance_executable_read_progress, allocate_executable_buffer, ExecutableFileError,
    ExecutableReadProgress, ExecutableReadProgressError,
};
use super::Process;
use crate::file::vfs;
use crate::mem::memapi::{Executable, LowerHalfAllocation, LowerHalfMemoryApi, Readonly, Writable};

/// Typed error returned by `Process::execve` and friends.
///
/// The previous `&'static str` return type was lossy: it collapsed
/// every allocation failure into a generic "Failed to allocate TLS" /
/// "Failed to allocate user stack" string, and propagated the
/// inner error from `ElfLoader::load` as a flat "Failed to load
/// ELF". For the audit-fault-injection work and the end-to-end
/// exec rollback coverage, the kernel needs to distinguish:
/// - `Parse`: the input bytes are not a structurally-valid ELF.
///   Propagated from `ElfFile::try_parse` via `ElfParseError`.
/// - `Load`: the ELF is structurally valid but the loader cannot
///   install its segments. Propagated from `ElfLoader::load` via
///   `LoadElfError` (which already has `AllocationFailed` and
///   other typed variants).
/// - `Enomem { stage }`: a frame or virtual-memory allocation
///   failed during the post-load stage (TLS copy, user stack,
///   or a wrapping LowerHalf allocation that the loader
///   delegates to the kernel's `LowerHalfMemoryApi`).
///
/// The `stage` field is `&'static str` rather than an enum so the
/// caller can add new failure points without breaking downstream
/// `match` exhaustiveness; the typed `Parse` and `Load` variants
/// cover the loader's own error surface.
#[derive(Debug, Error)]
pub(crate) enum ExecveError {
    /// The input bytes are not a structurally-valid ELF.
    #[error("execve: ELF parse error: {0}")]
    Parse(kernel_elfloader::ElfParseError),
    /// The ELF is structurally valid but the loader could not
    /// install its segments. `LoadElfError::AllocationFailed` is
    /// the audit-fault-injection-relevant variant; the other
    /// variants are structural (`UnsupportedFileType`,
    /// `WritableExecutableSegment`, etc.).
    #[error("execve: ELF load error: {0}")]
    Load(LoadElfError),
    /// A frame or virtual-memory allocation failed during the
    /// post-load stage. `stage` names the failing allocation
    /// (`"tls"`, `"user_stack"`, etc.) so an operator can
    /// distinguish them in a log.
    #[error("execve: out of memory during {stage}")]
    Enomem { stage: &'static str },
}

#[derive(Debug, Error)]
pub(crate) enum ExecutableReadError {
    #[error("executable buffer is shorter than its stat size")]
    BufferTooShort,
    #[error("failed to read executable: {0}")]
    Read(#[from] kernel_vfs::ReadError),
    #[error("invalid executable read progress: {0}")]
    Progress(#[from] ExecutableReadProgressError),
}

#[derive(Debug, Error)]
pub(crate) enum ExecPreflightError {
    #[error("failed to open executable: {0}")]
    Open(#[from] kernel_vfs::OpenError),
    #[error("failed to stat executable: {0}")]
    Stat(#[from] kernel_vfs::StatError),
    #[error("invalid executable buffer: {0}")]
    File(#[from] ExecutableFileError),
    #[error("failed to read executable: {0}")]
    Read(#[from] ExecutableReadError),
    #[error("invalid ELF file: {0}")]
    Parse(#[from] kernel_elfloader::ElfParseError),
}

pub(super) enum TrampolineLoadError {
    Parse(kernel_elfloader::ElfParseError),
    Load(LoadElfError),
}

impl Display for TrampolineLoadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "ELF parse error: {err}"),
            Self::Load(err) => write!(f, "ELF load error: {err}"),
        }
    }
}

pub(super) struct ElfSegments {
    pub(super) executable: Vec<LowerHalfAllocation<Executable>>,
    pub(super) readonly: Vec<LowerHalfAllocation<Readonly>>,
    pub(super) writable: Vec<LowerHalfAllocation<Writable>>,
}

pub(crate) struct ExecImage {
    pub entry_point: usize,
    pub stack_pointer: usize,
    pub tls: Option<LowerHalfAllocation<Writable>>,
    pub user_stack: LowerHalfAllocation<Writable>,
}

impl ElfSegments {
    pub(super) fn new() -> Self {
        Self {
            executable: Vec::new(),
            readonly: Vec::new(),
            writable: Vec::new(),
        }
    }

    pub(super) fn clear(&mut self) {
        self.executable.clear();
        self.readonly.clear();
        self.writable.clear();
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub(super) fn with_process_address_space_active<T, F>(process: &Arc<Process>, f: F) -> T
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

pub(super) fn read_executable_file_into(
    node: &VfsNode,
    buf: &mut [u8],
    expected_size: usize,
    log_label: &str,
) -> Result<(), ExecutableReadError> {
    if buf.len() < expected_size {
        return Err(ExecutableReadError::BufferTooShort);
    }

    let mut offset = 0;
    while offset < expected_size {
        log::info!(
            "{}: executable read request offset={} remaining={}",
            log_label,
            offset,
            expected_size - offset
        );
        let read = node.read(&mut buf[offset..expected_size], offset)?;
        log::info!(
            "{}: executable read returned offset={} read={}",
            log_label,
            offset,
            read
        );

        match advance_executable_read_progress(offset, read, expected_size)? {
            ExecutableReadProgress::Continue(next_offset) => offset = next_offset,
            ExecutableReadProgress::Complete => break,
        }
    }

    Ok(())
}

pub(super) fn trampoline_load_elf<'a>(
    bytes: &'a [u8],
    memapi: LowerHalfMemoryApi,
) -> Result<(usize, kernel_elfloader::ElfImageParts<LowerHalfMemoryApi>), TrampolineLoadError> {
    let elf_file = ElfFile::try_parse(bytes).map_err(TrampolineLoadError::Parse)?;
    let code_ptr = elf_file.entry();
    let elf_image = ElfLoader::new(memapi)
        .load(elf_file)
        .map_err(TrampolineLoadError::Load)?;
    Ok((code_ptr, elf_image.into_inner()))
}

impl Process {
    pub(crate) fn prepare_execve(
        &self,
        path: &AbsolutePath,
    ) -> Result<Vec<u8>, ExecPreflightError> {
        let node = vfs().write().open(path)?;
        let mut stat = Stat::default();
        node.stat(&mut stat)?;

        let mut file_content = allocate_executable_buffer(stat.size)?;
        read_executable_file_into(&node, &mut file_content, stat.size, "execve")?;
        ElfFile::try_parse(&file_content).map_err(|e| {
            log::error!("execve preflight: ELF parse error: {e}");
            e
        })?;
        Ok(file_content)
    }
}
