#![no_std]
extern crate alloc;

mod file;

use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::fmt::Debug;

pub use file::*;
use itertools::Itertools;
use kernel_memapi::{Guarded, Location, MemoryApi, UserAccessible};
use log::trace;
use thiserror::Error;

pub struct ElfLoader<M>
where
    M: MemoryApi,
{
    memory_api: M,
}

#[derive(Debug, Eq, PartialEq, Error)]
pub enum LoadElfError {
    #[error("could not allocate memory")]
    AllocationFailed,
    #[error("unsupported file type")]
    UnsupportedFileType(ElfType),
    #[error("size or alignment requirement is invalid")]
    InvalidSizeOrAlign,
    #[error("invalid virtual address 0x{0:016x}")]
    InvalidVirtualAddress(usize),
    #[error("more than one TLS header found")]
    TooManyTlsHeaders,
    /// The input ELF was structurally malformed in a way the loader relies on
    /// (e.g. a LOAD or TLS program's `phoff`/`phnum` claimed bytes past the
    /// end of the input). Propagates the parser's typed [`ElfParseError`]
    /// instead of panicking (audit H-05).
    #[error("ELF parse error: {0}")]
    Parse(ElfParseError),
}

impl<M> ElfLoader<M>
where
    M: MemoryApi,
{
    pub fn new(memory_api: M) -> Self {
        Self { memory_api }
    }

    /// # Errors
    /// Returns an error if the ELF file is not supported or if a required memory allocation fails.
    ///
    /// # Panics
    /// Panics if the ELF file is not of type `ET_EXEC`.
    pub fn load<'a>(&mut self, elf_file: ElfFile<'a>) -> Result<ElfImage<'a, M>, LoadElfError>
    where
        <M as MemoryApi>::WritableAllocation: Debug,
    {
        assert_eq!(
            ElfType::Exec,
            elf_file.header.typ,
            "only ET_EXEC supported for now"
        );

        let mut image = ElfImage {
            elf_file,
            executable_allocations: vec![],
            readonly_allocations: vec![],
            writable_allocations: vec![],
            tls_allocation: None,
        };

        self.load_loadable_headers(&mut image)?;
        self.load_tls(&mut image)?;

        Ok(image)
    }

    fn load_loadable_headers(&mut self, image: &mut ElfImage<'_, M>) -> Result<(), LoadElfError> {
        for hdr in image
            .elf_file
            .program_headers_by_type(ProgramHeaderType::LOAD)
        {
            let hdr = hdr.map_err(LoadElfError::Parse)?;
            trace!("load header {hdr:x?}");
            let pdata = image.elf_file.program_data(hdr).ok_or(LoadElfError::Parse(
                ElfParseError::SectionDataOutOfBounds {
                    offset: hdr.offset,
                    size: hdr.filesz,
                    source_len: image.elf_file.source.len(),
                },
            ))?;

            let location = Location::Fixed(hdr.vaddr as u64);

            // We deliberately ignore hdr.align here because:
            // 1. The memory API only supports 4KB alignment (and panics if > 4KB)
            // 2. We are using Location::Fixed, so we are not asking the allocator to find an aligned address for us.
            //    We are telling it exactly where to put it. The ELF spec guarantees that vaddr % align == offset % align,
            //    but not necessarily that vaddr is aligned to align.
            let layout = Layout::from_size_align(hdr.memsz, 4096)
                .map_err(|_| LoadElfError::InvalidSizeOrAlign)?;

            let mut alloc = self
                .memory_api
                .allocate(location, layout, UserAccessible::Yes, Guarded::No) // TODO: make user accessibility configurable
                .ok_or(LoadElfError::AllocationFailed)?;

            let slice = alloc.as_mut();
            slice[..hdr.filesz].copy_from_slice(pdata);
            slice[hdr.filesz..].fill(0);

            assert!(
                !(hdr.flags.contains(&ProgramHeaderFlags::EXECUTABLE)
                    && hdr.flags.contains(&ProgramHeaderFlags::WRITABLE)),
                "segments that are executable and writable are not supported"
            );

            if hdr.flags.contains(&ProgramHeaderFlags::EXECUTABLE) {
                let alloc = self
                    .memory_api
                    .make_executable(alloc)
                    .map_err(|_| LoadElfError::AllocationFailed)?;
                image.executable_allocations.push(alloc);
            } else if hdr.flags.contains(&ProgramHeaderFlags::WRITABLE) {
                image.writable_allocations.push(alloc);
            } else {
                let alloc = self
                    .memory_api
                    .make_readonly(alloc)
                    .map_err(|_| LoadElfError::AllocationFailed)?;
                image.readonly_allocations.push(alloc);
            }
        }
        Ok(())
    }

    fn load_tls(&mut self, image: &mut ElfImage<'_, M>) -> Result<(), LoadElfError> {
        let tls = image
            .elf_file
            .program_headers_by_type(ProgramHeaderType::TLS)
            .at_most_one()
            .map_err(|_| LoadElfError::TooManyTlsHeaders)?;
        let Some(tls) = tls else {
            return Ok(());
        };
        let tls = tls.map_err(LoadElfError::Parse)?;
        trace!("tls header {tls:x?}");

        let pdata = image.elf_file.program_data(tls).ok_or(LoadElfError::Parse(
            ElfParseError::SectionDataOutOfBounds {
                offset: tls.offset,
                size: tls.filesz,
                source_len: image.elf_file.source.len(),
            },
        ))?;

        let layout = Layout::from_size_align(tls.memsz, tls.align)
            .map_err(|_| LoadElfError::InvalidSizeOrAlign)?;

        let mut alloc = self
            .memory_api
            .allocate(Location::Anywhere, layout, UserAccessible::Yes, Guarded::No) // TODO: make user accessibility configurable
            .ok_or(LoadElfError::AllocationFailed)?;

        let slice = alloc.as_mut();
        slice[..tls.filesz].copy_from_slice(pdata);
        slice[tls.filesz..].fill(0);

        let alloc = self
            .memory_api
            .make_readonly(alloc)
            .map_err(|_| LoadElfError::AllocationFailed)?;

        image.tls_allocation = Some(alloc);

        Ok(())
    }
}

pub struct ElfImage<'a, M>
where
    M: MemoryApi,
{
    elf_file: ElfFile<'a>,
    executable_allocations: Vec<M::ExecutableAllocation>,
    readonly_allocations: Vec<M::ReadonlyAllocation>,
    writable_allocations: Vec<M::WritableAllocation>,
    tls_allocation: Option<M::ReadonlyAllocation>,
}

pub type ElfImageParts<M> = (
    Vec<<M as MemoryApi>::ExecutableAllocation>,
    Vec<<M as MemoryApi>::ReadonlyAllocation>,
    Vec<<M as MemoryApi>::WritableAllocation>,
    Option<<M as MemoryApi>::ReadonlyAllocation>,
);

impl<M> ElfImage<'_, M>
where
    M: MemoryApi,
{
    pub fn executable_allocations(&self) -> &[M::ExecutableAllocation] {
        &self.executable_allocations
    }

    pub fn readonly_allocations(&self) -> &[M::ReadonlyAllocation] {
        &self.readonly_allocations
    }

    pub fn writable_allocations(&self) -> &[M::WritableAllocation] {
        &self.writable_allocations
    }

    pub fn tls_allocation(&self) -> Option<&M::ReadonlyAllocation> {
        self.tls_allocation.as_ref()
    }

    pub fn entry_point(&self) -> usize {
        self.elf_file.entry()
    }

    pub fn into_inner(self) -> ElfImageParts<M> {
        (
            self.executable_allocations,
            self.readonly_allocations,
            self.writable_allocations,
            self.tls_allocation,
        )
    }
}
