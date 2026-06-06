use alloc::vec::Vec;
use core::slice;

use kernel_vfs::node::VfsNode;
use spin::mutex::Mutex;

use crate::arch::{PhysFrame, PhysFrameRange as PhysFrameRangeInclusive, VirtAddr};
use crate::mem::phys::PhysicalMemory;
use crate::mem::virt::OwnedSegment;
use crate::UsizeExt;

pub struct MemoryRegions {
    regions: Mutex<Vec<MemoryRegion>>,
}

impl Default for MemoryRegions {
    fn default() -> Self {
        Self::new()
    }
}

use alloc::sync::Arc;

use crate::arch::types::PageTableFlags;
#[cfg(target_arch = "aarch64")]
use crate::arch::types::Size4KiB;
use crate::mcore::mtask::process::Process;
use crate::mem::virt::VirtualMemoryAllocator;

impl MemoryRegions {
    pub fn new() -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
        }
    }

    pub fn clone_to_process(&self, new_process: &Arc<Process>) -> Result<Self, &'static str> {
        let mut new_regions = Vec::new();
        let guard = self.regions.lock();

        for region in guard.iter() {
            new_regions.push(region.clone_to_process(new_process)?);
        }

        Ok(Self {
            regions: Mutex::new(new_regions),
        })
    }

    pub fn add_region(&self, region: MemoryRegion) {
        self.regions.lock().push(region);
    }

    pub fn remove_region_at_address(&self, addr: VirtAddr) -> bool {
        let mut regions = self.regions.lock();
        if let Some(index) = regions.iter().position(|r| r.addr() == addr) {
            regions.remove(index);
            true
        } else {
            false
        }
    }

    pub fn with_memory_region_for_address<F, R>(&self, addr: VirtAddr, f: F) -> Option<R>
    where
        F: FnOnce(&MemoryRegion) -> R,
    {
        self.regions
            .lock()
            .iter()
            .find(|r| r.addr() <= addr && r.addr() + r.size().into_u64() > addr)
            .map(f)
    }

    pub fn is_memory_region_at_address(&self, addr: VirtAddr) -> bool {
        self.regions
            .lock()
            .iter()
            .any(|r| r.addr() <= addr && r.addr() + r.size().into_u64() > addr)
    }

    pub fn replace_from(&self, other: MemoryRegions) {
        let mut guard = self.regions.lock();
        let mut other_guard = other.regions.lock();
        // Since other is typically a newly created local variable (from clone_to_process),
        // we can take its contents.
        // But Mutex doesn't allow moving out easily if we only have &self.
        // However, `other` in `fork` is `cloned_regions`, which we own.
        // But `replace_from` takes `other: MemoryRegions` (owned).
        // But `regions` is private in `MemoryRegions`.
        // We can just swap vectors if we want.
        core::mem::swap(&mut *guard, &mut *other_guard);
    }

    pub fn clear(&self) {
        self.regions.lock().clear();
    }
}

#[derive(Debug)]
pub enum MemoryRegion {
    /// A memory region that will have its memory mapped in lazily
    /// by the page fault handler upon access to a page.
    ///
    /// - [`LazyMemoryRegion`]
    Lazy(LazyMemoryRegion),
    /// A memory region whose entire memory is already mapped.
    /// One could call it a "normal piece of memory".
    ///
    /// - [`MappedMemoryRegion`]
    Mapped(MappedMemoryRegion),
    /// A memory region that is lazy, but is additionally backed by
    /// a file. The page handler will map the pages lazily upon access,
    /// and read the bytes from the respective location from the backing
    /// file.
    ///
    /// - [`FileBackedMemoryRegion`]
    FileBacked(FileBackedMemoryRegion),
}

impl MemoryRegion {
    pub fn addr(&self) -> VirtAddr {
        match self {
            MemoryRegion::Lazy(lazy_memory_region) => lazy_memory_region.segment.start,
            MemoryRegion::Mapped(mapped_memory_region) => mapped_memory_region.segment.start,
            MemoryRegion::FileBacked(file_backed_memory_region) => {
                file_backed_memory_region.region.segment.start
            }
        }
    }

    pub fn clone_to_process(&self, new_process: &Arc<Process>) -> Result<Self, &'static str> {
        match self {
            MemoryRegion::Mapped(r) => Ok(MemoryRegion::Mapped(r.clone_to_process(new_process)?)),
            MemoryRegion::Lazy(r) => Ok(MemoryRegion::Lazy(r.clone_to_process(new_process)?)),
            MemoryRegion::FileBacked(r) => {
                Ok(MemoryRegion::FileBacked(r.clone_to_process(new_process)?))
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            MemoryRegion::Lazy(lazy_memory_region) => lazy_memory_region.size,
            MemoryRegion::Mapped(mapped_memory_region) => mapped_memory_region.size,
            MemoryRegion::FileBacked(file_backed_memory_region) => {
                file_backed_memory_region.region.size
            }
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: The memory region represents valid memory with the tracked size.
        // We assume the caller ensures the memory is accessible.
        unsafe { slice::from_raw_parts(self.addr().as_ptr(), self.size()) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: The memory region represents valid memory with the tracked size.
        // We assume the caller ensures the memory is accessible and we have exclusive access.
        unsafe { slice::from_raw_parts_mut(self.addr().as_mut_ptr(), self.size()) }
    }
}

impl MappedMemoryRegion {
    pub fn clone_to_process(&self, new_process: &Arc<Process>) -> Result<Self, &'static str> {
        let new_segment_inner =
            kernel_virtual_memory::Segment::new(self.segment.start, self.segment.len);

        let new_segment = new_process
            .vmm()
            .mark_as_reserved(new_segment_inner)
            .map_err(|_| "Failed to reserve segment in new process")?;

        PhysicalMemory::retain_frames(self.physical_frames);

        #[cfg(target_arch = "aarch64")]
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::COPY_ON_WRITE;

        #[cfg(not(target_arch = "aarch64"))]
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;

        new_process
            .with_address_space(|as_| {
                as_.map_range(*new_segment, self.physical_frames.into_iter(), flags)
            })
            .map_err(|_| "Failed to map memory in new process")?;

        #[cfg(target_arch = "aarch64")]
        {
            // Writable mapped regions become shared read-only pages in both parent and child.
            let current = crate::mcore::context::ExecutionContext::load().current_process();
            current
                .with_address_space(|as_| as_.remap_range::<Size4KiB, _>(*self.segment, |_| flags))
                .map_err(|_| "Failed to remap parent memory as copy-on-write")?;
        }

        Ok(MappedMemoryRegion {
            segment: new_segment,
            size: self.size,
            physical_frames: self.physical_frames,
        })
    }
}

impl LazyMemoryRegion {
    pub fn clone_to_process(&self, _new_process: &Arc<Process>) -> Result<Self, &'static str> {
        // TODO: Implement proper deep copy for Lazy regions.
        // For now, since we only use Eager allocation (Mapped), this is less critical.
        // But if we encounter one, we shouldn't fail silently or panic?
        // Let's return error for now as it's not supported.
        Err("Forking LazyMemoryRegion not implemented")
    }
}

impl FileBackedMemoryRegion {
    pub fn clone_to_process(&self, _new_process: &Arc<Process>) -> Result<Self, &'static str> {
        Err("Forking FileBackedMemoryRegion not implemented")
    }
}

#[derive(Debug)]
pub struct LazyMemoryRegion {
    segment: OwnedSegment<'static>,
    /// The size of the region. This may differ from the
    /// size of the segment in that the size of the segment
    /// is page-aligned, while this may not be.
    ///
    /// For example, the segment of a memory region whose
    /// size is 5 bytes is actually 4096 bytes.
    size: usize,
    /// The physical frames that were mapped for this lazy
    /// memory region.
    #[allow(dead_code)]
    physical_frames: Mutex<Vec<PhysFrame>>,
}

impl Drop for LazyMemoryRegion {
    fn drop(&mut self) {
        for frame in self.physical_frames.lock().iter() {
            PhysicalMemory::deallocate_frame(*frame);
        }
    }
}

#[derive(Debug)]
pub struct MappedMemoryRegion {
    segment: OwnedSegment<'static>,
    size: usize,
    #[allow(dead_code)]
    physical_frames: PhysFrameRangeInclusive,
}

impl MappedMemoryRegion {
    pub fn new(
        segment: OwnedSegment<'static>,
        size: usize,
        physical_frames: PhysFrameRangeInclusive,
    ) -> Self {
        Self {
            segment,
            size,
            physical_frames,
        }
    }
}

impl Drop for MappedMemoryRegion {
    fn drop(&mut self) {
        PhysicalMemory::deallocate_frames(self.physical_frames);
    }
}

#[derive(Debug)]
pub struct FileBackedMemoryRegion {
    region: LazyMemoryRegion,
    #[allow(dead_code)]
    node: VfsNode,
}

impl Drop for FileBackedMemoryRegion {
    fn drop(&mut self) {
        // region dropped automatically
    }
}
