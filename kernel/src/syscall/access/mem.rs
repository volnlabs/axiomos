use alloc::sync::Arc;

use kernel_abi::ProtFlags;
use kernel_syscall::access::{
    AllocationStrategy, CreateMappingError, Location, Mapping, MemoryAccess,
};
use kernel_syscall::UserspacePtr;
use kernel_virtual_memory::Segment;

use crate::arch::types::{PageSize, PhysFrameRangeInclusive, Size4KiB, VirtAddr};
use crate::mcore::mtask::process::mem::{user_page_flags, MappedMemoryRegion, MemoryRegion};
use crate::mcore::mtask::process::Process;
use crate::mem::phys::PhysicalMemory;
use crate::mem::phys_to_virt;
use crate::mem::virt::{OwnedSegment, VirtualMemoryAllocator};
use crate::syscall::access::{KernelAccess, KernelMemoryRegionHandle};
use crate::UsizeExt;

impl MemoryAccess for KernelAccess {
    type Mapping = KernelMapping;

    fn create_mapping(
        &self,
        location: Location,
        size: usize,
        allocation_strategy: AllocationStrategy,
        protection: ProtFlags,
    ) -> Result<Self::Mapping, CreateMappingError> {
        if size == 0 {
            return Err(CreateMappingError::InvalidRequest);
        }
        if allocation_strategy != AllocationStrategy::Eager {
            return Err(CreateMappingError::Unsupported);
        }

        let page_size = Size4KiB::SIZE as usize;
        let page_aligned_size = size
            .checked_add(page_size - 1)
            .map(|value| value / page_size * page_size)
            .ok_or(CreateMappingError::OutOfMemory)?;
        let page_count = page_aligned_size / Size4KiB::SIZE as usize;

        let segment = if let Location::Fixed(addr) = location {
            if (addr.as_ptr() as usize) % page_size != 0 {
                return Err(CreateMappingError::InvalidRequest);
            }
            self.process
                .vmm()
                .mark_as_reserved(Segment::new(
                    VirtAddr::new(addr.as_ptr() as u64),
                    page_aligned_size.into_u64(),
                ))
                .map_err(|_| CreateMappingError::LocationAlreadyMapped)?
        } else {
            self.process
                .vmm()
                .reserve(page_count)
                .ok_or(CreateMappingError::OutOfMemory)?
        };

        // Allocate physical frames and map them
        // TODO: Optimize by using 2MiB and 1GiB frames when possible instead of only 4KiB frames
        let frames = PhysicalMemory::allocate_frames::<Size4KiB>(page_count)
            .ok_or(CreateMappingError::OutOfMemory)?;

        // Zero the allocated frames for security
        // We use the direct map (phys_to_virt) to access the physical memory.
        for frame in frames {
            let paddr = frame.start_address().as_u64();
            let vaddr = phys_to_virt(paddr as usize);
            // SAFETY: We just allocated this frame, so we have exclusive access to it.
            // The direct map is always valid for physical memory.
            unsafe {
                core::ptr::write_bytes(vaddr as *mut u8, 0, Size4KiB::SIZE as usize);
            }
        }

        self.process
            .with_address_space(|as_| {
                as_.map_range_owned::<Size4KiB>(
                    &*segment,
                    frames.into_iter(),
                    user_page_flags(protection),
                )
            })
            .map_err(|_| CreateMappingError::OutOfMemory)?;

        Ok(KernelMapping {
            process: self.process.clone(),
            addr: segment.start,
            size,
            protection,
            segment: Some(segment),
            physical_frames: Some(frames),
        })
    }
}

#[must_use = "an uncommitted kernel mapping rolls back when dropped"]
pub struct KernelMapping {
    process: Arc<Process>,
    addr: VirtAddr,
    size: usize,
    protection: ProtFlags,
    segment: Option<OwnedSegment<'static>>,
    physical_frames: Option<PhysFrameRangeInclusive<Size4KiB>>,
}

impl Drop for KernelMapping {
    fn drop(&mut self) {
        if let Some(segment) = self.segment.take() {
            self.process.with_address_space(|address_space| {
                address_space.unmap_range::<Size4KiB>(&*segment, |_| {});
            });
        }
        if let Some(frames) = self.physical_frames.take() {
            PhysicalMemory::deallocate_frames(frames);
        }
    }
}

impl Mapping for KernelMapping {
    type Region = KernelMemoryRegionHandle;

    fn addr(&self) -> UserspacePtr<u8> {
        self.addr
            .as_ptr::<u8>()
            .try_into()
            .expect("kernel mapping should be located in user space")
    }

    fn size(&self) -> usize {
        self.size
    }

    fn protection(&self) -> ProtFlags {
        self.protection
    }

    fn commit(mut self) -> Self::Region {
        let addr = self.addr();
        let segment = self
            .segment
            .take()
            .expect("uncommitted mapping owns its virtual reservation");
        let _physical_frames = self
            .physical_frames
            .take()
            .expect("uncommitted mapping owns its physical frames");
        let inner = MemoryRegion::Mapped(MappedMemoryRegion::new(
            &self.process,
            segment,
            self.size,
            self.protection,
        ));

        KernelMemoryRegionHandle {
            addr,
            size: self.size,
            inner,
        }
    }
}
