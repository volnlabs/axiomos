use kernel_abi::ProtFlags;
use kernel_syscall::access::{
    AllocationStrategy, CreateMappingError, Location, Mapping, MemoryAccess,
};
use kernel_syscall::UserspacePtr;
use kernel_virtual_memory::Segment;

use crate::arch::types::{PageSize, PageTableFlags, PhysFrameRangeInclusive, Size4KiB, VirtAddr};
use crate::mcore::mtask::process::mem::{MappedMemoryRegion, MemoryRegion};
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
        // For now, we only support eager allocation
        assert!(
            matches!(allocation_strategy, AllocationStrategy::Eager),
            "only eager allocation is supported"
        );

        let page_aligned_size = size.next_multiple_of(Size4KiB::SIZE as usize);
        let page_count = page_aligned_size / Size4KiB::SIZE as usize;

        let segment = if let Location::Fixed(addr) = location {
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

        let mut page_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if protection.contains(ProtFlags::WRITE) {
            page_flags.insert(PageTableFlags::WRITABLE);
        }
        if !protection.contains(ProtFlags::EXEC) {
            page_flags.insert(PageTableFlags::NO_EXECUTE);
        }

        self.process
            .with_address_space(|as_| {
                as_.map_range_owned::<Size4KiB>(&*segment, frames.into_iter(), page_flags)
            })
            .map_err(|_| CreateMappingError::OutOfMemory)?;

        Ok(KernelMapping {
            addr: segment.start,
            size,
            segment,
            physical_frames: frames,
        })
    }
}

pub struct KernelMapping {
    addr: VirtAddr,
    size: usize,
    segment: OwnedSegment<'static>,
    physical_frames: PhysFrameRangeInclusive<Size4KiB>,
}

impl KernelMapping {
    /// Convert this mapping into a MemoryRegion handle that can be tracked by the process.
    pub fn into_region_handle(self) -> KernelMemoryRegionHandle {
        let addr = self
            .addr
            .as_ptr::<u8>()
            .try_into()
            .expect("kernel mapping should be located in user space");
        let size = self.size;

        let inner = MemoryRegion::Mapped(MappedMemoryRegion::new(
            self.segment,
            self.size,
            self.physical_frames,
        ));

        KernelMemoryRegionHandle { addr, size, inner }
    }
}

impl Mapping for KernelMapping {
    fn addr(&self) -> UserspacePtr<u8> {
        self.addr
            .as_ptr::<u8>()
            .try_into()
            .expect("kernel mapping should be located in user space")
    }

    fn size(&self) -> usize {
        self.size
    }
}
