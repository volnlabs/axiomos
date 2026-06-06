#[cfg(target_arch = "x86_64")]
use alloc::boxed::Box;
use core::ptr::NonNull;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_arch = "x86_64")]
use kernel_pci::config::ConfigurationAccess;
#[cfg(target_arch = "x86_64")]
use kernel_pci::PciAddress;
#[cfg(target_arch = "x86_64")]
use kernel_virtual_memory::Segment;
#[cfg(target_arch = "x86_64")]
use virtio_drivers::transport::pci::bus::{DeviceFunction, PciRoot};
#[cfg(target_arch = "x86_64")]
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::{BufferDirection, Hal};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::{
    mem::{self, pte_flags, PAGE_SIZE},
    mm,
    paging::{self, PageTableWalker},
    phys,
};
#[cfg(target_arch = "x86_64")]
use crate::arch::types::{PageSize, PageTableFlags, VirtAddr};
use crate::arch::types::{PhysAddr, PhysFrame, PhysFrameRangeInclusive, Size4KiB};
#[cfg(target_arch = "x86_64")]
use crate::driver::pci::VirtIoCam;
#[cfg(target_arch = "x86_64")]
use crate::mem::address_space::AddressSpace;
#[cfg(target_arch = "x86_64")]
use crate::mem::phys::PhysicalMemory;
#[cfg(target_arch = "x86_64")]
use crate::mem::virt::{VirtualMemoryAllocator, VirtualMemoryHigherHalf};
#[cfg(target_arch = "x86_64")]
use crate::{U64Ext, UsizeExt};

#[cfg(target_arch = "x86_64")]
pub fn transport(addr: PciAddress, cam: Box<dyn ConfigurationAccess>) -> PciTransport {
    let mut root = PciRoot::new(VirtIoCam::new(cam));
    PciTransport::new::<HalImpl, _>(
        &mut root,
        DeviceFunction {
            bus: addr.bus,
            device: addr.device,
            function: addr.function,
        },
    )
    .unwrap()
}

#[allow(dead_code)]
pub struct HalImpl;

// Offset for allocating MMIO virtual addresses on AArch64
#[cfg(target_arch = "aarch64")]
#[allow(unused)]
static MMIO_ALLOC_OFFSET: AtomicUsize = AtomicUsize::new(0);

// SAFETY: HalImpl implements the VirtIO HAL trait using the kernel's memory management
// subsystems (PhysicalMemory and AddressSpace). It guarantees correct DMA allocation
// and address translation for VirtIO drivers.
unsafe impl Hal for HalImpl {
    fn dma_alloc(pages: usize, _: BufferDirection) -> (u64, NonNull<u8>) {
        #[cfg(target_arch = "x86_64")]
        {
            let frames = PhysicalMemory::allocate_frames(pages).unwrap();
            let segment = VirtualMemoryHigherHalf.reserve(pages).unwrap();
            AddressSpace::kernel()
                .map_range::<Size4KiB>(
                    &*segment,
                    frames,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                )
                .unwrap();
            let segment = segment.leak();
            let addr = NonNull::new(segment.start.as_mut_ptr::<u8>()).unwrap();
            (frames.start.start_address().as_u64(), addr)
        }
        #[cfg(target_arch = "aarch64")]
        {
            // 1. Allocate contiguous physical frames
            let range = phys::allocate_frames::<Size4KiB>(pages).expect("dma_alloc: out of memory");
            let phys_addr = range.start.addr();

            // 2. Use direct map for virtual address
            // The kernel maintains a direct mapping of all physical memory at PHYS_MAP_BASE
            let virt_addr = mem::phys_to_virt(phys_addr as usize);

            // 3. Zero the memory
            // SAFETY: virt_addr is valid and backed by the allocated frames.
            unsafe {
                core::ptr::write_bytes(virt_addr as *mut u8, 0, pages * PAGE_SIZE);
            }

            (
                phys_addr as u64,
                NonNull::new(virt_addr as *mut u8).unwrap(),
            )
        }
    }

    // SAFETY: We are deallocating memory previously allocated by dma_alloc.
    // The caller guarantees that paddr, vaddr, and pages match the allocation.
    // The Hal trait contract requires the caller to be correct.
    unsafe fn dma_dealloc(paddr: u64, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        #[cfg(target_arch = "x86_64")]
        {
            let frames = PhysFrameRangeInclusive::<Size4KiB> {
                start: PhysFrame::containing_address(PhysAddr::new(paddr)),
                end: PhysFrame::containing_address(PhysAddr::new(
                    paddr + (pages * Size4KiB::SIZE.into_usize()).into_u64() - 1,
                )),
            };
            let segment = Segment::new(
                VirtAddr::from_ptr(_vaddr.as_ptr()),
                pages.into_u64() * Size4KiB::SIZE,
            );
            // SAFETY: We are unmapping and deallocating memory previously allocated by dma_alloc.
            // The caller guarantees that paddr, vaddr, and pages match the allocation.
            unsafe {
                AddressSpace::kernel().unmap_range::<Size4KiB>(&segment, |_| {});
                assert!(VirtualMemoryHigherHalf.release(segment));
                PhysicalMemory::deallocate_frames(frames);
            }

            0
        }
        #[cfg(target_arch = "aarch64")]
        {
            let start_frame: PhysFrame<Size4KiB> =
                PhysFrame::containing_address(PhysAddr::new(paddr));
            let end_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(PhysAddr::new(
                paddr + (pages as u64 - 1) * PAGE_SIZE as u64,
            ));
            let range = PhysFrameRangeInclusive {
                start: start_frame,
                end: end_frame,
            };

            phys::deallocate_frames::<Size4KiB>(range);
            0
        }
    }

    // SAFETY: We map the physical address to a virtual address. The caller guarantees
    // the physical address is valid for MMIO.
    unsafe fn mmio_phys_to_virt(paddr: u64, size: usize) -> NonNull<u8> {
        #[cfg(target_arch = "x86_64")]
        {
            let frames = PhysFrameRangeInclusive::<Size4KiB> {
                start: PhysFrame::containing_address(PhysAddr::new(paddr)),
                end: PhysFrame::containing_address(PhysAddr::new(paddr + size.into_u64() - 1)),
            };

            let segment = VirtualMemoryHigherHalf
                .reserve(size.div_ceil(Size4KiB::SIZE.into_usize()))
                .unwrap();
            AddressSpace::kernel()
                .map_range::<Size4KiB>(
                    &*segment,
                    frames,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                )
                .unwrap();
            let segment = segment.leak();
            NonNull::new(segment.start.as_mut_ptr::<u8>()).unwrap()
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Align physical address and size to page boundaries
            let paddr_page = (paddr as usize) & !(PAGE_SIZE - 1);
            let paddr_offset = (paddr as usize) & (PAGE_SIZE - 1);
            let size_aligned = (size + paddr_offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

            // Allocate virtual address space from MMIO region
            let offset = MMIO_ALLOC_OFFSET.fetch_add(size_aligned, Ordering::SeqCst);
            let vaddr_page = mem::kernel::MMIO_BASE + offset;

            // Map the range
            // SAFETY: kernel_page_table_phys returns the valid L0 table address.
            let pt_phys = mm::kernel_page_table_phys();
            let mut walker = unsafe { PageTableWalker::new(pt_phys as *mut _) };

            let flags = pte_flags::DEVICE;

            walker
                .map_range(vaddr_page, paddr_page, size_aligned, flags)
                .expect("Failed to map MMIO");

            // Flush TLB to ensure new mappings are visible
            paging::flush_tlb();

            NonNull::new((vaddr_page + paddr_offset) as *mut u8).unwrap()
        }
    }

    // SAFETY: We translate a virtual address to physical for DMA sharing.
    // The buffer is valid as ensured by the caller/Rust typing.
    unsafe fn share(buffer: NonNull<[u8]>, _: BufferDirection) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            AddressSpace::kernel()
                .translate(VirtAddr::from_ptr(buffer.as_ptr()))
                .unwrap()
                .as_u64()
        }
        #[cfg(target_arch = "aarch64")]
        {
            let vaddr = buffer.as_ptr() as *mut u8 as usize;

            // Try translating using page table walker
            let pt_phys = mm::kernel_page_table_phys();
            let walker = unsafe { PageTableWalker::new(pt_phys as *mut _) };

            if let Some(paddr) = walker.translate(vaddr) {
                paddr as u64
            } else {
                panic!("Hal::share: virtual address {:#x} not mapped", vaddr);
            }
        }
    }

    // SAFETY: No-op for this implementation.
    unsafe fn unshare(_: u64, _: NonNull<[u8]>, _: BufferDirection) {}
}
