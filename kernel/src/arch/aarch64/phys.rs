//! ARM64 Physical Memory Allocator
//!
//! Re-exports the common physical memory allocator with ARM64-specific initialization.

use kernel_physical_memory::{PhysicalFrameAllocator, PhysicalMemoryManager};

use crate::arch::aarch64::dtb;
pub use crate::arch::types::{PageSize, PhysFrame, PhysFrameRange, PhysFrameRangeInclusive};
pub use crate::mem::phys::*;

/// Static storage for memory regions to avoid allocation during early boot.
static mut BOOT_REGIONS: [crate::mem::phys::MemoryRegion; 8] =
    [crate::mem::phys::MemoryRegion { base: 0, length: 0 }; 8];

#[inline(always)]
fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

/// Initialize stage 1 (bump allocator)
pub fn init_stage1() {
    dbg_mark(0x4b); // 'K'
    let info = dtb::info();
    dbg_mark(0x4c); // 'L'

    // Register reserved regions BEFORE starting any allocations
    // Register DTB as reserved
    dbg_mark(0x54); // 'T'
    crate::mem::phys::register_reserved_region(info.dtb_start as u64, info.dtb_size as u64);
    dbg_mark(0x55); // 'U'
    dbg_mark(0x4d); // 'M'

    // Register kernel image as reserved
    extern "C" {
        static __text_start: u8;
        static __bss_end: u8;
    }

    let kernel_start = &raw const __text_start as u64;
    let kernel_end = &raw const __bss_end as u64;
    crate::mem::phys::register_reserved_region(kernel_start, kernel_end - kernel_start);
    dbg_mark(0x4e); // 'N'

    // Convert DTB regions to the generic MemoryRegion type without using Vec
    let mut count = 0;
    for region in info.memory_regions() {
        if count < 8 {
            // SAFETY: We are in early boot, single-threaded.
            unsafe {
                BOOT_REGIONS[count] = crate::mem::phys::MemoryRegion {
                    base: region.base as u64,
                    length: region.size as u64,
                };
            }
            count += 1;
        }
    }
    dbg_mark(0x4f); // 'O'

    // SAFETY: We only take the slice of initialized regions.
    let regions_static = unsafe { &BOOT_REGIONS[..count] };

    crate::mem::phys::init_stage1_aarch64(regions_static);
    dbg_mark(0x50); // 'P'

    log::info!(
        "Physical memory stage 1 initialized: {} MB available",
        info.total_memory / (1024 * 1024)
    );
    log::info!(
        "Reserved DTB region: {:#x} - {:#x}",
        info.dtb_start,
        info.dtb_start + info.dtb_size
    );
    log::info!(
        "Reserved kernel region: {:#x} - {:#x}",
        kernel_start,
        kernel_end
    );
}

/// Initialize stage 2 (bitmap allocator)
pub fn init_stage2() {
    crate::mem::phys::init_stage2();
}

/// Get total usable physical memory in bytes
pub fn total_memory() -> usize {
    dtb::info().total_memory
}

/// Checks whether the physical memory allocator has been initialized.
pub fn is_initialized() -> bool {
    PhysicalMemory::is_initialized()
}

/// Allocate a single physical frame
pub fn allocate_frame<S: PageSize>() -> Option<PhysFrame<S>>
where
    PhysicalMemoryManager: PhysicalFrameAllocator<S>,
{
    PhysicalMemory::allocate_frame::<S>()
}

/// Allocate contiguous physical frames
pub fn allocate_frames<S: PageSize>(n: usize) -> Option<PhysFrameRange<S>>
where
    PhysicalMemoryManager: PhysicalFrameAllocator<S>,
{
    PhysicalMemory::allocate_frames::<S>(n)
}

/// Deallocate a physical frame
pub fn deallocate_frame<S: PageSize>(frame: PhysFrame<S>)
where
    PhysicalMemoryManager: PhysicalFrameAllocator<S>,
{
    PhysicalMemory::deallocate_frame::<S>(frame);
}

/// Deallocate contiguous physical frames
pub fn deallocate_frames<S: PageSize>(range: PhysFrameRange<S>)
where
    PhysicalMemoryManager: PhysicalFrameAllocator<S>,
{
    PhysicalMemory::deallocate_frames::<S>(range);
}
