use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::Relaxed;

use conquer_once::spin::OnceCell;
use log::info;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::phys;
#[cfg(target_arch = "x86_64")]
use crate::arch::types::Size2MiB;
use crate::arch::types::{Page, PageRangeInclusive, PageTableFlags, Size4KiB, VirtAddr};
#[cfg(target_arch = "x86_64")]
use crate::mem::address_space::virt_addr_from_page_table_indices;
use crate::mem::address_space::AddressSpace;
#[cfg(target_arch = "x86_64")]
use crate::mem::phys::PhysicalMemory;
#[cfg(target_arch = "aarch64")]
use crate::U64Ext;

static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
static HEAP_START: VirtAddr = virt_addr_from_page_table_indices([257, 0, 0, 0], 0);

#[cfg(target_arch = "aarch64")]
static HEAP_START: VirtAddr = VirtAddr::new(crate::arch::aarch64::mem::kernel::HEAP_BASE as u64);

/// Runtime-initialized heap sizes based on available physical memory.
static HEAP_SIZES: OnceCell<HeapSizes> = OnceCell::uninit();

struct HeapSizes {
    /// Initial heap size for stage1
    initial: usize,
    /// Total heap size after stage2
    total: usize,
}

impl HeapSizes {
    /// Calculate heap sizes based on available physical memory.
    ///
    /// We use a conservative multiplier to ensure we have enough heap for other data structures:
    /// - Initial heap: RAM / 1024 (minimum 2 MiB, maximum 128 MiB to keep stage1 fast)
    ///   Must be 2MiB-aligned (for stage2 to start at a 2MiB boundary)
    /// - Total heap: RAM / 256 (minimum initial + 2 MiB, maximum 512 MiB)
    ///   The extension (total - initial) must also be 2MiB-aligned
    fn from_physical_memory(usable_ram_bytes: usize) -> Self {
        const MIB_2: usize = 2 * 1024 * 1024;

        // Calculate initial heap size: RAM / 1024
        // This gives us ~0.1% of RAM, which is more than enough for Vec<FrameState>
        let initial = {
            let calculated = usable_ram_bytes / 1024;
            // Clamp between 2 MiB and 128 MiB
            let clamped = calculated.clamp(2 * 1024 * 1024, 128 * 1024 * 1024);
            // Round up to next 2MiB boundary (required for stage2 to start at a 2MiB boundary)
            clamped.div_ceil(MIB_2) * MIB_2
        };

        // Calculate total heap size: RAM / 256
        // This gives us ~0.4% of RAM for all kernel heap needs
        let total = {
            let calculated = usable_ram_bytes / 256;
            // Clamp between (initial + 2 MiB) and 512 MiB
            let clamped = calculated.clamp(initial + MIB_2, 512 * 1024 * 1024);
            // Round up to next 2MiB boundary
            clamped.div_ceil(MIB_2) * MIB_2
        };

        Self { initial, total }
    }

    fn initial(&self) -> usize {
        self.initial
    }

    fn total(&self) -> usize {
        self.total
    }
}

#[global_allocator]
static ALLOCATOR: linked_list_allocator::LockedHeap = linked_list_allocator::LockedHeap::empty();

pub(in crate::mem) fn init(address_space: &AddressSpace, usable_physical_memory_bytes: usize) {
    #[cfg(target_arch = "x86_64")]
    assert!(PhysicalMemory::is_initialized());
    #[cfg(target_arch = "aarch64")]
    assert!(phys::is_initialized());

    // Calculate and store heap sizes based on available RAM
    let heap_sizes = HeapSizes::from_physical_memory(usable_physical_memory_bytes);
    info!(
        "heap sizes: initial={} MiB, total={} MiB (for {} MiB RAM)",
        heap_sizes.initial() / 1024 / 1024,
        heap_sizes.total() / 1024 / 1024,
        usable_physical_memory_bytes / 1024 / 1024
    );
    HEAP_SIZES.init_once(|| heap_sizes);

    let initial_heap_size = HEAP_SIZES.get().unwrap().initial();

    #[cfg(target_arch = "x86_64")]
    {
        info!("initializing heap at {HEAP_START:p}");
        let page_range = PageRangeInclusive::<Size4KiB> {
            start: Page::containing_address(HEAP_START),
            end: Page::containing_address(HEAP_START + initial_heap_size as u64 - 1),
        };

        address_space
            .map_range_owned(
                page_range,
                PhysicalMemory::allocate_frames_non_contiguous(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .expect("should be able to map heap");
    }

    #[cfg(target_arch = "aarch64")]
    {
        let heap_start = HEAP_START.as_u64();
        info!("initializing heap at {:#x}", heap_start);
        let num_pages = initial_heap_size / 4096;
        let frames = core::iter::from_fn(phys::allocate_frame::<Size4KiB>).take(num_pages);

        let page_range = PageRangeInclusive::<Size4KiB> {
            start: Page::containing_address(HEAP_START),
            end: Page::containing_address(HEAP_START + (initial_heap_size as u64 - 1)),
        };

        address_space
            .map_range_owned(
                page_range,
                frames,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .expect("should be able to map heap");
    }

    // SAFETY: We are initializing the global allocator with a valid memory range
    // that has just been mapped. This is called only once during initialization.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let ptr = HEAP_START.as_mut_ptr();
        #[cfg(target_arch = "aarch64")]
        let ptr = HEAP_START.as_u64().into_usize() as *mut u8;

        ALLOCATOR.lock().init(ptr, initial_heap_size);
    }

    HEAP_INITIALIZED.store(true, Relaxed);
}

// In stage2, we already have the physical memory manager that uses the heap, which is much faster
// than the one we use on boot, so we allocate the largest portion of memory for the heap in stage2.
pub(in crate::mem) fn init_stage2() {
    assert!(HEAP_INITIALIZED.load(Relaxed));

    let heap_sizes = HEAP_SIZES.get().expect("heap sizes should be initialized");
    let initial_heap_size = heap_sizes.initial();
    let total_heap_size = heap_sizes.total();

    #[cfg(target_arch = "x86_64")]
    {
        let new_start = HEAP_START + initial_heap_size as u64;

        let page_range = PageRangeInclusive::<Size2MiB> {
            start: Page::containing_address(new_start),
            end: Page::containing_address(new_start + (total_heap_size - initial_heap_size) as u64),
        };

        let address_space = AddressSpace::kernel();
        address_space
            .map_range_owned(
                page_range,
                PhysicalMemory::allocate_frames_non_contiguous(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .expect("should be able to map more heap");
    }

    #[cfg(target_arch = "aarch64")]
    {
        let new_start = HEAP_START + initial_heap_size as u64;
        let size_to_map = total_heap_size - initial_heap_size;
        // On AArch64 we stick to 4KiB pages for now as we don't have block mapping iterator setup in address_space yet
        let num_pages = size_to_map / 4096;
        let frames = core::iter::from_fn(phys::allocate_frame::<Size4KiB>).take(num_pages);

        let page_range = PageRangeInclusive::<Size4KiB> {
            start: Page::containing_address(new_start),
            end: Page::containing_address(new_start + (size_to_map as u64 - 1)),
        };

        let address_space = AddressSpace::kernel();
        address_space
            .map_range_owned(
                page_range,
                frames,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .expect("should be able to map more heap");
    }

    // SAFETY: We are extending the global allocator with a new memory range
    // that has just been mapped. The range is contiguous with the previous heap.
    unsafe {
        ALLOCATOR.lock().extend(total_heap_size - initial_heap_size);
    }
}

#[derive(Copy, Clone)]
pub struct Heap;

impl Heap {
    pub fn is_initialized() -> bool {
        HEAP_INITIALIZED.load(Relaxed)
    }

    pub fn free() -> usize {
        ALLOCATOR.lock().free()
    }

    pub fn used() -> usize {
        ALLOCATOR.lock().used()
    }

    pub fn size() -> usize {
        ALLOCATOR.lock().size()
    }

    pub fn bottom() -> VirtAddr {
        #[cfg(target_arch = "x86_64")]
        return VirtAddr::new(ALLOCATOR.lock().bottom() as u64);
        #[cfg(target_arch = "aarch64")]
        return VirtAddr::new(ALLOCATOR.lock().bottom() as u64);
    }
}

impl core::fmt::Debug for Heap {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Heap")
            .field("initialized", &Self::is_initialized())
            .field("free", &Self::free())
            .field("used", &Self::used())
            .field("size", &Self::size())
            .finish()
    }
}
