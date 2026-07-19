use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::Relaxed;

use conquer_once::spin::OnceCell;
use log::info;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::phys;
#[cfg(target_arch = "x86_64")]
use crate::arch::types::Size2MiB;
use crate::arch::types::{Page, PageRangeInclusive, PageSize, PageTableFlags, Size4KiB, VirtAddr};
#[cfg(target_arch = "x86_64")]
use crate::mem::address_space::virt_addr_from_page_table_indices;
use crate::mem::address_space::{AddressSpace, MAP_RANGE_TRANSACTION_CAPACITY};
#[cfg(target_arch = "x86_64")]
use crate::mem::phys::PhysicalMemory;
#[cfg(target_arch = "aarch64")]
use crate::U64Ext;

#[path = "heap_policy.rs"]
mod policy;

use policy::{inclusive_end_offset, HeapSizes, PageChunks};

const _: () = assert!(
    core::mem::size_of::<kernel_physical_memory::FrameState>() + core::mem::size_of::<u32>()
        == policy::EXPECTED_FRAME_METADATA_BYTES,
    "boot heap metadata budget must be updated when frame metadata layout changes",
);

static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
static HEAP_START: VirtAddr = virt_addr_from_page_table_indices([257, 0, 0, 0], 0);

#[cfg(target_arch = "aarch64")]
static HEAP_START: VirtAddr = VirtAddr::new(crate::arch::aarch64::mem::kernel::HEAP_BASE as u64);

/// Runtime-initialized heap sizes based on available physical memory.
static HEAP_SIZES: OnceCell<HeapSizes> = OnceCell::uninit();

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
        let page_count = initial_heap_size / Size4KiB::SIZE as usize;
        for chunk in PageChunks::new(page_count, MAP_RANGE_TRANSACTION_CAPACITY) {
            let chunk_start = HEAP_START + (chunk.start_page * Size4KiB::SIZE as usize) as u64;
            let chunk_bytes = chunk.page_count * Size4KiB::SIZE as usize;
            let page_range = PageRangeInclusive::<Size4KiB> {
                start: Page::containing_address(chunk_start),
                end: Page::containing_address(chunk_start + inclusive_end_offset(chunk_bytes)),
            };

            // Stage 1 is a bump allocator and cannot release frames. Each
            // bounded transaction therefore rolls back PTEs only; any failure
            // aborts boot before the global heap becomes observable.
            address_space
                .map_range(
                    page_range,
                    PhysicalMemory::allocate_frames_non_contiguous().take(chunk.page_count),
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                )
                .expect("should be able to map heap chunk");
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let heap_start = HEAP_START.as_u64();
        info!("initializing heap at {:#x}", heap_start);
        let page_count = initial_heap_size / Size4KiB::SIZE as usize;
        for chunk in PageChunks::new(page_count, MAP_RANGE_TRANSACTION_CAPACITY) {
            let chunk_start = HEAP_START + (chunk.start_page * Size4KiB::SIZE as usize) as u64;
            let chunk_bytes = chunk.page_count * Size4KiB::SIZE as usize;
            let frames =
                core::iter::from_fn(phys::allocate_frame::<Size4KiB>).take(chunk.page_count);
            let page_range = PageRangeInclusive::<Size4KiB> {
                start: Page::containing_address(chunk_start),
                end: Page::containing_address(chunk_start + inclusive_end_offset(chunk_bytes)),
            };

            address_space
                .map_range(
                    page_range,
                    frames,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                )
                .expect("should be able to map heap chunk");
        }
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
            end: Page::containing_address(
                new_start + inclusive_end_offset(total_heap_size - initial_heap_size),
            ),
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
        // AArch64 uses 4 KiB pages for the extension until block-map
        // iteration is available. Keep each owned rollback transaction within
        // the same stack-backed capacity as the bootstrap mapping.
        let page_count = size_to_map / Size4KiB::SIZE as usize;
        let address_space = AddressSpace::kernel();
        for chunk in PageChunks::new(page_count, MAP_RANGE_TRANSACTION_CAPACITY) {
            let chunk_start = new_start + (chunk.start_page * Size4KiB::SIZE as usize) as u64;
            let chunk_bytes = chunk.page_count * Size4KiB::SIZE as usize;
            let frames =
                core::iter::from_fn(phys::allocate_frame::<Size4KiB>).take(chunk.page_count);
            let page_range = PageRangeInclusive::<Size4KiB> {
                start: Page::containing_address(chunk_start),
                end: Page::containing_address(chunk_start + inclusive_end_offset(chunk_bytes)),
            };

            address_space
                .map_range_owned(
                    page_range,
                    frames,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                )
                .expect("should be able to map more heap");
        }
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
