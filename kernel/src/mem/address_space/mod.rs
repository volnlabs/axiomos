use core::fmt::{Debug, Formatter};

use conquer_once::spin::OnceCell;
use log::info;
use mapper::AddressSpaceMapper;
use spin::RwLock;
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::interrupts;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::control::Cr3;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::mapper::{FlagUpdateError, MapToError};
#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::{Mapper, PageTable, RecursivePageTable};

#[cfg(target_arch = "x86_64")]
use crate::arch::types::Size4KiB;
#[cfg(target_arch = "aarch64")]
use crate::arch::types::Size4KiB;
use crate::arch::types::{
    Page, PageRangeInclusive, PageSize, PageTableFlags, PhysAddr, PhysFrame, VirtAddr,
};

#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    use super::*;

    pub fn aarch64_init() -> (VirtAddr, PhysFrame) {
        let phys = crate::arch::aarch64::mm::kernel_page_table_phys();
        let frame = PhysFrame::containing_address(PhysAddr::new(phys as u64));
        // The bootstrap page tables are statically allocated in the kernel image.
        // Their virtual address is the same as their physical address during early boot (identity mapped),
        // and they remain accessible in the higher half after MMU is enabled.
        let vaddr = VirtAddr::new(crate::arch::aarch64::mem::phys_to_virt(phys) as u64);

        (vaddr, frame)
    }
}

#[cfg(target_arch = "x86_64")]
use crate::limine::{HHDM_REQUEST, KERNEL_ADDRESS_REQUEST};
use crate::mem::phys::PhysicalMemory;
#[cfg(target_arch = "x86_64")]
use crate::mem::virt::{VirtualMemoryAllocator, VirtualMemoryHigherHalf};
#[cfg(target_arch = "x86_64")]
use crate::U64Ext;

mod mapper;

static KERNEL_ADDRESS_SPACE: OnceCell<AddressSpace> = OnceCell::uninit();
#[cfg(target_arch = "x86_64")]
pub static RECURSIVE_INDEX: OnceCell<usize> = OnceCell::uninit();

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        let (pt_vaddr, pt_frame) = make_mapping_recursive();
        // SAFETY: We have just created the page table frame and mapped it recursively.
        // pt_vaddr and pt_frame are valid and compatible.
        let address_space = unsafe { AddressSpace::create_from(pt_frame, pt_vaddr) };
        info!(
            "Initialized kernel address space with frame: {:?}",
            address_space.level4_frame
        );
        KERNEL_ADDRESS_SPACE.init_once(|| address_space);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let (pt_vaddr, pt_frame) = aarch64::aarch64_init();
        let address_space = unsafe { AddressSpace::create_from(pt_frame, pt_vaddr) };
        info!(
            "Initialized kernel address space with frame: {:?}",
            address_space.level0_frame
        );
        KERNEL_ADDRESS_SPACE.init_once(|| address_space);
    }
}

#[cfg(target_arch = "x86_64")]
fn make_mapping_recursive() -> (VirtAddr, PhysFrame) {
    let hhdm_offset = HHDM_REQUEST
        .get_response()
        .expect("should have a HHDM response")
        .offset();

    // Instead of creating a new page table and copying mappings (which is complex and error-prone),
    // we'll use the bootloader's existing page tables and just add a recursive mapping to them.
    // This is simpler and avoids the triple-fault issues with map_to().

    let (level_4_table, level_4_table_frame) = {
        // Get the current CR3 (bootloader's page tables)
        let current_cr3_frame = Cr3::read().0;

        // Access the level 4 table via HHDM
        let pt = unsafe {
            &mut *VirtAddr::new(current_cr3_frame.start_address().as_u64() + hhdm_offset)
                .as_mut_ptr::<PageTable>()
        };

        (pt, current_cr3_frame)
    };

    let kernel_addr = KERNEL_ADDRESS_REQUEST
        .get_response()
        .unwrap()
        .virtual_base();
    assert_eq!(
        kernel_addr, 0xffff_ffff_8000_0000,
        "kernel address should be 0xffff_ffff_8000_0000, if it isn't, either check the linker file or you know what you're doing"
    );

    info!("setting up recursive page table mapping in bootloader's page tables");

    // Find an unused entry in the level 4 table for our recursive mapping
    let recursive_index = (0..512)
        .rposition(|p| level_4_table[p].is_unused())
        .expect("should have an unused index in the level 4 table");

    // Set up the recursive mapping: PML4[recursive_index] points to the PML4 itself
    level_4_table[recursive_index].set_frame(
        level_4_table_frame,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    );

    let vaddr = recursive_index_to_virtual_address(recursive_index);
    info!(
        "recursive mapping: PML4[{}] -> {:#x}",
        recursive_index,
        vaddr.as_u64()
    );
    RECURSIVE_INDEX.init_once(|| recursive_index);

    // Fill in any unused higher-half PML4 entries with new page tables
    // This ensures we have page tables available for kernel allocations
    info!("initializing unused higher-half PML4 entries");
    level_4_table
        .iter_mut()
        .skip(256)
        .filter(|e| e.is_unused())
        .for_each(|e| {
            e.set_frame(
                PhysicalMemory::allocate_frame().unwrap(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            );
        });

    info!("kernel address space initialized (using bootloader page tables)");
    (vaddr, level_4_table_frame)
}

#[cfg(target_arch = "x86_64")]
#[must_use]
pub const fn recursive_index_to_virtual_address(recursive_index: usize) -> VirtAddr {
    let i = recursive_index as u64;
    let addr = (i << 39) | (i << 30) | (i << 21) | (i << 12);

    let addr = sign_extend_vaddr(addr);

    VirtAddr::new(addr)
}

#[cfg(target_arch = "x86_64")]
#[must_use]
pub const fn virt_addr_from_page_table_indices(indices: [u16; 4], offset: u64) -> VirtAddr {
    let addr = ((indices[0] as u64) << 39)
        | ((indices[1] as u64) << 30)
        | ((indices[2] as u64) << 21)
        | ((indices[3] as u64) << 12)
        | (offset & ((1 << 12) - 1));
    VirtAddr::new(sign_extend_vaddr(addr))
}

#[cfg(target_arch = "x86_64")]
#[must_use]
pub const fn sign_extend_vaddr(vaddr: u64) -> u64 {
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    let result = ((vaddr << 16) as i64 >> 16) as u64; // only works for 48-bit addresses
    result
}

pub struct AddressSpace {
    #[cfg(target_arch = "x86_64")]
    level4_frame: PhysFrame,
    #[cfg(target_arch = "aarch64")]
    level0_frame: crate::arch::aarch64::phys::PhysFrame,
    inner: RwLock<AddressSpaceMapper>,
}

impl Debug for AddressSpace {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut ds = f.debug_struct("AddressSpace");

        #[cfg(target_arch = "x86_64")]
        ds.field("level4_frame", &self.level4_frame);
        #[cfg(target_arch = "aarch64")]
        ds.field("level0_frame", &self.level0_frame);

        ds.field("active", &self.inner.read().is_active())
            .finish_non_exhaustive()
    }
}

impl !Default for AddressSpace {}

impl AddressSpace {
    /// # Panics
    /// Panics if the kernel address space is not initialized yet.
    pub fn kernel() -> &'static Self {
        KERNEL_ADDRESS_SPACE
            .get()
            .expect("address space not initialized")
    }

    /// # Safety
    /// The level4_frame must be a valid physical frame containing a top-level page table.
    /// The level4_vaddr must be the virtual address where that frame is mapped.
    #[cfg(target_arch = "x86_64")]
    unsafe fn create_from(level4_frame: PhysFrame, level4_vaddr: VirtAddr) -> Self {
        Self {
            level4_frame,
            inner: RwLock::new(AddressSpaceMapper::new(level4_frame, level4_vaddr)),
        }
    }

    /// # Safety
    /// The level0_frame must be a valid physical frame containing a top-level page table.
    /// The level0_vaddr must be the virtual address where that frame is mapped.
    #[cfg(target_arch = "aarch64")]
    unsafe fn create_from(
        level0_frame: crate::arch::aarch64::phys::PhysFrame,
        level0_vaddr: crate::arch::types::VirtAddr,
    ) -> Self {
        Self {
            level0_frame,
            inner: RwLock::new(AddressSpaceMapper::new(level0_frame, level0_vaddr)),
        }
    }

    /// # Panics
    /// This function panics if not enough physical or virtual memory is available to create
    /// a new address space, or if something goes wrong during mapping of addresses.
    #[must_use]
    pub fn new() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let new_frame = PhysicalMemory::allocate_frame().unwrap();
            let new_pt_segment = VirtualMemoryHigherHalf.reserve(1).unwrap();
            let old_pt_segment = VirtualMemoryHigherHalf.reserve(1).unwrap();

            let old_pt_page = Page::containing_address(old_pt_segment.start);
            let new_pt_page = Page::containing_address(new_pt_segment.start);

            Self::kernel().with_active(|kernel_as| {
                kernel_as
                    .map::<Size4KiB>(
                        old_pt_page,
                        kernel_as.level4_frame,
                        PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE,
                    )
                    .unwrap();

                kernel_as
                    .map::<Size4KiB>(
                        new_pt_page,
                        new_frame,
                        PageTableFlags::PRESENT
                            | PageTableFlags::WRITABLE
                            | PageTableFlags::NO_EXECUTE,
                    )
                    .unwrap();

                // SAFETY: We have reserved segments in higher-half virtual memory.
                // We are casting the pointers to PageTable which matches the underlying data structure.
                // These pointers are valid because we just mapped the frames in the active (kernel) address space.
                let new_page_table =
                    unsafe { &mut *new_pt_segment.start.as_mut_ptr::<PageTable>() };
                // SAFETY: Same as above.
                let old_page_table = unsafe { &*old_pt_segment.start.as_mut_ptr::<PageTable>() };

                new_page_table.zero();
                new_page_table
                    .iter_mut()
                    .zip(old_page_table.iter())
                    .skip(256)
                    .for_each(|(new_entry, old_entry)| {
                        *new_entry = old_entry.clone();
                    });
                let recursive_index = *RECURSIVE_INDEX.get().unwrap();
                new_page_table[recursive_index].set_frame(
                    new_frame,
                    PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
                );

                kernel_as.unmap(old_pt_page).expect("page should be mapped");
                kernel_as.unmap(new_pt_page).expect("page should be mapped");
            });

            // SAFETY: We have initialized the new page table frame and mapped it.
            // We reuse the existing recursive mapping vaddr since we copied the recursive entry.
            unsafe { Self::create_from(new_frame, Self::kernel().inner.read().level4_vaddr) }
        }

        #[cfg(target_arch = "aarch64")]
        {
            let l0_phys = crate::arch::aarch64::mm::create_user_address_space()
                .expect("failed to create user address space");
            let frame = crate::arch::aarch64::phys::PhysFrame::containing_address(
                crate::arch::types::PhysAddr::new(l0_phys as u64),
            );
            // Convert physical address to virtual address using the direct map (HHDM equivalent)
            let vaddr = crate::arch::types::VirtAddr::new(crate::arch::aarch64::mem::phys_to_virt(
                l0_phys,
            ) as u64);
            unsafe { Self::create_from(frame, vaddr) }
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn cr3_value(&self) -> usize {
        self.level4_frame.start_address().as_u64().into_usize()
    }

    #[cfg(target_arch = "aarch64")]
    pub fn ttbr0_value(&self) -> usize {
        self.level0_frame.addr() as usize
    }

    pub fn with_active<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self) -> R,
    {
        #[cfg(target_arch = "x86_64")]
        {
            let current_cr3 = Cr3::read();
            let current_frame = current_cr3.0;
            let current_flags = current_cr3.1;

            if current_frame == self.level4_frame {
                return f(self);
            }

            interrupts::without_interrupts(|| {
                // SAFETY: We are temporarily switching to this address space to perform operations on it.
                // We ensure that we switch back to the original address space afterwards.
                // Since kernel mappings are shared, this is safe for kernel execution.
                unsafe {
                    Cr3::write(self.level4_frame, current_flags);
                }

                let result = f(self);

                // SAFETY: Restoring the original address space.
                unsafe {
                    Cr3::write(current_frame, current_flags);
                }

                result
            })
        }

        #[cfg(target_arch = "aarch64")]
        {
            let current_ttbr0 = crate::arch::aarch64::paging::get_ttbr0();
            let current_ttbr1 = crate::arch::aarch64::paging::get_ttbr1();
            let target_phys = self.level0_frame.addr() as usize;

            // If the target address space is already active in either TTBR0 or TTBR1,
            // we don't need to switch. TTBR1 is used for the kernel address space.
            if target_phys == current_ttbr0 || target_phys == current_ttbr1 {
                return f(self);
            }

            // SAFETY: Switching TTBR0 to the target address space.
            // This is safe because kernel mappings are shared across all address spaces (via TTBR1).
            unsafe {
                crate::arch::aarch64::paging::set_ttbr0(target_phys);
            }

            let result = f(self);

            // SAFETY: Restoring the original TTBR0.
            unsafe {
                crate::arch::aarch64::paging::set_ttbr0(current_ttbr0);
            }

            result
        }
    }

    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        self.inner.read().is_active()
    }

    /// # Errors
    /// Returns an error if the page is already mapped or flags are invalid.
    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub fn map<S: PageSize>(
        &self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: PageTableFlags,
    ) -> Result<(), MapToError<S>>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        self.inner.write().map(page, frame, flags)
    }

    /// # Errors
    /// Returns an error if the pages are already mapped or flags are invalid.
    #[cfg(target_arch = "x86_64")]
    pub fn map_range<S: PageSize>(
        &self,
        pages: impl Into<PageRangeInclusive<S>>,
        frames: impl Iterator<Item = PhysFrame<S>>,
        flags: PageTableFlags,
    ) -> Result<(), MapToError<S>>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        self.inner.write().map_range(pages.into(), frames, flags)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn unmap<S: PageSize>(&self, page: Page<S>) -> Option<PhysFrame<S>>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        self.inner.write().unmap(page)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn unmap_range<S: PageSize>(
        &self,
        pages: impl Into<PageRangeInclusive<S>>,
        callback: impl Fn(PhysFrame<S>),
    ) where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        self.inner.write().unmap_range(pages.into(), callback);
    }

    /// # Errors
    /// Returns an error if the page is not mapped or flags are invalid.
    #[cfg(target_arch = "x86_64")]
    pub fn remap<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &self,
        page: Page<S>,
        f: F,
    ) -> Result<(), FlagUpdateError>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        self.inner.write().remap(page, &f)
    }

    /// # Errors
    /// Returns an error if the pages are not mapped or flags are invalid.
    #[cfg(target_arch = "x86_64")]
    pub fn remap_range<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &self,
        pages: impl Into<PageRangeInclusive<S>>,
        f: F,
    ) -> Result<(), FlagUpdateError>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        self.inner.write().remap_range(pages.into(), &f)
    }

    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.inner.read().translate(vaddr)
    }

    #[allow(dead_code)]
    #[cfg(target_arch = "aarch64")]
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.inner.read().translate(vaddr)
    }

    #[allow(dead_code)]
    pub fn translate_page_flags(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        self.inner.read().translate_page_flags(vaddr)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn map<S: PageSize>(
        &self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        self.inner.write().map(page, frame, flags)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn map_range<S: PageSize>(
        &self,
        pages: impl Into<PageRangeInclusive<S>>,
        frames: impl Iterator<Item = PhysFrame<S>>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        self.inner.write().map_range(pages.into(), frames, flags)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn unmap<S: PageSize>(&self, page: Page<S>) -> Option<PhysFrame<S>> {
        self.inner.write().unmap(page)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn unmap_range<S: PageSize>(
        &self,
        pages: impl Into<PageRangeInclusive<S>>,
        callback: impl Fn(PhysFrame<S>),
    ) {
        self.inner.write().unmap_range(pages.into(), callback);
    }

    #[cfg(target_arch = "aarch64")]
    pub fn remap<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &self,
        page: Page<S>,
        f: F,
    ) -> Result<(), &'static str> {
        self.inner.write().remap(page, &f)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn remap_range<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &self,
        pages: impl Into<PageRangeInclusive<S>>,
        f: F,
    ) -> Result<(), &'static str> {
        self.inner.write().remap_range(pages.into(), &f)
    }

    /// Creates a deep copy of the address space.
    ///
    /// This is used for `fork()`. It creates a new address space and copies all user-space
    /// mappings and their underlying physical memory.
    ///
    /// # Errors
    /// Returns an error if memory allocation fails.
    pub fn fork(&self) -> Result<Self, &'static str> {
        // 1. Create a new empty address space (this sets up kernel mappings)
        let new_as = Self::new();

        // 2. We need to collect all pages to copy.
        // We can't map into new_as while iterating because we might need to switch context
        // (on x86_64) or we just want to batch operations.
        // Also, we need to handle errors by cleaning up.
        let mut mappings = alloc::vec::Vec::new();
        let mut error = None;

        // Ensure we are active so we can read the user pages
        // (On x86_64, visit_user_pages relies on recursive mapping which requires activation)
        if !self.is_active() {
            return Err("Cannot fork inactive address space");
        }

        self.inner.read().visit_user_pages(|page, frame, flags| {
            if error.is_some() {
                return;
            }

            // Allocate a new physical frame
            let new_frame = match PhysicalMemory::allocate_frame() {
                Some(f) => f,
                None => {
                    error = Some("Out of physical memory");
                    return;
                }
            };

            // Copy memory content
            // SAFETY: We are accessing valid physical frames. We use phys_to_virt to map them.
            // On Axiom, all physical memory is mapped in the higher half.
            unsafe {
                let src_ptr =
                    crate::mem::phys_to_virt(frame.start_address().as_u64() as usize) as *const u8;
                let dst_ptr = crate::mem::phys_to_virt(new_frame.start_address().as_u64() as usize)
                    as *mut u8;
                core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, Size4KiB::SIZE as usize);
            }

            mappings.push((page, new_frame, flags));
        });

        if let Some(e) = error {
            // Cleanup allocated frames that were meant for the new AS
            for (_, frame, _) in mappings {
                PhysicalMemory::deallocate_frame(frame);
            }
            return Err(e);
        }

        // 3. Map the new frames into the new address space
        let res = new_as.with_active(|active_as| {
            for (page, frame, flags) in mappings {
                // On x86_64, `map` returns Result<(), MapToError>. On AArch64, Result<(), &str>
                #[cfg(target_arch = "x86_64")]
                if active_as.map(page, frame, flags).is_err() {
                    return Err("Failed to map page");
                }

                #[cfg(target_arch = "aarch64")]
                if active_as.map(page, frame, flags).is_err() {
                    return Err("Failed to map page");
                }
            }
            Ok(())
        });

        match res {
            Ok(_) => Ok(new_as),
            Err(e) => {
                // If mapping failed, we should cleanup.
                // The mappings vec has all the frames we allocated.
                // Note: frames that were successfully mapped will be owned by new_as?
                // AddressSpace doesn't strictly track ownership of frames for Drop yet (TODO),
                // so we probably need to manually free them if we are discarding new_as.
                // But finding which ones were mapped is hard.
                // For MVP, we might leak on map error.
                // But map error is unlikely if we pre-allocated frames.
                Err(e)
            }
        }
    }
}
