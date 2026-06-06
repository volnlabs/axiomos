#[cfg(target_arch = "x86_64")]
use x86_64::registers::control::Cr3;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::mapper::{FlagUpdateError, MapToError, TranslateResult};
#[cfg(target_arch = "x86_64")]
use x86_64::structures::paging::{Mapper, PageTable, RecursivePageTable, Translate};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::paging::PageTableWalker;
use crate::arch::types::{
    Page, PageRangeInclusive, PageSize, PageTableFlags, PhysAddr, PhysFrame, VirtAddr,
};
#[cfg(target_arch = "x86_64")]
use crate::mem::phys::PhysicalMemory;

#[derive(Debug)]
pub struct AddressSpaceMapper {
    #[cfg(target_arch = "x86_64")]
    level4_frame: PhysFrame,
    #[cfg(target_arch = "x86_64")]
    pub(crate) level4_vaddr: VirtAddr,
    #[cfg(target_arch = "x86_64")]
    page_table: RecursivePageTable<'static>,

    #[cfg(target_arch = "aarch64")]
    level0_frame: PhysFrame,
    #[cfg(target_arch = "aarch64")]
    pub(crate) level0_vaddr: VirtAddr,
}

impl AddressSpaceMapper {
    #[cfg(target_arch = "x86_64")]
    pub fn new(level4_frame: PhysFrame, level4_vaddr: VirtAddr) -> Self {
        let page_table = {
            // SAFETY: The caller ensures that level4_vaddr points to a valid PageTable
            // and that we have exclusive access (or appropriate synchronization) to it.
            let pt = unsafe { &mut *level4_vaddr.as_mut_ptr::<PageTable>() };
            RecursivePageTable::new(pt).expect("should be a valid recursive page table")
        };

        Self {
            level4_frame,
            level4_vaddr,
            page_table,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn new(level0_frame: PhysFrame, level0_vaddr: VirtAddr) -> Self {
        Self {
            level0_frame,
            level0_vaddr,
        }
    }

    pub fn is_active(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            self.level4_frame == Cr3::read().0
        }

        #[cfg(target_arch = "aarch64")]
        {
            self.level0_frame.addr() == crate::arch::aarch64::paging::get_ttbr0() as u64
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn map<S: PageSize>(
        &mut self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: PageTableFlags,
    ) -> Result<(), MapToError<S>>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        assert!(self.is_active());

        #[cfg(debug_assertions)]
        {
            if !flags.contains(PageTableFlags::PRESENT) {
                ::log::warn!(
                    "mapping {:p} to {:p} without PRESENT flag",
                    page.start_address(),
                    frame.start_address()
                );
            }
        }

        // SAFETY: We hold a mutable reference to the mapper, ensuring exclusive access.
        // The frame allocator (PhysicalMemory) is thread-safe.
        unsafe {
            self.page_table
                .map_to(page, frame, flags, &mut PhysicalMemory)?
                .flush();
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn map_range<S: PageSize>(
        &mut self,
        pages: PageRangeInclusive<S>,
        frames: impl Iterator<Item = PhysFrame<S>>,
        flags: PageTableFlags,
    ) -> Result<(), MapToError<S>>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        assert!(self.is_active());

        let mut frames = frames.into_iter();

        for page in pages {
            let frame = frames.next().ok_or(MapToError::FrameAllocationFailed)?;
            self.map(page, frame, flags)?;
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn unmap<S: PageSize>(&mut self, page: Page<S>) -> Option<PhysFrame<S>>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        assert!(self.is_active());

        if let Ok((frame, flusher)) = self.page_table.unmap(page) {
            flusher.flush();
            Some(frame)
        } else {
            None
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn unmap_range<S: PageSize>(
        &mut self,
        pages: PageRangeInclusive<S>,
        callback: impl Fn(PhysFrame<S>),
    ) where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        assert!(self.is_active());

        for page in pages {
            self.unmap(page).map(&callback);
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn remap<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &mut self,
        page: Page<S>,
        f: &F,
    ) -> Result<(), FlagUpdateError>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        assert!(self.is_active());

        let TranslateResult::Mapped {
            frame: _,
            offset: _,
            flags,
        } = self.page_table.translate(page.start_address())
        else {
            return Err(FlagUpdateError::PageNotMapped);
        };
        // SAFETY: We checked that the page is mapped. We hold exclusive access via &mut self.
        let flusher = unsafe { self.page_table.update_flags(page, f(flags)) }?;
        flusher.flush();
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn remap_range<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &mut self,
        pages: PageRangeInclusive<S>,
        f: &F,
    ) -> Result<(), FlagUpdateError>
    where
        for<'a> RecursivePageTable<'a>: Mapper<S>,
    {
        assert!(self.is_active());

        for page in pages {
            self.remap(page, &f)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn map<S: PageSize>(
        &mut self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let mut walker = unsafe { PageTableWalker::new(self.level0_vaddr.as_mut_ptr()) };
        walker.map_page(
            page.start_address().as_usize(),
            frame.start_address().as_u64() as usize,
            flags.to_pte_bits(),
        )
    }

    #[cfg(target_arch = "aarch64")]
    pub fn map_range<S: PageSize>(
        &mut self,
        pages: PageRangeInclusive<S>,
        frames: impl Iterator<Item = PhysFrame<S>>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let mut frames = frames.into_iter();
        for page in pages {
            let frame = frames.next().ok_or("Not enough frames for range")?;
            self.map(page, frame, flags)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn unmap<S: PageSize>(&mut self, page: Page<S>) -> Option<PhysFrame<S>> {
        let mut walker = unsafe { PageTableWalker::new(self.level0_vaddr.as_mut_ptr()) };
        walker
            .unmap_page(page.start_address().as_usize())
            .ok()
            .map(|phys| PhysFrame::containing_address(PhysAddr::new(phys as u64)))
    }

    #[cfg(target_arch = "aarch64")]
    pub fn unmap_range<S: PageSize>(
        &mut self,
        pages: PageRangeInclusive<S>,
        callback: impl Fn(PhysFrame<S>),
    ) {
        for page in pages {
            if let Some(frame) = self.unmap(page) {
                callback(frame);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn remap<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &mut self,
        page: Page<S>,
        f: &F,
    ) -> Result<(), &'static str> {
        let mut walker = unsafe { PageTableWalker::new(self.level0_vaddr.as_mut_ptr()) };
        let vaddr = page.start_address().as_usize();
        let (_phys, raw_flags) = walker.translate_full(vaddr).ok_or("Page not mapped")?;

        let old_flags = PageTableFlags::from_pte_bits(raw_flags);
        let new_flags = f(old_flags);

        let phys = walker.unmap_page(vaddr)?;
        let pte_bits = new_flags.to_pte_bits();

        walker.map_page(vaddr, phys, pte_bits)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn remap_range<S: PageSize, F: Fn(PageTableFlags) -> PageTableFlags>(
        &mut self,
        pages: PageRangeInclusive<S>,
        f: &F,
    ) -> Result<(), &'static str> {
        for page in pages {
            self.remap(page, f)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.page_table.translate_addr(vaddr)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn translate_page_flags(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        let TranslateResult::Mapped {
            frame,
            offset,
            flags,
        } = self.page_table.translate(vaddr)
        else {
            return None;
        };

        Some((frame.start_address() + offset, flags))
    }

    #[cfg(target_arch = "aarch64")]
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let walker = unsafe { PageTableWalker::new(self.level0_vaddr.as_mut_ptr()) };
        walker
            .translate(vaddr.as_usize())
            .map(|phys| PhysAddr::new(phys as u64))
    }

    #[cfg(target_arch = "aarch64")]
    pub fn translate_page_flags(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        let walker = unsafe { PageTableWalker::new(self.level0_vaddr.as_mut_ptr()) };
        walker
            .translate_full(vaddr.as_usize())
            .map(|(phys, raw_flags)| {
                (
                    PhysAddr::new(phys as u64),
                    PageTableFlags::from_pte_bits(raw_flags),
                )
            })
    }

    pub fn visit_user_pages<F>(&self, mut callback: F)
    where
        F: FnMut(
            Page<crate::arch::types::Size4KiB>,
            PhysFrame<crate::arch::types::Size4KiB>,
            PageTableFlags,
        ),
    {
        #[cfg(target_arch = "x86_64")]
        {
            use x86_64::structures::paging::PageTable;
            // On x86_64, user space is the lower half (entries 0-255 of PML4)
            // We need to walk the page tables manually since RecursivePageTable doesn't provide iteration

            // We can access the PML4 via the recursive mapping or HHDM if we knew the physical address
            // Since we have self.page_table (RecursivePageTable), it points to the ACTIVE PML4
            // But we might be iterating an inactive one?
            // The AddressSpace struct ensures we only create a mapper for an active AS or we use HHDM...
            // Wait, AddressSpaceMapper::new takes level4_vaddr.

            let pml4 = unsafe { &*self.level4_vaddr.as_ptr::<PageTable>() };

            for (i, entry) in pml4.iter().enumerate().take(256) {
                if !entry.is_unused()
                    && entry.flags().contains(PageTableFlags::PRESENT)
                    && !entry.flags().contains(PageTableFlags::HUGE_PAGE)
                {
                    let pdpt_addr = crate::mem::phys_to_virt(entry.addr().as_u64() as usize);
                    let pdpt = unsafe { &*VirtAddr::new(pdpt_addr as u64).as_ptr::<PageTable>() };

                    for (j, entry) in pdpt.iter().enumerate() {
                        if !entry.is_unused()
                            && entry.flags().contains(PageTableFlags::PRESENT)
                            && !entry.flags().contains(PageTableFlags::HUGE_PAGE)
                        {
                            let pd_addr = crate::mem::phys_to_virt(entry.addr().as_u64() as usize);
                            let pd =
                                unsafe { &*VirtAddr::new(pd_addr as u64).as_ptr::<PageTable>() };

                            for (k, entry) in pd.iter().enumerate() {
                                if !entry.is_unused()
                                    && entry.flags().contains(PageTableFlags::PRESENT)
                                    && !entry.flags().contains(PageTableFlags::HUGE_PAGE)
                                {
                                    let pt_addr =
                                        crate::mem::phys_to_virt(entry.addr().as_u64() as usize);
                                    let pt = unsafe {
                                        &*VirtAddr::new(pt_addr as u64).as_ptr::<PageTable>()
                                    };

                                    for (l, entry) in pt.iter().enumerate() {
                                        if !entry.is_unused()
                                            && entry.flags().contains(PageTableFlags::PRESENT)
                                        {
                                            let page_addr = crate::mem::address_space::virt_addr_from_page_table_indices(
                                                [i as u16, j as u16, k as u16, l as u16], 0
                                            );
                                            let page = Page::containing_address(page_addr);
                                            let frame = PhysFrame::containing_address(entry.addr());
                                            callback(page, frame, entry.flags());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // On AArch64, user space is TTBR0.
            // We walk the table at self.level0_vaddr
            // This is a simplified walker assuming 4KB pages and 4 levels (L0-L3)
            use crate::arch::aarch64::paging::PageTableEntry;

            // L0 table (512 entries)
            let l0_table = unsafe {
                core::slice::from_raw_parts(self.level0_vaddr.as_ptr::<PageTableEntry>(), 512)
            };

            for (i, entry) in l0_table.iter().enumerate() {
                if entry.is_valid() && entry.is_table() {
                    let l1_phys = entry.addr();
                    let l1_virt = crate::mem::phys_to_virt(l1_phys);
                    let l1_table = unsafe {
                        core::slice::from_raw_parts(
                            VirtAddr::new(l1_virt as u64).as_ptr::<PageTableEntry>(),
                            512,
                        )
                    };

                    for (j, entry) in l1_table.iter().enumerate() {
                        if entry.is_valid() && entry.is_table() {
                            let l2_phys = entry.addr();
                            let l2_virt = crate::mem::phys_to_virt(l2_phys);
                            let l2_table = unsafe {
                                core::slice::from_raw_parts(
                                    VirtAddr::new(l2_virt as u64).as_ptr::<PageTableEntry>(),
                                    512,
                                )
                            };

                            for (k, entry) in l2_table.iter().enumerate() {
                                if entry.is_valid() && entry.is_table() {
                                    let l3_phys = entry.addr();
                                    let l3_virt = crate::mem::phys_to_virt(l3_phys);
                                    let l3_table = unsafe {
                                        core::slice::from_raw_parts(
                                            VirtAddr::new(l3_virt as u64)
                                                .as_ptr::<PageTableEntry>(),
                                            512,
                                        )
                                    };

                                    for (l, entry) in l3_table.iter().enumerate() {
                                        if entry.is_valid() {
                                            // Calculate virtual address
                                            // 48-bit address: 9 bits per level + 12 bits offset
                                            // L0: 47..39, L1: 38..30, L2: 29..21, L3: 20..12
                                            let virt = ((i as u64) << 39)
                                                | ((j as u64) << 30)
                                                | ((k as u64) << 21)
                                                | ((l as u64) << 12);
                                            let page =
                                                Page::containing_address(VirtAddr::new(virt));
                                            let frame = PhysFrame::containing_address(
                                                PhysAddr::new(entry.addr() as u64),
                                            );
                                            let flags = PageTableFlags::from_pte_bits(entry.raw());
                                            callback(page, frame, flags);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
