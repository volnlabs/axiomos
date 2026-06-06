//! ARM64 Paging Implementation
//!
//! Implements 4-level page tables for ARM64 with 4KB granule and 48-bit VA.
//! Supports both kernel (TTBR1) and user (TTBR0) address spaces.

use core::ptr;

use bitflags::bitflags;

use super::mem::{
    mair, phys_to_virt, pte_flags, ENTRIES_PER_TABLE, L0_SHIFT, L1_BLOCK_SIZE, L1_SHIFT,
    L2_BLOCK_SIZE, L2_SHIFT, L3_SHIFT, PAGE_SIZE,
};
use super::phys::{self};

bitflags! {
    /// Page table entry flags for AArch64.
    /// Maps to AArch64 PTE bits (Valid, AP bits, UXN/PXN).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PageTableFlags: u64 {
        /// Bit 0: Valid bit.
        const PRESENT = pte_flags::VALID;
        /// AP[2] bit: 0 for RW, 1 for RO. WRITABLE means AP[2] = 0.
        const WRITABLE = 1 << 63; // Placeholder bit to be handled in conversion
        /// UXN and PXN bits.
        const NO_EXECUTE = pte_flags::UXN | pte_flags::PXN;
        /// AP[1] bit: 1 for user access.
        const USER_ACCESSIBLE = pte_flags::AP_RW_ALL;
        /// Bit 1: Table bit (0 for block/page).
        const HUGE_PAGE = 0;
        /// Custom bit to mark this as a device mapping (Device-nGnRE)
        const MMIO_DEVICE = 1 << 62;
        /// Software-defined bit used to mark a userspace page as copy-on-write.
        const COPY_ON_WRITE = 1 << 55;
    }
}

impl PageTableFlags {
    /// Convert PageTableFlags to raw AArch64 PTE bits.
    pub fn to_pte_bits(self) -> u64 {
        let mut bits = self.bits() & !((1 << 63) | (1 << 62)); // Remove our placeholders

        if self.contains(PageTableFlags::WRITABLE) {
            bits &= !(1 << 7);
        } else {
            bits |= 1 << 7;
        }

        if self.contains(PageTableFlags::PRESENT) {
            bits |= pte_flags::AF | pte_flags::SH_INNER;

            // Set memory attributes based on MMIO_DEVICE flag
            if self.contains(PageTableFlags::MMIO_DEVICE) {
                // Device-nGnRE (Index 1) - used for MMIO
                bits |= pte_flags::attr_index(mair::DEVICE_NGNRE);
                // Device memory is typically outer shareable or non-shareable,
                // but SH_INNER is ignored for Device-nGnRnE/nGnRE on some implementations.
                // Keeping SH_INNER for consistency, but MAIR rules apply.
            } else {
                // Normal WB (Index 2) - used for RAM
                bits |= pte_flags::attr_index(mair::NORMAL_WB);
            }

            bits |= pte_flags::PAGE;
        }

        bits
    }

    /// Convert raw AArch64 PTE bits back to PageTableFlags.
    pub fn from_pte_bits(bits: u64) -> Self {
        let mut flags = PageTableFlags::empty();

        if bits & pte_flags::VALID != 0 {
            flags |= PageTableFlags::PRESENT;
        }

        if bits & (1 << 7) == 0 {
            flags |= PageTableFlags::WRITABLE;
        }

        if bits & (pte_flags::UXN | pte_flags::PXN) != 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        if bits & (1 << 6) != 0 {
            flags |= PageTableFlags::USER_ACCESSIBLE;
        }

        // Check for Device-nGnRE attribute (Index 1)
        if (bits >> 2) & 0x7 == mair::DEVICE_NGNRE as u64 {
            flags |= PageTableFlags::MMIO_DEVICE;
        }

        if bits & PageTableFlags::COPY_ON_WRITE.bits() != 0 {
            flags |= PageTableFlags::COPY_ON_WRITE;
        }

        flags
    }
}

/// Page table entry for 4KB granule
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create an empty (invalid) entry
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a table descriptor pointing to next level page table
    pub const fn table(phys_addr: usize) -> Self {
        Self((phys_addr as u64) | pte_flags::VALID | pte_flags::TABLE)
    }

    /// Create a page descriptor (L3 entry)
    pub const fn page(phys_addr: usize, flags: u64) -> Self {
        Self((phys_addr as u64) | flags)
    }

    /// Create a block descriptor (L1/L2 entry for large mappings)
    pub const fn block(phys_addr: usize, flags: u64) -> Self {
        Self((phys_addr as u64) | (flags & !pte_flags::TABLE) | pte_flags::VALID)
    }

    /// Check if entry is valid
    pub const fn is_valid(&self) -> bool {
        self.0 & pte_flags::VALID != 0
    }

    /// Check if entry is a table descriptor (points to next level)
    pub const fn is_table(&self) -> bool {
        (self.0 & 0x3) == 0x3
    }

    /// Check if entry is a block descriptor
    pub const fn is_block(&self) -> bool {
        (self.0 & 0x3) == 0x1
    }

    /// Get the physical address from this entry
    pub const fn addr(&self) -> usize {
        (self.0 & 0x0000_FFFF_FFFF_F000) as usize
    }

    /// Get raw value
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Set the entry value
    pub fn set(&mut self, value: u64) {
        self.0 = value;
    }

    /// Clear the entry
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

/// Page table (512 entries for 4KB granule)
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create an empty page table
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry::empty(); ENTRIES_PER_TABLE],
        }
    }

    /// Get entry at index
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    /// Get mutable entry at index
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }

    /// Zero all entries
    pub fn zero(&mut self) {
        for entry in &mut self.entries {
            entry.clear();
        }
    }
}

/// Extract page table indices from virtual address
pub const fn va_to_indices(va: usize) -> [usize; 4] {
    [
        (va >> L0_SHIFT) & 0x1FF,
        (va >> L1_SHIFT) & 0x1FF,
        (va >> L2_SHIFT) & 0x1FF,
        (va >> L3_SHIFT) & 0x1FF,
    ]
}

/// Page table walker for creating and walking page tables
pub struct PageTableWalker {
    root: *mut PageTable,
}

impl PageTableWalker {
    /// Create a new walker with the given root table
    ///
    /// # Safety
    /// The root pointer must be valid and properly aligned.
    pub unsafe fn new(root: *mut PageTable) -> Self {
        Self { root }
    }

    /// Get the root table physical address
    pub fn root_phys(&self) -> usize {
        self.root as usize
    }

    /// Map a single 4KB page
    ///
    /// Creates intermediate tables as needed.
    pub fn map_page(&mut self, virt: usize, phys: usize, flags: u64) -> Result<(), &'static str> {
        let indices = va_to_indices(virt);

        let l1_ptr = Self::get_or_create_table_ptr(self.root, indices[0])?;
        let l2_ptr = Self::get_or_create_table_ptr(l1_ptr, indices[1])?;
        let l3_ptr = Self::get_or_create_table_ptr(l2_ptr, indices[2])?;

        let l3 = unsafe { &mut *l3_ptr };
        let entry = l3.entry_mut(indices[3]);
        if entry.is_valid() {
            log::error!(
                "Page already mapped: virt={:#x}, existing entry={:#x}",
                virt,
                entry.raw()
            );
            return Err("Page already mapped");
        }

        *entry = PageTableEntry::page(phys, flags);

        // Ensure the write is visible to the MMU and subsequent instruction fetches
        unsafe {
            core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags));
        }

        Ok(())
    }

    /// Map a 1GB block (L1 entry)
    pub fn map_l1_block(
        &mut self,
        virt: usize,
        phys: usize,
        flags: u64,
    ) -> Result<(), &'static str> {
        if virt & (L1_BLOCK_SIZE - 1) != 0 || phys & (L1_BLOCK_SIZE - 1) != 0 {
            return Err("Address not aligned to 1GB boundary");
        }

        let indices = va_to_indices(virt);
        let _l0 = unsafe { &mut *self.root };
        let l1_ptr = Self::get_or_create_table_ptr(self.root, indices[0])?;
        let l1 = unsafe { &mut *l1_ptr };

        let entry = l1.entry_mut(indices[1]);
        if entry.is_valid() {
            return Err("L1 entry already mapped");
        }

        *entry = PageTableEntry::block(phys, flags);

        unsafe {
            core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags));
        }

        Ok(())
    }

    /// Map a 2MB block (L2 entry)
    pub fn map_l2_block(
        &mut self,
        virt: usize,
        phys: usize,
        flags: u64,
    ) -> Result<(), &'static str> {
        if virt & (L2_BLOCK_SIZE - 1) != 0 || phys & (L2_BLOCK_SIZE - 1) != 0 {
            return Err("Address not aligned to 2MB boundary");
        }

        let indices = va_to_indices(virt);
        let l1_ptr = Self::get_or_create_table_ptr(self.root, indices[0])?;
        let l2_ptr = Self::get_or_create_table_ptr(l1_ptr, indices[1])?;
        let l2 = unsafe { &mut *l2_ptr };

        let entry = l2.entry_mut(indices[2]);
        if entry.is_valid() {
            return Err("L2 entry already mapped");
        }

        *entry = PageTableEntry::block(phys, flags);

        unsafe {
            core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags));
        }

        Ok(())
    }

    /// Map a range of pages
    pub fn map_range(
        &mut self,
        virt_start: usize,
        phys_start: usize,
        size: usize,
        flags: u64,
    ) -> Result<(), &'static str> {
        let pages = size.div_ceil(PAGE_SIZE);

        for i in 0..pages {
            let virt = virt_start + i * PAGE_SIZE;
            let phys = phys_start + i * PAGE_SIZE;
            self.map_page(virt, phys, flags)?;
        }

        Ok(())
    }

    /// Unmap a page and return its physical address
    pub fn unmap_page(&mut self, virt: usize) -> Result<usize, &'static str> {
        let indices = va_to_indices(virt);

        let l0 = unsafe { &mut *self.root };
        let l1 = self
            .get_table(l0, indices[0])
            .ok_or("L1 table not present")?;
        let l2 = self
            .get_table(l1, indices[1])
            .ok_or("L2 table not present")?;
        let l3 = self
            .get_table(l2, indices[2])
            .ok_or("L3 table not present")?;

        let entry = l3.entry_mut(indices[3]);
        if !entry.is_valid() {
            return Err("Page not mapped");
        }

        let phys = entry.addr();
        entry.clear();

        flush_tlb_page(virt);

        Ok(phys)
    }

    /// Translate virtual address to physical address and raw flags
    pub fn translate_full(&self, virt: usize) -> Option<(usize, u64)> {
        let indices = va_to_indices(virt);

        let l0 = unsafe { &*self.root };
        let entry0 = l0.entry(indices[0]);
        if !entry0.is_valid() {
            return None;
        }
        if entry0.is_block() {
            let offset = virt & ((1 << L0_SHIFT) - 1);
            return Some((entry0.addr() + offset, entry0.raw()));
        }

        let l1 = self.get_table_readonly(l0, indices[0])?;
        let entry1 = l1.entry(indices[1]);
        if !entry1.is_valid() {
            return None;
        }
        if entry1.is_block() {
            let offset = virt & ((1 << L1_SHIFT) - 1);
            return Some((entry1.addr() + offset, entry1.raw()));
        }

        let l2 = self.get_table_readonly(l1, indices[1])?;
        let entry2 = l2.entry(indices[2]);
        if !entry2.is_valid() {
            return None;
        }
        if entry2.is_block() {
            let offset = virt & ((1 << L2_SHIFT) - 1);
            return Some((entry2.addr() + offset, entry2.raw()));
        }

        let l3 = self.get_table_readonly(l2, indices[2])?;
        let entry3 = l3.entry(indices[3]);
        if entry3.is_valid() {
            let offset = virt & (PAGE_SIZE - 1);
            Some((entry3.addr() + offset, entry3.raw()))
        } else {
            None
        }
    }

    /// Translate virtual address to physical address
    pub fn translate(&self, virt: usize) -> Option<usize> {
        self.translate_full(virt).map(|(addr, _)| addr)
    }

    /// Get or create a table at the given index (using raw pointers)
    fn get_or_create_table_ptr(
        table: *mut PageTable,
        index: usize,
    ) -> Result<*mut PageTable, &'static str> {
        let entry = unsafe { (*table).entry_mut(index) };

        if entry.is_valid() {
            if !entry.is_table() {
                log::error!(
                    "Entry at index {} is block, not table: {:#x}",
                    index,
                    entry.raw()
                );
                return Err("Entry is block, not table");
            }
            Ok(phys_to_virt(entry.addr()) as *mut PageTable)
        } else {
            let frame =
                phys::allocate_frame::<crate::arch::types::Size4KiB>().ok_or_else(|| {
                    log::error!(
                        "Failed to allocate physical frame for page table at index {}",
                        index
                    );
                    "Out of memory for page table"
                })?;
            let phys_addr = frame.addr() as usize;
            let virt_addr = phys_to_virt(phys_addr);
            let table_ptr = virt_addr as *mut PageTable;

            unsafe {
                ptr::write_bytes(table_ptr, 0, 1);
            }

            *entry = PageTableEntry::table(phys_addr);

            // Ensure the write is visible to the MMU before it's used for translation
            unsafe {
                core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
            }

            Ok(table_ptr)
        }
    }

    /// Get existing table at index (mutable)
    fn get_table<'a>(&self, table: &'a mut PageTable, index: usize) -> Option<&'a mut PageTable> {
        let entry = table.entry(index);
        if entry.is_valid() && entry.is_table() {
            let next_table = phys_to_virt(entry.addr()) as *mut PageTable;
            Some(unsafe { &mut *next_table })
        } else {
            None
        }
    }

    /// Get existing table at index (readonly)
    fn get_table_readonly(&self, table: &PageTable, index: usize) -> Option<&PageTable> {
        let entry = table.entry(index);
        if entry.is_valid() && entry.is_table() {
            let next_table = phys_to_virt(entry.addr()) as *const PageTable;
            Some(unsafe { &*next_table })
        } else {
            None
        }
    }
}

/// Flush entire TLB
pub fn flush_tlb() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}

/// Flush TLB for specific virtual address
pub fn flush_tlb_page(vaddr: usize) {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vae1is, {0}",
            "dsb ish",
            "isb",
            in(reg) vaddr >> 12,
            options(nostack, preserves_flags)
        );
    }
}

/// Set TTBR0_EL1 (user page table base)
///
/// # Safety
/// The base address must point to a valid page table.
pub unsafe fn set_ttbr0(base: usize) {
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {0}",
            "isb",
            in(reg) base,
            options(nostack, preserves_flags)
        );
    }
    flush_tlb();
}

/// Set TTBR1_EL1 (kernel page table base)
///
/// # Safety
/// The base address must point to a valid page table.
pub unsafe fn set_ttbr1(base: usize) {
    unsafe {
        core::arch::asm!(
            "msr ttbr1_el1, {0}",
            "isb",
            in(reg) base,
            options(nostack, preserves_flags)
        );
    }
    flush_tlb();
}

pub fn get_ttbr0() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!(
            "mrs {0}, ttbr0_el1",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

pub fn get_ttbr1() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!(
            "mrs {0}, ttbr1_el1",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// Configure MAIR_EL1
///
/// # Safety
///
/// This function is unsafe because it modifies the processor's memory
/// attribute configuration.
pub unsafe fn configure_mair() {
    unsafe {
        core::arch::asm!(
            "msr mair_el1, {0}",
            "isb",
            in(reg) mair::MAIR_VALUE,
            options(nostack, preserves_flags)
        );
    }
}

/// Configure TCR_EL1
///
/// # Safety
///
/// This function is unsafe because it modifies the processor's translation
/// control configuration.
pub unsafe fn configure_tcr() {
    let tcr: u64 = 16               // T0SZ = 16 (48-bit VA)
                 | (16 << 16)       // T1SZ = 16 (48-bit VA)
                 | (0b10 << 30)     // TG1 = 4KB
                 | (0b11 << 12)     // SH0 = Inner Shareable
                 | (0b11 << 28)     // SH1 = Inner Shareable
                 | (0b01 << 10)     // ORGN0 = Write-back
                 | (0b01 << 26)     // ORGN1 = Write-back
                 | (0b01 << 8)      // IRGN0 = Write-back
                 | (0b01 << 24)     // IRGN1 = Write-back
                 | (0b101 << 32); // IPS = 48-bit PA (256TB)

    unsafe {
        core::arch::asm!(
            "msr tcr_el1, {0}",
            "isb",
            in(reg) tcr,
            options(nostack, preserves_flags)
        );
    }
}

pub fn init() {
    log::info!("ARM64 paging initialized (4KB granule, 48-bit VA)");
}

/// Enable the MMU
///
/// # Safety
///
/// This function is unsafe because it enables address translation, which
/// will cause immediate page faults if the current execution flow is not
/// properly mapped.
pub unsafe fn enable_mmu() {
    let mut sctlr: u64;
    unsafe {
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= 0x1005; // M, C, I bits
        core::arch::asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr,
            options(nostack, preserves_flags)
        );
    }
}
