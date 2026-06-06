//! ARM64 Memory Management Initialization
//!
//! Sets up kernel page tables and enables the MMU.

use core::ptr;

use super::dtb;
use super::mem::{self, pte_flags};
use super::paging::{self, PageTable};
use super::phys::{self};

/// Kernel L0 page tables (statically allocated for bootstrap)
#[repr(C, align(4096))]
struct BootPageTables {
    l0_user: PageTable,   // For identity mapping (TTBR0)
    l0_kernel: PageTable, // For kernel mapping (TTBR1)
    l1_low: PageTable,    // For identity mapping (low addresses)
    l1_high: PageTable,   // For kernel mapping (high addresses)
}

static mut BOOT_TABLES: BootPageTables = BootPageTables {
    l0_user: PageTable::empty(),
    l0_kernel: PageTable::empty(),
    l1_low: PageTable::empty(),
    l1_high: PageTable::empty(),
};

#[inline(always)]
fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

/// Initialize ARM64 memory management
///
/// This function:
/// 1. Initializes the physical memory allocator (stage 1)
/// 2. Sets up kernel page tables with identity + higher-half mappings
/// 3. Configures MAIR and TCR
/// 4. Enables the MMU with new page tables
/// 5. Maps and initializes the kernel heap
pub fn init() {
    dbg_mark(0x41); // 'A'
    log::info!("Initializing ARM64 memory management...");
    dbg_mark(0x4a); // 'J'

    // Initialize physical memory allocator (stage 1 - bump allocator)
    phys::init_stage1();
    dbg_mark(0x42); // 'B'

    // Get memory info from DTB
    let dtb_info = dtb::info();
    let total_memory = dtb_info.total_memory;
    dbg_mark(0x43); // 'C'

    log::info!("Setting up kernel page tables...");
    dbg_mark(0x44); // 'D'

    // Set up initial page tables
    // SAFETY: We are in early boot, single-threaded, and have exclusive access to memory.
    // The total_memory value comes from the DTB which was validated earlier.
    unsafe {
        setup_kernel_page_tables(total_memory);
        dbg_mark(0x45); // 'E'

        // Configure MAIR (memory attributes)
        paging::configure_mair();
        dbg_mark(0x46); // 'F'

        // Configure TCR (translation control)
        paging::configure_tcr();
        dbg_mark(0x47); // 'G'

        // Set TTBR0 (user/identity mapping) and TTBR1 (kernel mapping)
        let l0_user_phys = &raw const BOOT_TABLES.l0_user as usize;
        let l0_kernel_phys = &raw const BOOT_TABLES.l0_kernel as usize;
        paging::set_ttbr0(l0_user_phys);
        paging::set_ttbr1(l0_kernel_phys);
        dbg_mark(0x48); // 'H'

        // Enable the MMU
        paging::enable_mmu();
        dbg_mark(0x49); // 'I'
    }

    log::info!("ARM64 memory management initialized");
}

/// Set up kernel page tables
///
/// Creates identity mapping for low memory and higher-half mapping for kernel.
///
/// # Safety
///
/// This function must be called only during early boot. It accesses the static
/// `BOOT_TABLES` which is mutable and not thread-safe. It assumes `total_memory`
/// correctly reflects the physical memory size available.
unsafe fn setup_kernel_page_tables(total_memory: usize) {
    #[allow(clippy::deref_addrof)]
    // SAFETY: We are in early boot (single core) and this is the only access to BOOT_TABLES.
    let boot_tables = &mut *(&raw mut BOOT_TABLES);

    // Clear all tables
    boot_tables.l0_user.zero();
    boot_tables.l0_kernel.zero();
    boot_tables.l1_low.zero();
    boot_tables.l1_high.zero();

    // Get physical addresses of tables
    let l1_low_phys = &raw const boot_tables.l1_low as usize;
    let l1_high_phys = &raw const boot_tables.l1_high as usize;

    // L0_user[0] -> L1_low (identity mapping for first 512GB)
    *boot_tables.l0_user.entry_mut(0) = paging::PageTableEntry::table(l1_low_phys);

    // L0_kernel[0] -> L1_low (also identity map in kernel table for convenience)
    // This allows the PageTableWalker to translate identity-mapped addresses
    // using the kernel page table root.
    *boot_tables.l0_kernel.entry_mut(0) = paging::PageTableEntry::table(l1_low_phys);

    // L0_kernel[256] -> L1_high (kernel higher-half mapping, 0xFFFF_8000_0000_0000+)
    // Index 256 covers 0xFFFF_8000_0000_0000 - 0xFFFF_807F_FFFF_FFFF
    *boot_tables.l0_kernel.entry_mut(256) = paging::PageTableEntry::table(l1_high_phys);

    // Set up identity mapping using 1GB blocks for simplicity
    // Map first N GB where N depends on total memory
    let gb_to_map = ((total_memory + (1 << 30) - 1) >> 30).max(4); // At least 4GB

    for i in 0..gb_to_map.min(512) {
        let phys_addr = i << 30; // 1GB per entry

        // L1 block descriptor for 1GB mapping
        #[allow(unused_mut)]
        let mut block_flags = pte_flags::VALID | pte_flags::AF | pte_flags::SH_INNER;

        // QEMU virt memory map:
        // 0x0000_0000 - 0x3FFF_FFFF: Devices
        // 0x4000_0000 - ...        : RAM (kernel at 0x4008_0000)
        //
        // Raspberry Pi 5 boots kernel at 0x0008_0000, so mapping the entire first 1GB
        // as Device/XN would fault immediately after MMU enable.
        #[cfg(feature = "virt")]
        if i == 0 {
            block_flags |= pte_flags::attr_index(mem::mair::DEVICE_NGNRE);
            block_flags |= pte_flags::UXN | pte_flags::PXN;
        } else {
            block_flags |= pte_flags::attr_index(mem::mair::NORMAL_WB);
        }
        #[cfg(feature = "rpi5")]
        {
            block_flags |= pte_flags::attr_index(mem::mair::NORMAL_WB);
        }

        *boot_tables.l1_low.entry_mut(i) = paging::PageTableEntry::block(phys_addr, block_flags);

        // Also map in higher-half (same physical memory)
        if i < 512 {
            *boot_tables.l1_high.entry_mut(i) =
                paging::PageTableEntry::block(phys_addr, block_flags);
        }
    }

    #[cfg(feature = "rpi5")]
    {
        use crate::arch::aarch64::platform::rpi5::memory_map::{
            BCM2712_UART10_BASE_PHYS, GICC_BASE_PHYS, GICD_BASE_PHYS, RP1_PERIPHERAL_BASE_PHYS,
        };

        // Keep Pi 5 high MMIO apertures accessible after MMU-on.
        let mmio_flags = pte_flags::VALID
            | pte_flags::AF
            | pte_flags::SH_INNER
            | pte_flags::UXN
            | pte_flags::PXN
            | pte_flags::attr_index(mem::mair::DEVICE_NGNRE);

        for &phys_base in &[
            BCM2712_UART10_BASE_PHYS,
            GICD_BASE_PHYS,
            GICC_BASE_PHYS,
            RP1_PERIPHERAL_BASE_PHYS,
        ] {
            let l1_idx = phys_base >> 30; // 1GB block index
            if l1_idx < 512 {
                let phys_addr = l1_idx << 30;
                // Map in identity region
                *boot_tables.l1_low.entry_mut(l1_idx) =
                    paging::PageTableEntry::block(phys_addr, mmio_flags);

                // Map in higher-half region ONLY if it doesn't conflict with kernel RAM (index 0)
                // Pi 5 RAM starts at 0x0, so kernel is in index 0.
                if l1_idx > 0 {
                    *boot_tables.l1_high.entry_mut(l1_idx) =
                        paging::PageTableEntry::block(phys_addr, mmio_flags);
                }
            }
        }
    }

    log::info!("Bootstrap page tables configured, mapped {}GB", gb_to_map);
}

/// Get the kernel page table root physical address
pub fn kernel_page_table_phys() -> usize {
    // SAFETY: Accessing the address of the static BOOT_TABLES.l0_kernel.
    unsafe { &raw const BOOT_TABLES.l0_kernel as usize }
}

/// Create a new user address space
///
/// Allocates a new L0 table and copies kernel mappings into it.
/// Returns the physical address of the new L0 table.
pub fn create_user_address_space() -> Option<usize> {
    // Allocate a new L0 table
    let frame = phys::allocate_frame::<crate::arch::types::Size4KiB>()?;
    let l0_phys = frame.addr() as usize;
    let l0_ptr = mem::phys_to_virt(l0_phys) as *mut PageTable;

    // SAFETY: We allocated a fresh frame, so writing to it is safe.
    unsafe {
        // Zero the table
        ptr::write_bytes(l0_ptr, 0, 1);

        // We need to map the kernel (which runs in low memory 0x40080000+)
        // and devices (UART, GIC, VirtIO) into the user's TTBR0.
        // BUT we cannot simply copy the 1GB identity block (Index 0) from l1_low
        // because that would prevent userspace from mapping anything in 0-1GB (like init at 0x200000).

        // 1. Allocate a new L1 table for the first 512GB (L0 index 0)
        let l1_frame = phys::allocate_frame::<crate::arch::types::Size4KiB>()?;
        let l1_phys = l1_frame.addr() as usize;
        let l1_ptr = mem::phys_to_virt(l1_phys) as *mut PageTable;
        ptr::write_bytes(l1_ptr, 0, 1);

        // Link L1 to L0
        (*l0_ptr)
            .entry_mut(0)
            .set(paging::PageTableEntry::table(l1_phys).raw());

        // 2. Copy the Kernel RAM mapping (Index 1 of L1: 1GB-2GB)
        // This covers 0x40000000 - 0x7FFFFFFF, where the kernel code/data resides.
        #[allow(clippy::deref_addrof)]
        let boot_tables = &mut *(&raw mut BOOT_TABLES);
        let kernel_entry = *boot_tables.l1_low.entry(1);
        *(*l1_ptr).entry_mut(1) = kernel_entry;

        log::info!(
            "create_user_address_space: L0={:#x}, L1={:#x}, KernelEntry[1]={:#x}",
            l0_phys,
            l1_phys,
            kernel_entry.raw()
        );

        // 3. Map necessary devices in the first 1GB (Index 0 of L1)
        // We use PageTableWalker to map specific ranges instead of a 1GB block.
        let mut walker = paging::PageTableWalker::new(l0_ptr);
        let device_flags = paging::PageTableFlags::PRESENT
            | paging::PageTableFlags::WRITABLE
            | paging::PageTableFlags::MMIO_DEVICE
            | paging::PageTableFlags::NO_EXECUTE; // Devices shouldn't be executable

        // Keep a larger EL1-only bootstrap identity window so low-address kernel code can
        // safely execute the TTBR0 switch + ERET path on Pi5. The kernel is ~11MB.
        //
        // Important: keep this below user app load addresses (user apps start at 0x1_0000_0000 on Pi5).
        let kernel_bootstrap_flags =
            paging::PageTableFlags::PRESENT | paging::PageTableFlags::WRITABLE;
        let _ = walker.map_range(
            0x0000_0000,
            0x0000_0000,
            0x0200_0000, // Map 32MB to cover the entire kernel
            kernel_bootstrap_flags.to_pte_bits(),
        );

        // UART (PL011) at 0x0900_0000
        walker
            .map_page(0x0900_0000, 0x0900_0000, device_flags.to_pte_bits())
            .ok()?;

        // Pi 5 debug connector UART10 (BCM2712 PL011) used by serial/log paths.
        // This MMIO must remain visible while TTBR0 is switched for process-AS operations.
        #[cfg(feature = "rpi5")]
        {
            use crate::arch::aarch64::platform::rpi5::memory_map::BCM2712_UART10_BASE_PHYS;
            walker
                .map_page(
                    BCM2712_UART10_BASE_PHYS,
                    BCM2712_UART10_BASE_PHYS,
                    device_flags.to_pte_bits(),
                )
                .ok()?;
        }

        #[cfg(feature = "rpi5")]
        {
            use crate::arch::aarch64::platform::rpi5::memory_map::{
                GICC_BASE_PHYS, GICD_BASE_PHYS, RP1_PERIPHERAL_BASE_PHYS,
            };

            // Keep the Pi 5 GIC distributor + CPU interface visible while TTBR0 is active.
            // These apertures overlap (GICC is 0x1000 above GICD), so we map them as one contiguous range.
            let gic_start = GICD_BASE_PHYS;
            let gic_end = GICC_BASE_PHYS + 0x20000;
            let gic_size = gic_end - gic_start;
            walker
                .map_range(gic_start, gic_start, gic_size, device_flags.to_pte_bits())
                .ok()?;

            // Map RP1 peripheral range using an efficient 1GB block mapping.
            // This replaces the previous 4KiB page-by-page mapping of the full range.
            walker
                .map_l1_block(
                    RP1_PERIPHERAL_BASE_PHYS,
                    RP1_PERIPHERAL_BASE_PHYS,
                    device_flags.to_pte_bits(),
                )
                .ok()?;
        }

        #[cfg(all(feature = "virt", not(feature = "rpi5")))]
        walker
            .map_range(
                0x0800_0000,
                0x0800_0000,
                0x20000,
                device_flags.to_pte_bits(),
            )
            .ok()?;

        // VirtIO MMIO at 0x0a00_0000 (32 devices * 512 bytes = 16KB)
        walker
            .map_range(0x0a00_0000, 0x0a00_0000, 0x4000, device_flags.to_pte_bits())
            .ok()?;

        // Note: We leave the rest of 0-1GB unmapped so userspace can use it.
    }

    Some(l0_phys)
}

/// Initialize stage 2 of memory management (after heap is available)
pub fn init_stage2() {
    phys::init_stage2();
    log::info!("ARM64 memory management stage 2 initialized");
}
