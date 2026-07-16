//! Device Tree Blob (DTB) parsing for ARM64
//!
//! Parses the device tree passed by the bootloader to extract hardware information,
//! particularly memory regions.

use fdt::Fdt;
use thiserror::Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum DtbParseError {
    #[error("DTB address is null")]
    NullAddress,
    #[error("invalid DTB magic number")]
    InvalidMagic,
    #[error("failed to parse DTB")]
    InvalidBlob,
}

/// Memory region extracted from DTB
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
}

/// Parsed device tree information
pub struct DeviceTreeInfo {
    pub memory_regions: [Option<MemoryRegion>; 8],
    pub memory_region_count: usize,
    pub total_memory: usize,
    pub dtb_start: usize,
    pub dtb_size: usize,
}

impl DeviceTreeInfo {
    /// Create empty device tree info
    pub const fn empty() -> Self {
        Self {
            memory_regions: [None; 8],
            memory_region_count: 0,
            total_memory: 0,
            dtb_start: 0,
            dtb_size: 0,
        }
    }

    /// Iterate over memory regions
    pub fn memory_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.memory_regions[..self.memory_region_count]
            .iter()
            .filter_map(|r| r.as_ref())
    }
}

static mut DTB_INFO: DeviceTreeInfo = DeviceTreeInfo::empty();

/// Parse the device tree blob at the given address
///
/// # Safety
/// The dtb_addr must point to a valid device tree blob in memory
pub unsafe fn parse(dtb_addr: usize) -> Result<(), DtbParseError> {
    let res = unsafe { parse_internal(dtb_addr) };
    if res.is_err() {
        log::warn!(
            "DTB parsing failed: {:?}. Using fallback for 'virt' machine.",
            res.err()
        );
        unsafe {
            DTB_INFO.memory_regions[0] = Some(MemoryRegion {
                base: 0x4000_0000,
                size: 0x4000_0000, // 1GB
            });
            DTB_INFO.memory_region_count = 1;
            DTB_INFO.total_memory = 0x4000_0000;
            DTB_INFO.dtb_start = dtb_addr;
            DTB_INFO.dtb_size = 0x10000; // Assume 64KB if parsing failed
        }
    }
    res
}

unsafe fn parse_internal(dtb_addr: usize) -> Result<(), DtbParseError> {
    // SAFETY: We are accessing raw memory at dtb_addr. The caller guarantees this is valid.
    // We also modify the static DTB_INFO, which is safe because we are single-threaded
    // during early boot.
    unsafe {
        if dtb_addr == 0 {
            return Err(DtbParseError::NullAddress);
        }

        // Create a slice from the DTB address - we don't know the size yet,
        // but the fdt crate will validate the header
        let dtb_ptr = dtb_addr as *const u8;

        // Read the magic number first to validate
        let magic = core::ptr::read_volatile(dtb_ptr as *const u32);
        if magic.to_be() != 0xd00dfeed {
            return Err(DtbParseError::InvalidMagic);
        }

        // Read the total size from the header
        let total_size = core::ptr::read_volatile(dtb_ptr.add(4) as *const u32).to_be() as usize;

        // Create the slice
        let dtb_slice = core::slice::from_raw_parts(dtb_ptr, total_size);

        // Parse the FDT
        let fdt = Fdt::new(dtb_slice).map_err(|_| DtbParseError::InvalidBlob)?;

        // Extract memory regions
        let mut region_count = 0;
        let mut total_memory = 0usize;

        let memory = fdt.memory();
        for region in memory.regions() {
            if region_count < 8 {
                let base = region.starting_address as usize;
                let size = region.size.unwrap_or(0);

                if size > 0 {
                    DTB_INFO.memory_regions[region_count] = Some(MemoryRegion { base, size });
                    total_memory = total_memory.saturating_add(size);
                    region_count += 1;

                    log::info!(
                        "DTB: memory region {}: {:#x} - {:#x} ({} MB)",
                        region_count,
                        base,
                        base + size,
                        size / (1024 * 1024)
                    );
                }
            }
        }

        DTB_INFO.memory_region_count = region_count;
        DTB_INFO.total_memory = total_memory;
        DTB_INFO.dtb_start = dtb_addr;
        DTB_INFO.dtb_size = total_size;

        log::info!(
            "DTB: parsed {} memory regions, total {} MB, DTB at {:#x} ({} bytes)",
            region_count,
            total_memory / (1024 * 1024),
            dtb_addr,
            total_size
        );

        Ok(())
    }
}

/// Get the parsed device tree information
#[allow(clippy::deref_addrof)]
pub fn info() -> &'static DeviceTreeInfo {
    // SAFETY: DTB_INFO is initialized in parse() during early boot and is effectively
    // read-only afterwards.
    unsafe { &*(&raw const DTB_INFO) }
}

/// Get the total memory available
pub fn total_memory() -> usize {
    // SAFETY: Reading initialized static global.
    unsafe { DTB_INFO.total_memory }
}
