use log::info;

#[cfg(target_arch = "x86_64")]
use crate::limine::{HHDM_REQUEST, MEMORY_MAP_REQUEST};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::mem::address_space::AddressSpace;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::mem::heap::Heap;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod address_space;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod heap;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod memapi;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod phys;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod virt;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

/// Convert a physical address to a virtual address using the Higher Half Direct Map (HHDM).
///
/// # Panics
///
/// Panics if the HHDM request failed (x86_64) or if the architecture is not supported.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn phys_to_virt(phys: usize) -> usize {
    let offset = HHDM_REQUEST
        .get_response()
        .expect("HHDM request failed")
        .offset();
    phys.wrapping_add(offset as usize)
}

/// Convert a physical address to a virtual address using the Higher Half Direct Map (HHDM).
#[cfg(target_arch = "aarch64")]
#[must_use]
pub fn phys_to_virt(phys: usize) -> usize {
    crate::arch::aarch64::mem::phys_to_virt(phys)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[must_use]
pub fn phys_to_virt(phys: usize) -> usize {
    // Fallback for other architectures (e.g. RISC-V) if/when implemented
    // For now, identity mapping or panic
    phys
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_panics_doc)]
pub fn init() {
    let response = MEMORY_MAP_REQUEST
        .get_response()
        .expect("should have a memory map response");

    let usable_physical_memory = phys::init_stage1(response.entries());

    address_space::init();

    let address_space = AddressSpace::kernel();

    heap::init(address_space, usable_physical_memory);

    virt::init();

    phys::init_stage2();

    heap::init_stage2();

    info!("memory initialized, {Heap:x?}");
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::missing_panics_doc)]
pub fn init() {
    use crate::arch::aarch64::{mm, phys};

    dbg_mark(0x72); // 'r'
    info!("Starting memory initialization...");
    dbg_mark(0x52); // 'R'
    mm::init();
    dbg_mark(0x73); // 's'

    // Stage 1 phys alloc already initialized in mm::init()
    let usable_physical_memory = phys::total_memory();
    info!(
        "Usable physical memory: {} MB",
        usable_physical_memory / 1024 / 1024
    );

    address_space::init();
    dbg_mark(0x74); // 't'
    info!("Address space initialized");

    let address_space = AddressSpace::kernel();

    heap::init(address_space, usable_physical_memory);
    dbg_mark(0x75); // 'u'
    info!("Heap initialized");

    virt::init();
    dbg_mark(0x76); // 'v'
    info!("Virtual memory initialized");

    info!("memory initialized via arch::mm::init");
    info!("heap info: {Heap:x?}");

    // Initialize stage 2 physical allocator (requires heap)
    phys::init_stage2();
    dbg_mark(0x77); // 'w'
    info!("Physical memory stage 2 initialized");

    // We need to call heap::init_stage2 if we want dynamic resizing.
    heap::init_stage2();
    dbg_mark(0x78); // 'x'
    info!("Heap stage 2 initialized");
}
