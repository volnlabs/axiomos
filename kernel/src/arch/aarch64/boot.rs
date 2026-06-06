/// Boot information passed from bootloader
pub struct BootInfo {
    pub dtb_addr: usize,
}

static mut BOOT_INFO: BootInfo = BootInfo { dtb_addr: 0 };

#[inline(always)]
fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

/// Initialize boot information
///
/// # Safety
/// The caller must ensure that `dtb_addr` is a valid physical address.
pub unsafe fn init_boot_info(dtb_addr: usize) {
    // SAFETY: We are writing to the static BOOT_INFO. This is safe because:
    // 1. We are in early boot (single core)
    // 2. interrupts are disabled
    // 3. This function is only called once from _start
    unsafe {
        BOOT_INFO.dtb_addr = dtb_addr;
    }
}

/// Get boot information
#[allow(clippy::deref_addrof)]
pub fn boot_info() -> &'static BootInfo {
    // SAFETY: BOOT_INFO is initialized in _start before any other code runs.
    // It is effectively read-only after initialization.
    unsafe { &*(&raw const BOOT_INFO) }
}

/// Early boot initialization (called from assembly)
///
/// # Safety
/// This function is the kernel entry point and expects to be called with MMU disabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(dtb_addr: usize) -> ! {
    dbg_mark(0x7e); // '~'

    // DEBUG: Early print to verify execution on QEMU virt
    #[cfg(feature = "virt")]
    {
        // Write 'A' to PL011 UART DR at 0x09000000
        (0x0900_0000 as *mut u32).write_volatile(0x41);
    }

    // Initialize boot info
    // SAFETY: This is the first thing we do. dtb_addr is passed in x0 from the bootloader.
    unsafe {
        init_boot_info(dtb_addr);
    }
    dbg_mark(0x31); // '1'

    // BSS is already cleared by assembly, but we define the symbols
    // for reference
    // SAFETY: These symbols are defined in the linker script and represent valid memory ranges.
    unsafe extern "C" {
        static __bss_start: u8;
        static __bss_end: u8;
    }

    // Initialize platform-specific hardware (UART, etc.)
    dbg_mark(0x32); // '2'
    #[cfg(feature = "rpi5")]
    super::platform::rpi5::init();
    #[cfg(feature = "virt")]
    super::platform::virt::init();
    dbg_mark(0x33); // '3'

    // Parse device tree to get memory information
    dbg_mark(0x34); // '4'
                    // SAFETY: dtb_addr is guaranteed to be a valid physical address by the bootloader protocol.
    if let Err(e) = unsafe { super::dtb::parse(dtb_addr) } {
        dbg_mark(0x45); // 'E'
                        // Log error but continue - we can fall back to hardcoded values
        log::warn!("Failed to parse DTB: {}", e);
    }
    dbg_mark(0x35); // '5'

    // Jump to kernel main
    // SAFETY: kernel_main is defined in the kernel crate and has the correct signature.
    unsafe extern "C" {
        fn kernel_main() -> !;
    }

    // SAFETY: We have initialized the minimal environment required for the kernel main.
    // This function never returns.
    dbg_mark(0x36); // '6'
    unsafe { kernel_main() }
}
