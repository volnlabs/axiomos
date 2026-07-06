//! ARM Generic Interrupt Controller (GICv2) Driver
//!
//! The GIC is the standard interrupt controller for ARM Cortex-A processors.
//! It consists of two main components:
//! - Distributor (GICD): Manages interrupt sources and routing
//! - CPU Interface (GICC): Per-CPU interrupt handling
//!
//! The Raspberry Pi 5 uses a GIC (likely GICv2) for interrupt management.

#[cfg(feature = "rpi5")]
use super::platform::rpi5::memory_map as platform_map;
#[cfg(all(feature = "virt", not(feature = "rpi5")))]
use super::platform::virt::mmio as platform_map;

#[cfg(not(any(feature = "rpi5", feature = "virt")))]
#[allow(dead_code)]
mod platform_map {
    pub const GICC_BASE: usize = 0;
    pub const GICD_BASE: usize = 0;
}

/// GIC Distributor register offsets
#[allow(dead_code)]
mod gicd {
    /// Distributor Control Register
    pub const CTLR: usize = 0x000;
    /// Interrupt Controller Type Register
    pub const TYPER: usize = 0x004;
    /// Distributor Implementer Identification Register
    #[allow(dead_code)]
    pub const IIDR: usize = 0x008;
    /// Interrupt Group Registers (0 = Group 0, 1 = Group 1)
    pub const IGROUPR: usize = 0x080;
    /// Interrupt Set-Enable Registers (32 bits each, 1 bit per IRQ)
    pub const ISENABLER: usize = 0x100;
    /// Interrupt Clear-Enable Registers
    pub const ICENABLER: usize = 0x180;
    /// Interrupt Set-Pending Registers
    #[allow(dead_code)]
    pub const ISPENDR: usize = 0x200;
    /// Interrupt Clear-Pending Registers
    pub const ICPENDR: usize = 0x280;
    /// Interrupt Priority Registers (8 bits per IRQ)
    pub const IPRIORITYR: usize = 0x400;
    /// Interrupt Processor Targets Registers (8 bits per IRQ)
    pub const ITARGETSR: usize = 0x800;
    /// Interrupt Configuration Registers (2 bits per IRQ)
    pub const ICFGR: usize = 0xC00;
}

/// GIC CPU Interface register offsets
#[allow(dead_code)]
mod gicc {
    /// CPU Interface Control Register
    pub const CTLR: usize = 0x000;
    /// Interrupt Priority Mask Register
    pub const PMR: usize = 0x004;
    /// Binary Point Register
    #[allow(dead_code)]
    pub const BPR: usize = 0x008;
    /// Interrupt Acknowledge Register
    pub const IAR: usize = 0x00C;
    /// End of Interrupt Register
    pub const EOIR: usize = 0x010;
    /// Running Priority Register
    #[allow(dead_code)]
    pub const RPR: usize = 0x014;
    /// Highest Priority Pending Interrupt Register
    #[allow(dead_code)]
    pub const HPPIR: usize = 0x018;
}

/// Special IRQ numbers
pub mod irq {
    /// Physical timer IRQ (PPI, ID 30)
    pub const TIMER_PHYS: u32 = 30;
    /// Virtual timer IRQ (PPI, ID 27)
    pub const TIMER_VIRT: u32 = 27;
    /// Spurious interrupt (no pending interrupt)
    pub const SPURIOUS: u32 = 1023;
}

/// GICD base address (set at runtime for flexibility)
#[cfg(any(feature = "rpi5", feature = "virt"))]
static GICD: usize = platform_map::GICD_BASE;

/// GICC base address
#[cfg(any(feature = "rpi5", feature = "virt"))]
static GICC: usize = platform_map::GICC_BASE;

/// Initialize the GIC
///
/// This configures both the Distributor and CPU Interface.
#[cfg(any(feature = "rpi5", feature = "virt"))]
pub fn init() {
    // SAFETY: All register accesses are to valid GIC MMIO addresses defined by the
    // platform memory map. The GIC is being initialized before any interrupts are
    // enabled, so there are no race conditions. The kernel has exclusive access to
    // the GIC hardware.
    unsafe {
        // Disable distributor while configuring
        write_gicd(gicd::CTLR, 0);

        // Read how many IRQ lines are supported
        let typer = read_gicd(gicd::TYPER);
        let num_irqs = ((typer & 0x1F) + 1) * 32;
        log::debug!("GIC supports {} IRQs", num_irqs);

        // Disable all interrupts
        let num_regs = num_irqs.div_ceil(32);
        for i in 0..num_regs {
            write_gicd(gicd::ICENABLER + i as usize * 4, 0xFFFF_FFFF);
        }

        // Route all interrupts to Group 1 (non-secure). On BCM2712/EL1-NS we
        // must handle Group 1 IRQs; leaving defaults can keep PPIs undispatched.
        // rpi5-only: on QEMU virt (no security extensions) Group 1 interrupts
        // cannot be acked through the plain IAR (AckCtl=0), so every IAR read
        // returns spurious 1022 and the pending IRQ storms the core. virt keeps
        // the reset default (Group 0), which is delivered as IRQ with FIQEn=0.
        #[cfg(feature = "rpi5")]
        for i in 0..num_regs {
            write_gicd(gicd::IGROUPR + i as usize * 4, 0xFFFF_FFFF);
        }

        // Clear all pending interrupts
        for i in 0..num_regs {
            write_gicd(gicd::ICPENDR + i as usize * 4, 0xFFFF_FFFF);
        }

        // Set all interrupts to lowest priority (0xFF)
        let num_priority_regs = num_irqs.div_ceil(4);
        for i in 0..num_priority_regs {
            write_gicd(gicd::IPRIORITYR + i as usize * 4, 0xFFFF_FFFF);
        }

        // Route all SPIs to CPU 0
        let num_target_regs = num_irqs.div_ceil(4);
        for i in 8..num_target_regs {
            // Skip first 8 (SGIs/PPIs are per-CPU)
            write_gicd(gicd::ITARGETSR + i as usize * 4, 0x0101_0101);
        }

        // Configure all interrupts as level-triggered
        let num_cfg_regs = num_irqs.div_ceil(16);
        for i in 0..num_cfg_regs {
            write_gicd(gicd::ICFGR + i as usize * 4, 0);
        }

        // Enable distributor for both Group 0 and Group 1 interrupts.
        write_gicd(gicd::CTLR, 0b11);

        // Configure CPU interface
        // Set priority mask to accept all priorities
        write_gicc(gicc::PMR, 0xFF);

        // Enable CPU interface for both Group 0 and Group 1 interrupts.
        write_gicc(gicc::CTLR, 0b11);
    }

    log::info!("GICv2 initialized");
}

/// Placeholder for non-supported builds
#[cfg(not(any(feature = "rpi5", feature = "virt")))]
pub fn init() {
    log::warn!("GIC not initialized (no platform selected)");
}

/// Enable a specific interrupt
#[cfg(any(feature = "rpi5", feature = "virt"))]
pub fn enable_irq(irq: u32) {
    let reg_index = (irq / 32) as usize;
    let bit = 1u32 << (irq % 32);

    // SAFETY: Writing to ISENABLER is safe - it's a set-enable register where
    // writing 1 enables the interrupt and writing 0 has no effect. The register
    // address is computed from platform constants and validated offsets.
    unsafe {
        write_gicd(gicd::ISENABLER + reg_index * 4, bit);
    }

    log::debug!("Enabled IRQ {}", irq);
}

#[cfg(not(any(feature = "rpi5", feature = "virt")))]
pub fn enable_irq(_irq: u32) {}

/// Disable a specific interrupt
#[cfg(any(feature = "rpi5", feature = "virt"))]
pub fn disable_irq(irq: u32) {
    let reg_index = (irq / 32) as usize;
    let bit = 1u32 << (irq % 32);

    // SAFETY: Writing to ICENABLER is safe - it's a clear-enable register where
    // writing 1 disables the interrupt and writing 0 has no effect. The register
    // address is computed from platform constants and validated offsets.
    unsafe {
        write_gicd(gicd::ICENABLER + reg_index * 4, bit);
    }
}

#[cfg(not(any(feature = "rpi5", feature = "virt")))]
pub fn disable_irq(_irq: u32) {}

/// Acknowledge an interrupt (read IAR)
///
/// Returns the raw IAR value. Use [`irq_id_from_iar`] to extract the 10-bit
/// interrupt ID for dispatch decisions.
#[cfg(any(feature = "rpi5", feature = "virt"))]
pub fn acknowledge() -> u32 {
    // SAFETY: Reading IAR is the standard way to acknowledge an interrupt.
    // This atomically returns the highest priority pending interrupt ID and
    // marks it as active. The GICC base address is a platform constant.
    unsafe { read_gicc(gicc::IAR) }
}

#[cfg(not(any(feature = "rpi5", feature = "virt")))]
pub fn acknowledge() -> u32 {
    irq::SPURIOUS
}

/// Extract the interrupt ID from a raw IAR value.
///
/// In GICv2, IAR bits [9:0] contain the interrupt ID and upper bits may carry
/// CPU/source metadata. Dispatch logic should compare against this masked ID.
#[inline]
pub const fn irq_id_from_iar(iar: u32) -> u32 {
    iar & 0x3FF
}

/// Signal end of interrupt handling
#[cfg(any(feature = "rpi5", feature = "virt"))]
pub fn end_of_interrupt(irq: u32) {
    // SAFETY: Writing to EOIR signals completion of interrupt handling.
    // The irq value must be the same as returned by acknowledge().
    // The GICC base address is a platform constant.
    unsafe {
        write_gicc(gicc::EOIR, irq);
    }
}

#[cfg(not(any(feature = "rpi5", feature = "virt")))]
pub fn end_of_interrupt(_irq: u32) {}

/// Set interrupt priority (0 = highest, 255 = lowest)
#[cfg(any(feature = "rpi5", feature = "virt"))]
pub fn set_priority(irq: u32, priority: u8) {
    let reg_index = (irq / 4) as usize;
    let byte_offset = (irq % 4) as usize;

    // SAFETY: Reading and writing IPRIORITYR is safe. Each IRQ has an 8-bit
    // priority field, and we use read-modify-write to update only the relevant
    // byte. The register address is computed from platform constants.
    unsafe {
        let mut val = read_gicd(gicd::IPRIORITYR + reg_index * 4);
        val &= !(0xFF << (byte_offset * 8));
        val |= (priority as u32) << (byte_offset * 8);
        write_gicd(gicd::IPRIORITYR + reg_index * 4, val);
    }
}

#[cfg(not(any(feature = "rpi5", feature = "virt")))]
pub fn set_priority(_irq: u32, _priority: u8) {}

// Low-level register access
//
// SAFETY for all GIC register access functions:
// These functions perform MMIO access to GIC registers. They are safe because:
// 1. The GIC base addresses (GICD_BASE, GICC_BASE) are platform-specific constants
//    that are correct for the RPi5/virt platform when feature is enabled
// 2. The offsets used are defined by the ARM GICv2 specification
// 3. The kernel has exclusive access to these hardware registers
// 4. read_volatile/write_volatile ensure proper memory ordering for MMIO

#[cfg(any(feature = "rpi5", feature = "virt"))]
/// Read from GIC Distributor register
///
/// # Safety
///
/// Caller must ensure `offset` is a valid register offset within the GIC Distributor
/// memory map. The GICD base address is assumed valid for the platform.
unsafe fn read_gicd(offset: usize) -> u32 {
    // SAFETY: The caller ensures the offset is valid. Accessing GICD memory is safe
    // as it's a dedicated MMIO region.
    unsafe { core::ptr::read_volatile((GICD + offset) as *const u32) }
}

#[cfg(any(feature = "rpi5", feature = "virt"))]
/// Write to GIC Distributor register
///
/// # Safety
///
/// Caller must ensure `offset` is a valid register offset within the GIC Distributor
/// memory map. The GICD base address is assumed valid for the platform.
unsafe fn write_gicd(offset: usize, value: u32) {
    // SAFETY: The caller ensures the offset is valid. Accessing GICD memory is safe
    // as it's a dedicated MMIO region.
    unsafe {
        core::ptr::write_volatile((GICD + offset) as *mut u32, value);
    }
}

#[cfg(any(feature = "rpi5", feature = "virt"))]
/// Read from GIC CPU Interface register
///
/// # Safety
///
/// Caller must ensure `offset` is a valid register offset within the GIC CPU Interface
/// memory map. The GICC base address is assumed valid for the platform.
unsafe fn read_gicc(offset: usize) -> u32 {
    // SAFETY: The caller ensures the offset is valid. Accessing GICC memory is safe
    // as it's a dedicated MMIO region.
    unsafe { core::ptr::read_volatile((GICC + offset) as *const u32) }
}

#[cfg(any(feature = "rpi5", feature = "virt"))]
/// Write to GIC CPU Interface register
///
/// # Safety
///
/// Caller must ensure `offset` is a valid register offset within the GIC CPU Interface
/// memory map. The GICC base address is assumed valid for the platform.
unsafe fn write_gicc(offset: usize, value: u32) {
    // SAFETY: The caller ensures the offset is valid. Accessing GICC memory is safe
    // as it's a dedicated MMIO region.
    unsafe {
        core::ptr::write_volatile((GICC + offset) as *mut u32, value);
    }
}
