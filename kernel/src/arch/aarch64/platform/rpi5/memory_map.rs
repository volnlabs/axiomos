//! Raspberry Pi 5 Memory Map
//!
//! The Pi 5 has a complex memory layout with the RP1 southbridge
//! providing I/O peripherals through a PCIe connection.
//!
//! With firmware shortcuts enabled (pciex4_reset=0, enable_rp1_uart=1),
//! the RP1 peripherals are pre-mapped to the CPU's physical address space.

use crate::arch::aarch64::mem::phys_to_virt;

/// RP1 peripheral base address (PCIe BAR1 window)
pub const RP1_PERIPHERAL_BASE_PHYS: usize = 0x1F_0000_0000;
pub const RP1_PERIPHERAL_BASE: usize = phys_to_virt(RP1_PERIPHERAL_BASE_PHYS);

/// BCM2712 primary/debug UART (PL011, uart10)
pub const BCM2712_UART10_BASE_PHYS: usize = 0x10_7D00_1000;
pub const BCM2712_UART10_BASE: usize = phys_to_virt(BCM2712_UART10_BASE_PHYS);

/// RP1 internal offset for UART0
pub const RP1_UART0_OFFSET: usize = 0x0003_0000;

/// RP1 internal offset for UART1
pub const RP1_UART1_OFFSET: usize = 0x0003_4000;

/// RP1 internal offset for GPIO
pub const RP1_GPIO_OFFSET: usize = 0x000D_0000;

/// RP1 internal offset for I2C0
pub const RP1_I2C0_OFFSET: usize = 0x0007_0000;

/// RP1 internal offset for SPI0
pub const RP1_SPI0_OFFSET: usize = 0x0005_0000;

/// RP1 internal offset for PWM0
pub const RP1_PWM0_OFFSET: usize = 0x0009_8000;

/// RP1 internal offset for PWM1
pub const RP1_PWM1_OFFSET: usize = 0x0009_C000;

/// Calculate CPU virtual address for an RP1 peripheral
#[inline]
pub const fn rp1_peripheral_addr(offset: usize) -> usize {
    RP1_PERIPHERAL_BASE.wrapping_add(offset)
}

/// UART0 base address (PL011-compatible)
pub const RP1_UART0_BASE: usize = rp1_peripheral_addr(RP1_UART0_OFFSET);

/// UART1 base address
pub const RP1_UART1_BASE: usize = rp1_peripheral_addr(RP1_UART1_OFFSET);

/// GPIO base address
pub const RP1_GPIO_BASE: usize = rp1_peripheral_addr(RP1_GPIO_OFFSET);

/// PWM0 base address
pub const RP1_PWM0_BASE: usize = rp1_peripheral_addr(RP1_PWM0_OFFSET);

/// PWM1 base address
pub const RP1_PWM1_BASE: usize = rp1_peripheral_addr(RP1_PWM1_OFFSET);

/// ARM GIC-400 distributor base address
pub const GICD_BASE_PHYS: usize = 0x10_7FFF_9000;
pub const GICD_BASE: usize = phys_to_virt(GICD_BASE_PHYS);

/// ARM GIC-400 CPU interface base address
pub const GICC_BASE_PHYS: usize = 0x10_7FFF_A000;
pub const GICC_BASE: usize = phys_to_virt(GICC_BASE_PHYS);

/// Physical memory (DRAM) start
pub const DRAM_BASE: usize = 0x0;

/// Kernel load address (where Pi firmware loads kernel8.img)
pub const KERNEL_LOAD_ADDR: usize = 0x8_0000;
