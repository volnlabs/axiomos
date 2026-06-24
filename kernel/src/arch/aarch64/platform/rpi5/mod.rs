//! Raspberry Pi 5 platform support
//!
//! The Pi 5 uses the BCM2712 SoC with the RP1 southbridge chip connected via PCIe.
//! When using firmware shortcuts (pciex4_reset=0, enable_rp1_uart=1),
//! RP1 peripherals are pre-mapped at fixed addresses in the CPU's physical
//! address space.
//!
//! Key addresses:
//! - RP1 peripheral base: 0x1F_0000_0000
//! - Debug UART (UART10): 0x10_7D00_1000
//! - RP1 GPIO: 0x1F_000D_0000

pub mod gpio;
pub mod memory_map;
pub mod mmio;
pub mod pl011;
pub mod pwm;
pub mod uart;

use conquer_once::spin::Lazy;
use pwm::Rp1Pwm;
use spin::Mutex;
use uart::Rp1Uart;

/// Global UART instance for debug output
pub static UART: Lazy<Mutex<Rp1Uart>> = Lazy::new(|| {
    // SAFETY: We initialize the UART driver for the RPi5 platform.
    // This is called once by Lazy initialization.
    let mut uart = unsafe { Rp1Uart::new() };
    uart.init();
    Mutex::new(uart)
});

/// Global PWM0 instance
pub static PWM0: Lazy<Mutex<Rp1Pwm>> = Lazy::new(|| {
    // SAFETY: We initialize the PWM0 driver for the RPi5 platform.
    // This is called once by Lazy initialization.
    let pwm = unsafe { Rp1Pwm::pwm0() };
    pwm.init();
    Mutex::new(pwm)
});

/// Global PWM1 instance
pub static PWM1: Lazy<Mutex<Rp1Pwm>> = Lazy::new(|| {
    // SAFETY: We initialize the PWM1 driver for the RPi5 platform.
    // This is called once by Lazy initialization.
    let pwm = unsafe { Rp1Pwm::pwm1() };
    pwm.init();
    Mutex::new(pwm)
});

/// Initialize Raspberry Pi 5 platform
///
/// This should be called early in boot to set up essential peripherals
/// like UART for debug output.
pub fn init() {
    // Keep early platform init side-effect free. Firmware already sets up
    // debug UART routing; first real log write will lazily initialize UART.
}
