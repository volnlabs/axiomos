//! QEMU virt platform support

pub mod mmio;
pub mod uart;

use conquer_once::spin::Lazy;
use spin::Mutex;
use uart::{PL011Uart, UART_BASE};

/// Global UART instance for debug output
pub static SERIAL_CONSOLE: Lazy<Mutex<PL011Uart>> = Lazy::new(|| {
    // SAFETY: We initialize the UART driver for the virt platform.
    // This is called once by Lazy initialization.
    let mut uart = unsafe { PL011Uart::new(UART_BASE) };
    uart.init();
    Mutex::new(uart)
});

/// Initialize QEMU virt platform
pub fn init() {
    // Force lazy initialization of UART
    let _ = &*SERIAL_CONSOLE;

    // Print boot banner
    use core::fmt::Write;
    let _ = writeln!(SERIAL_CONSOLE.lock(), "\n=== axiomos on QEMU virt ===");
    let _ = writeln!(SERIAL_CONSOLE.lock(), "Platform initialized");
}

/// Export serial_console for use by other modules
pub use SERIAL_CONSOLE as serial_console;
