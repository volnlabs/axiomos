// Bench transport is kept separate from the production synchronous console.
#[cfg(any(
    test,
    all(target_arch = "aarch64", feature = "rpi5", feature = "bench")
))]
mod bench_buffer;

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "bench"))]
mod deferred_bench {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use spin::Mutex;

    use super::bench_buffer::BenchBuffer;

    pub(super) static ACTIVE: AtomicBool = AtomicBool::new(false);
    static BUFFER: Mutex<BenchBuffer<16384>> = Mutex::new(BenchBuffer::new());
    static CONTENDED: AtomicU64 = AtomicU64::new(0);

    // Called with IRQs masked. try_lock also rejects recursive formatting and
    // contention instead of making the console a blocking dependency.
    pub(super) fn record(args: core::fmt::Arguments<'_>) {
        if let Some(mut buffer) = BUFFER.try_lock() {
            buffer.note_dropped(CONTENDED.swap(0, Ordering::Relaxed));
            buffer.record(args);
        } else {
            CONTENDED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Called from the masked timer IRQ, after its control work. No FIFO wait,
    // allocation, blocking lock or unbounded drain; GPIO still needs hardware
    // timing measurements with this bounded interference present.
    pub(super) fn drain() {
        if !ACTIVE.load(Ordering::Acquire) {
            return;
        }
        let Some(mut buffer) = BUFFER.try_lock() else {
            return;
        };
        let Some(uart) = crate::arch::aarch64::platform::rpi5::UART.try_lock() else {
            return;
        };
        buffer.note_dropped(CONTENDED.swap(0, Ordering::Relaxed));
        buffer.drain(64, |byte| uart.try_putc(byte));
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "bench"))]
pub(crate) fn enable_bench_buffer() {
    deferred_bench::ACTIVE.store(true, core::sync::atomic::Ordering::Release);
    crate::serial_println!(
        "PI5_BENCH_LOG_MODE deferred=true capacity_bytes=16384 record_bytes=1024 drain_budget=64"
    );
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "bench"))]
pub(crate) fn drain_bench_buffer() {
    deferred_bench::drain();
}

/// Panic diagnostics cannot depend on another timer tick. Pending bench records
/// may be lost on this emergency path; the panic itself invalidates the run.
#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "bench"))]
pub fn emergency_console() {
    deferred_bench::ACTIVE.store(false, core::sync::atomic::Ordering::Release);
}

// x86_64 serial implementation
#[cfg(target_arch = "x86_64")]
mod x86_64_impl {
    use conquer_once::spin::Lazy;
    use spin::Mutex;
    use uart_16550::SerialPort;

    static SERIAL1: Lazy<Mutex<SerialPort>> = Lazy::new(|| {
        // SAFETY: We are initializing the standard COM1 serial port at 0x3F8.
        // This address is reserved for the serial port on x86 platforms.
        let mut serial_port = unsafe { SerialPort::new(0x3F8) };
        serial_port.init();
        Mutex::new(serial_port)
    });

    pub fn internal_print(args: core::fmt::Arguments) {
        use core::fmt::Write;

        use x86_64::instructions::interrupts;

        // disable interrupts while holding a lock on the WRITER
        // so that no deadlock can occur when we want to print
        // something in an interrupt handler
        interrupts::without_interrupts(|| {
            SERIAL1
                .lock()
                .write_fmt(args)
                .expect("Printing to serial failed");
        });
    }
}

// aarch64 serial implementation
#[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
mod aarch64_impl {
    pub fn internal_print(args: core::fmt::Arguments) {
        use core::fmt::Write;

        #[cfg(feature = "rpi5")]
        {
            use crate::arch::aarch64::platform::rpi5::UART;
            use crate::arch::aarch64::Aarch64;
            use crate::arch::traits::Architecture;

            // Disable interrupts while printing to avoid deadlock
            let were_enabled = Aarch64::are_interrupts_enabled();
            if were_enabled {
                Aarch64::disable_interrupts();
            }

            #[cfg(feature = "bench")]
            if super::deferred_bench::ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
                super::deferred_bench::record(args);
                if were_enabled {
                    Aarch64::enable_interrupts();
                }
                return;
            }
            let _ = UART.lock().write_fmt(args);

            if were_enabled {
                Aarch64::enable_interrupts();
            }
        }

        #[cfg(feature = "virt")]
        {
            use crate::arch::aarch64::platform::virt::SERIAL_CONSOLE;
            use crate::arch::aarch64::Aarch64;
            use crate::arch::traits::Architecture;

            // Disable interrupts while printing to avoid deadlock
            let were_enabled = Aarch64::are_interrupts_enabled();
            if were_enabled {
                Aarch64::disable_interrupts();
            }

            let _ = SERIAL_CONSOLE.lock().write_fmt(args);

            if were_enabled {
                Aarch64::enable_interrupts();
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
#[doc(hidden)]
pub use aarch64_impl::internal_print;

// Stub for aarch64 without aarch64_arch feature
#[cfg(all(target_arch = "aarch64", not(feature = "aarch64_arch")))]
#[doc(hidden)]
pub fn internal_print(_args: core::fmt::Arguments) {
    // No-op when aarch64_arch feature is not enabled
}
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub use x86_64_impl::internal_print;

/// Prints to the host through the serial interface.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::serial::internal_print(format_args!($($arg)*)));
}

/// Prints to the host through the serial interface, appending a newline.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(
        concat!($fmt, "\n"), $($arg)*));
}
