use log::{Level, Metadata, Record};

#[cfg(target_arch = "x86_64")]
use crate::mcore::context::ExecutionContext;
use crate::serial_println;

#[inline(always)]
fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

pub(crate) fn init() {
    dbg_mark(0x79); // 'y'
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    // SAFETY: Early boot is single-core and we do logger setup exactly once.
    unsafe {
        let _ = log::set_logger_racy(&SerialLogger);
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    let _ = log::set_logger(&SerialLogger);
    dbg_mark(0x7a); // 'z'
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    // SAFETY: Same rationale as set_logger_racy during single-core early boot.
    unsafe {
        // Keep runtime logging disabled on Pi 5 early bring-up; use raw UART
        // markers instead to avoid faulting in formatted serial output path.
        log::set_max_level_racy(::log::LevelFilter::Off);
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    log::set_max_level(::log::LevelFilter::Info);
    dbg_mark(0x5a); // 'Z'
}

pub struct SerialLogger;

impl SerialLogger {}

impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() < Level::Trace || metadata.target().starts_with("kernel")
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let color = match record.level() {
                Level::Error => "\x1b[1;31m",
                Level::Warn => "\x1b[1;33m",
                Level::Info => "\x1b[1;94m",
                Level::Debug => "\x1b[1;30m",
                Level::Trace => "\x1b[1;90m",
            };

            #[cfg(target_arch = "x86_64")]
            {
                if let Some(ctx) = ExecutionContext::try_load() {
                    serial_println!(
                        "{}{:5}\x1b[0m cpu{} pid{:3} [{}] {}",
                        color,
                        record.level(),
                        ctx.cpu_id(),
                        ctx.pid(),
                        record.target(),
                        record.args()
                    );
                } else {
                    serial_println!(
                        "{}{:5}\x1b[0m boot [{}] {}",
                        color,
                        record.level(),
                        record.target(),
                        record.args()
                    );
                }
            }

            #[cfg(not(target_arch = "x86_64"))]
            {
                serial_println!(
                    "{}{:5}\x1b[0m boot [{}] {}",
                    color,
                    record.level(),
                    record.target(),
                    record.args()
                );
            }
        }
    }

    fn flush(&self) {
        // no-op
    }
}
