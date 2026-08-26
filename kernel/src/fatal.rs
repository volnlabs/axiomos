/// Stops the kernel after a non-recoverable invariant or an infallible-trait
/// boundary fails.
///
/// The code must be a stable, bounded identifier. Debug builds panic to retain
/// source diagnostics; release builds emit one record and enter the
/// architecture halt path, as required by ADR-0002.
pub(crate) fn halt(code: &'static str) -> ! {
    #[cfg(debug_assertions)]
    panic!("kernel fatal: {code}");

    #[cfg(not(debug_assertions))]
    {
        crate::serial_println!("V04_PANIC kind=fatal");
        crate::serial_println!("KERNEL_FATAL code={}", code);
        loop {
            #[cfg(target_arch = "x86_64")]
            x86_64::instructions::hlt();
            #[cfg(target_arch = "aarch64")]
            // SAFETY: The kernel has entered its terminal fail-closed state.
            unsafe {
                core::arch::asm!("wfi");
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            core::hint::spin_loop();
        }
    }
}
