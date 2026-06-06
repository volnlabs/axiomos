pub mod boot;
pub mod context;
pub mod cpu;
pub mod dtb;
pub mod exceptions;
pub mod gic;
pub mod interrupts;
pub mod mem;
pub mod mm;
pub mod paging;
pub mod phys;
pub mod platform;
pub mod shutdown;
pub mod syscall;

use crate::arch::traits::Architecture;

pub struct Aarch64;

#[inline(always)]
fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
    // ALWAYS use the physical address here so it works both before and after MMU is enabled
    // (requires the address to be identity mapped in the page tables).
    unsafe {
        (platform::rpi5::memory_map::BCM2712_UART10_BASE_PHYS as *mut u32).write_volatile(_ch);
    }
}

impl Architecture for Aarch64 {
    fn early_init() {
        // Setup exception vector table
        exceptions::init_exception_vector();
    }

    fn init() {
        // Initialize memory management (physical allocator + page tables)
        dbg_mark(0x6e); // 'n'
        crate::mem::init();
        dbg_mark(0x6f); // 'o'

        // Initialize interrupt controller (GIC)
        interrupts::init();
        dbg_mark(0x70); // 'p'

        // Setup syscall interface
        syscall::init();
        dbg_mark(0x71); // 'q'
    }

    fn enable_interrupts() {
        // SAFETY: daifclr is the interrupt mask clear register. Writing #2
        // clears the IRQ mask bit, enabling IRQ interrupts. This is safe as
        // it only affects interrupt delivery, and we're in kernel mode.
        unsafe {
            core::arch::asm!("msr daifclr, #2");
        }
    }

    fn disable_interrupts() {
        // SAFETY: daifset is the interrupt mask set register. Writing #2
        // sets the IRQ mask bit, disabling IRQ interrupts. This is safe as
        // it only affects interrupt delivery, and we're in kernel mode.
        unsafe {
            core::arch::asm!("msr daifset, #2");
        }
    }

    fn are_interrupts_enabled() -> bool {
        let daif: u64;
        // SAFETY: Reading the DAIF register is always safe. It contains the
        // current interrupt mask state. Bit 7 (I bit) indicates IRQ masking.
        unsafe {
            core::arch::asm!("mrs {}, daif", out(reg) daif);
        }
        (daif & 0x80) == 0
    }

    fn wait_for_interrupt() {
        // SAFETY: wfi (wait for interrupt) halts the CPU until an interrupt
        // occurs. This is safe as long as interrupts are properly configured.
        // The kernel calls this from idle loops when there's no work to do.
        unsafe {
            core::arch::asm!("wfi");
        }
    }

    fn shutdown() -> ! {
        shutdown::shutdown()
    }

    fn reboot() -> ! {
        shutdown::reboot()
    }
}
