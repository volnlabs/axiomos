#![no_std]
#![no_main]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
#![feature(negative_impls, vec_push_within_capacity)]
extern crate alloc;

use ::log::info;
use conquer_once::spin::OnceCell;
use spin::Mutex;

#[cfg(target_arch = "x86_64")]
use crate::driver::pci;
#[cfg(target_arch = "x86_64")]
use crate::limine::BOOT_TIME;

#[cfg(target_arch = "x86_64")]
mod acpi;
#[cfg(target_arch = "x86_64")]
mod apic;
pub mod arch;
pub mod backtrace;
pub mod bpf;
pub mod driver;
pub mod file;
#[cfg(target_arch = "x86_64")]
pub mod hpet;
#[cfg(target_arch = "x86_64")]
pub mod limine;
mod log;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod mcore;
pub mod mem;
pub mod serial;

// Provide a dummy allocator for non-x86_64 and non-aarch64 targets
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[global_allocator]
static ALLOCATOR: DummyAllocator = DummyAllocator;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
struct DummyAllocator;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe impl core::alloc::GlobalAlloc for DummyAllocator {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[cfg(target_arch = "x86_64")]
pub mod sse;
pub mod syscall;
pub mod time;

pub static BOOT_TIME_SECONDS: OnceCell<u64> = OnceCell::uninit();

/// Kernel boot metrics for userspace reporting
#[derive(Debug, Clone, Copy)]
pub struct KernelBootMetrics {
    pub boot_time_ms: u64,
    pub kernel_heap_kb: u64,
    pub kernel_image_mb: u64,
}

pub static BOOT_METRICS: OnceCell<KernelBootMetrics> = OnceCell::uninit();
pub static BPF_MANAGER: OnceCell<Mutex<bpf::BpfManager>> = OnceCell::uninit();

#[inline(always)]
pub(crate) fn dbg_mark(_ch: u32) {
    #[cfg(feature = "rpi5")]
    // SAFETY: Write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

fn init_boot_time() {
    #[cfg(target_arch = "x86_64")]
    BOOT_TIME_SECONDS.init_once(|| BOOT_TIME.get_response().unwrap().timestamp().as_secs());
    #[cfg(not(target_arch = "x86_64"))]
    {
        // AArch64/RISC-V currently run without a platform RTC source here.
        // Keep boot time at epoch 0 and avoid early OnceCell initialization.
    }
}

pub fn init() {
    dbg_mark(0x61); // 'a'
    init_boot_time();
    dbg_mark(0x62); // 'b'
    log::init();
    dbg_mark(0x63); // 'c'
    info!("Logging initialized");

    #[cfg(target_arch = "x86_64")]
    {
        mem::init();
        acpi::init();
        apic::init();
        hpet::init();
    }

    #[cfg(target_arch = "aarch64")]
    {
        use arch::traits::Architecture;
        dbg_mark(0x64); // 'd'
        info!("Initializing architecture...");
        arch::aarch64::Aarch64::early_init();
        dbg_mark(0x65); // 'e'
        arch::aarch64::Aarch64::init();
        dbg_mark(0x66); // 'f'
        info!("Architecture initialized");
    }

    dbg_mark(0x67); // 'g'
    info!("Initializing BPF subsystem...");
    BPF_MANAGER.init_once(|| {
        let manager = bpf::BpfManager::new();
        Mutex::new(manager)
    });
    dbg_mark(0x68); // 'h'
    info!("BPF subsystem initialized");

    info!("Initializing backtrace...");
    backtrace::init();
    dbg_mark(0x69); // 'i'
    info!("Backtrace initialized");

    info!("Initializing VFS...");
    file::init();
    dbg_mark(0x6a); // 'j'
    info!("VFS initialized");

    info!("Initializing IIO...");
    driver::iio::init();
    dbg_mark(0x6b); // 'k'
    info!("IIO initialized");

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        info!("Initializing multicore/scheduler...");
        mcore::init();
        dbg_mark(0x6c); // 'l'
        info!("Multicore/scheduler initialized");
    }

    #[cfg(target_arch = "x86_64")]
    {
        pci::init();
    }

    #[cfg(all(target_arch = "aarch64", feature = "virt"))]
    {
        info!("Initializing VirtIO MMIO...");
        driver::virtio::mmio::init();
        info!("VirtIO MMIO initialized");
    }

    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        info!("Initializing embedded ramdisk...");
        driver::ram::init_embedded();
        dbg_mark(0x52); // 'R'
        info!("Embedded ramdisk initialized");
    }

    info!("Initializing simulated devices...");
    driver::iio::init_simulated_device();
    dbg_mark(0x6d); // 'm'
    info!("Simulated devices initialized");

    info!("kernel initialized");

    // Print benchmark metrics
    print_benchmark_metrics();
}

fn print_benchmark_metrics() {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        use crate::mem::heap::Heap;
        use crate::serial_println;
        use crate::time::get_kernel_time_ns;

        // Symbols from linker script
        extern "C" {
            static __text_start: u8;
            static __kernel_end: u8;
        }

        let kernel_start = &raw const __text_start as u64;
        let kernel_end = &raw const __kernel_end as u64;
        let kernel_size_bytes = kernel_end - kernel_start;

        let boot_time_ms = get_kernel_time_ns() / 1_000_000;
        let heap_used_kb = Heap::used() / 1024;
        let kernel_image_mb = kernel_size_bytes / 1024 / 1024;

        // Store metrics for BPF context
        let metrics = KernelBootMetrics {
            boot_time_ms,
            kernel_heap_kb: heap_used_kb as u64,
            kernel_image_mb,
        };
        let _ = BOOT_METRICS.try_init_once(|| metrics);

        serial_println!("");
        serial_println!("AXIOM KERNEL METRICS");
        serial_println!("Boot to init: {} ms", boot_time_ms);
        serial_println!("Kernel heap: {} KB", heap_used_kb);
        serial_println!("Kernel image: {} MB", kernel_image_mb);
        serial_println!("");
    }
}

#[cfg(target_pointer_width = "64")]
pub trait U64Ext {
    fn into_usize(self) -> usize;
}

#[cfg(target_pointer_width = "64")]
impl U64Ext for u64 {
    #[allow(clippy::cast_possible_truncation)]
    fn into_usize(self) -> usize {
        unsafe { usize::try_from(self).unwrap_unchecked() }
    }
}

#[cfg(target_pointer_width = "64")]
pub trait UsizeExt {
    fn into_u64(self) -> u64;
}

#[cfg(target_pointer_width = "64")]
impl UsizeExt for usize {
    fn into_u64(self) -> u64 {
        self as u64
    }
}
