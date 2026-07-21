#![no_std]
#![no_main]
extern crate alloc;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use core::error::Error;
use core::panic::PanicInfo;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use ext2::Ext2Fs;
#[cfg(target_arch = "aarch64")]
use kernel::arch::traits::Architecture;
#[cfg(target_arch = "x86_64")]
use kernel::limine::BASE_REVISION;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel::mcore;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel::mcore::mtask::process::Process;
#[cfg(target_arch = "x86_64")]
use kernel::serial_println;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel::{
    driver::{block::BlockDevices, KernelDeviceId},
    file::{ext2::VirtualExt2Fs, vfs},
};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel_device::block::{BlockBuf, BlockDevice};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel_vfs::path::{AbsolutePath, ROOT};
use log::info;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use spin::RwLock;
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::hlt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BootError {
    BootloaderRevisionUnsupported,
    BootTimeUnavailable,
    FileSystemInitialization,
    EmbeddedRamdiskInitialization,
    IioSimulationInitialization,
    RootBlockDeviceMissing,
    RootFilesystemInvalid,
    RootMountFailed,
    InitPathInvalid,
    InitExecutableMissing,
    InitProcessCreationFailed,
}

impl BootError {
    const fn code(self) -> &'static str {
        match self {
            Self::BootloaderRevisionUnsupported => "bootloader-revision-unsupported",
            Self::BootTimeUnavailable => "boot-time-unavailable",
            Self::FileSystemInitialization => "filesystem-initialization",
            Self::EmbeddedRamdiskInitialization => "embedded-ramdisk-initialization",
            Self::IioSimulationInitialization => "iio-simulation-initialization",
            Self::RootBlockDeviceMissing => "root-block-device-missing",
            Self::RootFilesystemInvalid => "root-filesystem-invalid",
            Self::RootMountFailed => "root-mount-failed",
            Self::InitPathInvalid => "init-path-invalid",
            Self::InitExecutableMissing => "init-executable-missing",
            Self::InitProcessCreationFailed => "init-process-creation-failed",
        }
    }

    fn from_kernel_init(error: kernel::KernelInitError) -> Self {
        match error {
            #[cfg(target_arch = "x86_64")]
            kernel::KernelInitError::BootTimeUnavailable => Self::BootTimeUnavailable,
            kernel::KernelInitError::FileSystem(_) => Self::FileSystemInitialization,
            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            kernel::KernelInitError::EmbeddedRamdisk(_) => Self::EmbeddedRamdiskInitialization,
            kernel::KernelInitError::IioSimulationTask(_) => Self::IioSimulationInitialization,
        }
    }
}

fn boot_fatal(error: BootError) -> ! {
    kernel::serial_println!("BOOT_FATAL code={}", error.code());
    loop {
        hlt();
    }
}

#[cfg(target_arch = "aarch64")]
fn hlt() {
    // SAFETY: Executing wfi instruction is safe in kernel mode.
    unsafe {
        core::arch::asm!("wfi");
    }
}

#[cfg(all(feature = "audit-fault-injection", target_arch = "x86_64"))]
mod audit_fault_probe;

#[cfg(target_arch = "x86_64")]
// SAFETY: We export "kernel_main" as the symbol name for the bootloader to find.
// This symbol name is unique and required by the Limine protocol.
#[unsafe(export_name = "kernel_main")]
// SAFETY: This is the kernel entry point. It initializes the system and manages resources
// which inherently involves unsafe operations. The bootloader guarantees the initial state.
unsafe extern "C" fn main() -> ! {
    if !BASE_REVISION.is_supported() {
        boot_fatal(BootError::BootloaderRevisionUnsupported);
    }

    if let Err(error) = kernel::init() {
        boot_fatal(BootError::from_kernel_init(error));
    }

    {
        info!("mounting root filesystem");
        let Some(root_block_device) = BlockDevices::by_id(0) else {
            boot_fatal(BootError::RootBlockDeviceMissing);
        };
        let root_block_device = ArcLockedBlockDevice(root_block_device);
        let root_fs = match Ext2Fs::try_new(root_block_device) {
            Ok(root_fs) => root_fs,
            Err(_) => boot_fatal(BootError::RootFilesystemInvalid),
        };
        if vfs()
            .write()
            .mount(ROOT, VirtualExt2Fs::from(root_fs))
            .is_err()
        {
            boot_fatal(BootError::RootMountFailed);
        }
    }

    {
        info!("starting init process...");

        let init_path = match AbsolutePath::try_new("/bin/init") {
            Ok(path) => path,
            Err(_) => boot_fatal(BootError::InitPathInvalid),
        };
        if vfs().read().open(init_path).is_err() {
            boot_fatal(BootError::InitExecutableMissing);
        }
        let proc = match Process::create_userspace_init(Process::root(), init_path) {
            Ok(process) => process,
            Err(_) => boot_fatal(BootError::InitProcessCreationFailed),
        };
        info!("started process pid={}", proc.pid());
        #[cfg(feature = "audit-diagnostics")]
        serial_println!("INIT_PROCESS_STARTED pid={}", proc.pid());

        // Boot-success marker for CI smoke tests (H-06 / T-01). Placed
        // here — after kernel::init() AND root mount AND init creation —
        // so a panic between any of those steps correctly fails the
        // gate. The qemu-kernel-smoke job in .github/workflows/build.yml
        // greps the serial capture for this exact string before
        // declaring PASS.
        serial_println!("QEMU_BOOT_OK");

        // Audit-fault-injection probe (gated feature). Exercises the
        // PhysicalMemory facade under controller-armed fault scenarios.
        // Required by `scripts/verify/engineering-audit.sh` with
        // `RUN_AUDIT_FAULT=1`; absent the feature, this branch is dead.
        #[cfg(all(feature = "audit-fault-injection", target_arch = "x86_64"))]
        audit_fault_probe::run_probe();
    }

    mcore::turn_idle()
}

#[cfg(target_arch = "aarch64")]
// SAFETY: Export "kernel_main" for the bootloader.
#[unsafe(export_name = "kernel_main")]
// SAFETY: Kernel entry point.
unsafe extern "C" fn main() -> ! {
    #[inline(always)]
    fn dbg_mark(_ch: u32) {
        #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
        // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
        unsafe {
            (0x10_7D00_1000 as *mut u32).write_volatile(_ch);
        }
    }

    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(0x37); // '7'
    }

    // SAFETY: We are initializing the kernel subsystems in the correct order.
    if let Err(error) = kernel::init() {
        boot_fatal(BootError::from_kernel_init(error));
    }

    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    // SAFETY: Early debug marker write to Pi 5 debug UART10 data register.
    unsafe {
        (0x10_7D00_1000 as *mut u32).write_volatile(0x38); // '8'
    }
    dbg_mark(0x39); // '9'

    info!("ARM64 kernel started");

    // Initialize per-CPU context for CPU 0
    kernel::arch::aarch64::cpu::init_current_cpu(0);
    dbg_mark(0x41); // 'A'

    info!("About to enable interrupts...");
    // Enable interrupts
    kernel::arch::aarch64::Aarch64::enable_interrupts();
    dbg_mark(0x42); // 'B'

    info!("Interrupts enabled");

    if let Some(root_block_device) = BlockDevices::by_id(0) {
        dbg_mark(0x43); // 'C'
        info!("mounting root filesystem");
        let root_block_device = ArcLockedBlockDevice(root_block_device);
        if vfs()
            .write()
            .mount(
                ROOT,
                VirtualExt2Fs::from(match Ext2Fs::try_new(root_block_device) {
                    Ok(fs) => fs,
                    Err(_) => {
                        dbg_mark(0x65); // 'e'
                        boot_fatal(BootError::RootFilesystemInvalid);
                    }
                }),
            )
            .is_err()
        {
            dbg_mark(0x66); // 'f'
            boot_fatal(BootError::RootMountFailed);
        }
        dbg_mark(0x44); // 'D'

        info!("starting init process...");
        let init_path = match AbsolutePath::try_new("/bin/init") {
            Ok(p) => p,
            Err(_) => {
                dbg_mark(0x67); // 'g'
                boot_fatal(BootError::InitPathInvalid);
            }
        };
        if vfs().read().open(init_path).is_err() {
            dbg_mark(0x68); // 'h'
            boot_fatal(BootError::InitExecutableMissing);
        }
        let proc = match Process::create_userspace_init(Process::root(), init_path) {
            Ok(process) => process,
            Err(_) => {
                dbg_mark(0x69); // 'i'
                boot_fatal(BootError::InitProcessCreationFailed);
            }
        };
        kernel::serial_println!("INIT_PROCESS_STARTED pid={}", proc.pid());
        #[cfg(feature = "bench")]
        kernel::serial_println!("PI5_BOOT_OK");
        dbg_mark(0x45); // 'E'
    } else {
        // Expected on Pi5 bring-up before a block driver is wired in.
        dbg_mark(0x6e); // 'n'
    }

    #[cfg(feature = "rpi5")]
    kernel::arch::aarch64::platform::rpi5::control_link::spawn();

    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    {
        // Forced scheduling probe:
        // If timer/preemption is the blocker, this should still let a runnable init task run.
        dbg_mark(0x53); // 'S'
        let ctx = kernel::mcore::context::ExecutionContext::load();
        kernel::arch::aarch64::Aarch64::disable_interrupts();
        // SAFETY: We are in kernel context and intentionally forcing one scheduler pass
        // to validate runnable task handoff.
        unsafe {
            ctx.reschedule();
        }
        kernel::arch::aarch64::Aarch64::enable_interrupts();
        dbg_mark(0x59); // 'Y'
    }

    dbg_mark(0x46); // 'F'
    mcore::turn_idle()
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
struct ArcLockedBlockDevice<const N: usize>(
    Arc<RwLock<dyn BlockDevice<KernelDeviceId, N> + Send + Sync>>,
);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl<const N: usize> filesystem::BlockDevice for ArcLockedBlockDevice<N> {
    type Error = Box<dyn Error>;

    fn sector_size(&self) -> usize {
        N
    }

    fn sector_count(&self) -> usize {
        self.0.read().block_count()
    }

    fn read_sector(&self, sector_index: usize, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut read_buf = BlockBuf::new();
        self.0.write().read_block(sector_index, &mut read_buf)?;
        buf.copy_from_slice(&read_buf[..]);
        Ok(buf.len())
    }

    fn write_sector(&mut self, sector_index: usize, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut write_buf = BlockBuf::new();
        write_buf.copy_from_slice(buf);
        self.0
            .write()
            .write_block(sector_index, &write_buf)
            .map(|()| buf.len())
    }
}

#[panic_handler]
#[cfg(not(test))]
fn rust_panic(info: &PanicInfo) -> ! {
    handle_panic(info);
    loop {
        hlt();
    }
}

#[cfg(not(test))]
fn handle_panic(info: &PanicInfo) {
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    // SAFETY: Panic-time debug marker write to Pi 5 debug UART10 data register.
    unsafe {
        (0xFFFF_8010_7D00_1000 as *mut u32).write_volatile(0x21); // '!'
    }

    if let Some(location) = info.location() {
        kernel::serial_println!(
            "kernel panicked at {}:{}:{}:",
            location.file(),
            location.line(),
            location.column(),
        );
    } else {
        kernel::serial_println!("kernel panicked at <unknown>:");
    }
    kernel::serial_println!("{}", info.message());

    #[cfg(feature = "backtrace")]
    match kernel::backtrace::Backtrace::try_capture() {
        Ok(bt) => {
            error!("stack backtrace:\n{bt}");
        }
        Err(e) => {
            error!("error capturing backtrace: {e:?}");
        }
    }
}
