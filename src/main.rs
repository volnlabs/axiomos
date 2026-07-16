#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
use clap::Parser;

#[cfg(not(target_os = "none"))]
static KERNEL_BINARY: &str = env!("KERNEL_BINARY");
#[cfg(not(target_os = "none"))]
static BOOTABLE_ISO: &str = env!("BOOTABLE_ISO");
#[cfg(not(target_os = "none"))]
static OVMF_CODE: &str = env!("OVMF_X86_64_CODE");
#[cfg(not(target_os = "none"))]
static OVMF_VARS: &str = env!("OVMF_X86_64_VARS");
#[cfg(not(target_os = "none"))]
static DISK_IMAGE: &str = env!("DISK_IMAGE");

#[cfg(not(target_os = "none"))]
#[derive(Parser)]
struct Args {
    #[arg(
        long,
        help = "Start QEMU with a GDB server listening on localhost:1234"
    )]
    debug: bool,
    #[arg(long, help = "Run QEMU without a display")]
    headless: bool,
    #[arg(long, help = "Number of CPU cores to emulate", default_value_t = 4)]
    smp: u8,
    #[arg(long, help = "Don't boot, just build")]
    no_run: bool,
    #[arg(
        long,
        help = "The amount of RAM that the emulator will boot with ('4G', '17M' etc.)",
        default_value = "4G"
    )]
    mem: String,
}

#[cfg(not(target_os = "none"))]
fn main() {
    println!("KERNEL_BINARY: {KERNEL_BINARY}");
    println!("BOOTABLE_ISO: {BOOTABLE_ISO}");
    println!("DISK_IMAGE: {DISK_IMAGE}");

    let args = Args::parse();

    if args.no_run {
        return;
    }

    #[cfg(debug_assertions)]
    {
        // create an lldb debug file to make debugging easy
        let content = format!(
            r"target create {KERNEL_BINARY}

# If the kernel is a position independent executable (PIE), you need to set the slide as the offset
# at which the kernel is being loaded. For static executables, the slide is 0, in which case
# we can omit this whole line.
#
# target modules load --file {KERNEL_BINARY} --slide 0xffffffff80000000

gdb-remote localhost:1234
b kernel_main
b handle_panic
continue"
        );
        std::fs::write("debug.lldb", content).expect("unable to create debug file");
        println!("debug file is ready, run `lldb -s debug.lldb` to start debugging");
    }

    let mut cmd = std::process::Command::new("qemu-system-x86_64");
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));

    // serial comms via console - needed for log output of the kernel
    cmd.arg("-serial");
    cmd.arg("stdio");

    // QEMU monitor via telnet
    cmd.arg("-monitor");
    cmd.arg("telnet::45454,server,nowait");

    // start GDB server
    cmd.arg("-s");

    if args.debug {
        // wait for client to connect
        cmd.arg("-S");
    }

    if args.headless {
        // run without a window, but with graphics devices attached
        cmd.arg("-nographic");
    }

    cmd.arg("-m");
    cmd.arg(args.mem);

    // OVMF firmware
    cmd.arg("-drive");
    cmd.arg(format!(
        "if=pflash,unit=0,format=raw,file={OVMF_CODE},readonly=on"
    ));
    cmd.arg("-drive");
    cmd.arg(format!(
        "if=pflash,unit=1,format=raw,file={OVMF_VARS},snapshot=on"
    ));

    // kernel binary
    cmd.arg("-cdrom");
    cmd.arg(BOOTABLE_ISO);

    cmd.arg("-cpu");
    cmd.arg("max");

    cmd.arg("-smp");
    cmd.arg(args.smp.to_string());

    cmd.arg("-drive");
    cmd.arg(format!(
        "id=virtio-disk0,file={DISK_IMAGE},format=raw,if=none"
    ));
    cmd.arg("-device");
    cmd.arg("virtio-blk-pci,drive=virtio-disk0");

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        cmd.arg("-accel");
        cmd.arg("kvm");
    }

    cmd.arg("-vga");
    cmd.arg("none");

    // Exit cleanly on kernel-initiated CPU reset instead of restarting
    // the guest and erasing the captured serial buffer with Limine
    // VT100 escape sequences. Without this flag, a kernel panic or
    // triple-fault loops the boot and the boot-success markers
    // (QEMU_BOOT_OK, AUDIT_FAULT_PROBE:*) emitted before the reset
    // are clobbered in CI logs.
    cmd.arg("--no-reboot");

    let status = cmd.status().unwrap();
    assert!(status.success());
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
