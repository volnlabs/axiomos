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
fn qemu_command(args: &Args) -> std::process::Command {
    let mut cmd = std::process::Command::new("qemu-system-x86_64");
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));

    cmd.arg("-serial").arg("stdio");
    cmd.arg("-monitor").arg("telnet::45454,server,nowait");
    cmd.arg("-s");

    if args.debug {
        cmd.arg("-S");
    }
    if args.headless {
        cmd.arg("-nographic");
    }

    cmd.arg("-m").arg(&args.mem);
    cmd.arg("-drive").arg(format!(
        "if=pflash,unit=0,format=raw,file={OVMF_CODE},readonly=on"
    ));
    cmd.arg("-drive").arg(format!(
        "if=pflash,unit=1,format=raw,file={OVMF_VARS},snapshot=on"
    ));
    cmd.arg("-cdrom").arg(BOOTABLE_ISO);
    cmd.arg("-cpu").arg("max");
    cmd.arg("-smp").arg(args.smp.to_string());
    cmd.arg("-drive").arg(format!(
        "id=virtio-disk0,file={DISK_IMAGE},format=raw,if=none"
    ));
    cmd.arg("-device").arg("virtio-blk-pci,drive=virtio-disk0");

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    cmd.arg("-accel").arg("kvm");

    cmd.arg("-vga").arg("none");
    // Exit cleanly on kernel-initiated CPU reset instead of restarting
    // the guest and erasing the captured serial buffer with Limine
    // VT100 escape sequences. Without this flag, a kernel panic or
    // triple-fault loops the boot and the boot-success markers
    // (QEMU_BOOT_OK, AUDIT_FAULT_PROBE:*) emitted before the reset
    // are clobbered in CI logs.
    cmd.arg("--no-reboot");
    cmd
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

    let mut cmd = qemu_command(&args);
    let status = cmd.status().unwrap();
    assert!(status.success());
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn command_args(args: &Args) -> Vec<String> {
        qemu_command(args)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn contains_pair(args: &[String], first: &str, second: &str) -> bool {
        args.windows(2)
            .any(|pair| pair[0] == first && pair[1] == second)
    }

    #[test]
    fn cli_defaults_match_the_supported_runner_contract() {
        let args = Args::try_parse_from(["axiomos"]).expect("default CLI should parse");
        assert!(!args.debug);
        assert!(!args.headless);
        assert!(!args.no_run);
        assert_eq!(args.smp, 4);
        assert_eq!(args.mem, "4G");
    }

    #[test]
    fn cli_accepts_debug_headless_and_resource_overrides() {
        let args = Args::try_parse_from([
            "axiomos",
            "--debug",
            "--headless",
            "--no-run",
            "--smp",
            "2",
            "--mem",
            "768M",
        ])
        .expect("explicit runner options should parse");
        assert!(args.debug);
        assert!(args.headless);
        assert!(args.no_run);
        assert_eq!(args.smp, 2);
        assert_eq!(args.mem, "768M");
    }

    #[test]
    fn qemu_command_uses_resolved_artifacts_and_writable_vars_snapshot() {
        let args = Args::try_parse_from([
            "axiomos",
            "--debug",
            "--headless",
            "--smp",
            "3",
            "--mem",
            "1G",
        ])
        .expect("runner options should parse");
        let command = qemu_command(&args);
        let actual = command_args(&args);

        assert_eq!(command.get_program(), OsStr::new("qemu-system-x86_64"));
        assert_eq!(
            command.get_current_dir(),
            Some(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
        );
        assert!(contains_pair(&actual, "-serial", "stdio"));
        assert!(contains_pair(
            &actual,
            "-monitor",
            "telnet::45454,server,nowait"
        ));
        assert!(actual.iter().any(|arg| arg == "-s"));
        assert!(actual.iter().any(|arg| arg == "-S"));
        assert!(actual.iter().any(|arg| arg == "-nographic"));
        assert!(contains_pair(&actual, "-m", "1G"));
        assert!(contains_pair(&actual, "-smp", "3"));
        assert!(contains_pair(&actual, "-cdrom", BOOTABLE_ISO));
        assert!(actual.iter().any(|arg| {
            arg == &format!("if=pflash,unit=0,format=raw,file={OVMF_CODE},readonly=on")
        }));
        assert!(actual.iter().any(|arg| {
            arg == &format!("if=pflash,unit=1,format=raw,file={OVMF_VARS},snapshot=on")
        }));
        assert!(actual.iter().any(|arg| {
            arg == &format!("id=virtio-disk0,file={DISK_IMAGE},format=raw,if=none")
        }));
        assert!(contains_pair(
            &actual,
            "-device",
            "virtio-blk-pci,drive=virtio-disk0"
        ));
        assert!(contains_pair(&actual, "-vga", "none"));
        assert!(actual.iter().any(|arg| arg == "--no-reboot"));
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        assert!(contains_pair(&actual, "-accel", "kvm"));
    }

    #[test]
    fn qemu_command_does_not_freeze_or_hide_graphics_without_flags() {
        let args = Args::try_parse_from(["axiomos"]).expect("default CLI should parse");
        let actual = command_args(&args);
        assert!(!actual.iter().any(|arg| arg == "-S"));
        assert!(!actual.iter().any(|arg| arg == "-nographic"));
    }
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
