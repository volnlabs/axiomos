#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[cfg(feature = "managed-syscall-probe")]
mod syscall_probe;

#[cfg(not(feature = "managed-runtime"))]
use kernel_abi::{BPF_PROG_LOAD_ELF, BpfAttr};
use minilib::exit;
#[cfg(all(feature = "managed-runtime", not(feature = "managed-syscall-probe")))]
use minilib::msleep;
#[cfg(not(feature = "managed-runtime"))]
use minilib::{O_RDONLY, bpf, close, open, pause};
#[cfg(not(feature = "managed-syscall-probe"))]
use minilib::{read, write};

#[cfg(not(feature = "managed-runtime"))]
// `rk deploy --program startup.rbpf` places the signed container here.
const SIGNED_PROGRAM_PATH: &str = "/var/lib/rkbpf/programs/startup.rbpf";
#[cfg(not(feature = "managed-runtime"))]
const MAX_SIGNED_PROGRAM_SIZE: usize = 256 * 1024;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}

// SAFETY: Bare-metal userspace entry point invoked by the kernel ELF loader.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    #[cfg(feature = "managed-syscall-probe")]
    {
        syscall_probe::run()
    }
    #[cfg(all(feature = "managed-runtime", not(feature = "managed-syscall-probe")))]
    {
        managed_start()
    }
    #[cfg(not(feature = "managed-runtime"))]
    {
        legacy_start()
    }
}

#[cfg(all(feature = "managed-runtime", not(feature = "managed-syscall-probe")))]
fn managed_start() -> ! {
    use shrike_link::installer::FRAME_BYTES;
    use signed_bpf_loader::{Transport, dispatch};

    let mut transport = Transport::new();
    let mut input = [0; FRAME_BYTES];
    loop {
        if let Some(prefix) = transport.pending_reply() {
            let count = write(1, prefix);
            if count > 0 {
                transport.written(count as usize);
            } else {
                msleep(1);
            }
            continue;
        }

        let count = read(0, &mut input);
        if count < 0 {
            transport.read_error(count);
            msleep(1);
            continue;
        }
        if count == 0 {
            msleep(1);
            continue;
        }
        transport.receive(
            &input[..(count as usize).min(FRAME_BYTES)],
            |request, response| {
                dispatch(request, response, minilib::managed_bpf_bytes, || {
                    minilib::estop_trigger() as isize
                })
            },
        );
    }
}

#[cfg(not(feature = "managed-runtime"))]
fn legacy_start() -> ! {
    let fd = open(SIGNED_PROGRAM_PATH, O_RDONLY, 0);
    if fd < 0 {
        write(1, b"SIGNED_BPF_INPUT_MISSING\n");
        exit(2);
    }

    let mut program = [0u8; MAX_SIGNED_PROGRAM_SIZE];
    let mut len = 0usize;
    while len < program.len() {
        let count = read(fd, &mut program[len..]);
        if count < 0 {
            close(fd);
            exit(3);
        }
        if count == 0 {
            break;
        }
        len += count as usize;
    }
    close(fd);
    if len == 0 || len == program.len() {
        write(1, b"SIGNED_BPF_INPUT_INVALID\n");
        exit(4);
    }

    let attr = BpfAttr {
        insn_cnt: len as u32,
        insns: program.as_ptr() as u64,
        ..BpfAttr::default()
    };
    let program_id = bpf(
        BPF_PROG_LOAD_ELF as i32,
        (&raw const attr).cast(),
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if program_id < 0 {
        write(1, b"SIGNED_BPF_LOAD_REJECTED\n");
        exit(5);
    }

    write(1, b"SIGNED_BPF_LOAD_OK\n");
    loop {
        pause();
    }
}
