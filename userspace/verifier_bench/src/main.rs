#![no_std]
#![no_main]

//! Track B verifier-cost driver.
//!
//! Loads a series of straight-line BPF programs of increasing size so the
//! kernel's load path (built with `--features verifier-cost`) emits one
//! `AXIOM VERIFIER COST` marker per load. `scripts/verifier-cost.py` parses the
//! serial log into the cost-vs-size curve.
//!
//! The shapes mirror `kernel_bpf::cost_corpus` (the host-side corpus) and the
//! `benches/verifier.rs` `bench_scaling` sizes, so the on-device cycle curve,
//! the host `states_explored` curve, and the host wall-clock curve all describe
//! the same programs.

use kernel_abi::BpfAttr;
use minilib::{bpf, exit, write};

/// Measurement sizes — must match `cost_corpus::MEASUREMENT_SIZES`.
const SIZES: [usize; 5] = [10, 50, 100, 500, 1000];
const MAX_INSNS: usize = 1000;

/// BPF_PROG_LOAD command number (raw instruction load path).
const BPF_PROG_LOAD: i32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst_src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_src,
            off,
            imm,
        }
    }
}

/// `mov r0, 0 ; (n-2)×(r0 += 1) ; exit` — one path, exactly `n` instructions.
/// Writes into `buf` and returns the populated length.
fn straight_line(buf: &mut [BpfInsn; MAX_INSNS], n: usize) -> usize {
    let mut i = 0;
    buf[i] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    i += 1;
    while i < n - 1 {
        buf[i] = BpfInsn::new(0x07, 0, 0, 1); // add64 r0, 1
        i += 1;
    }
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== Verifier Cost Bench ===\n");

    let mut buf = [BpfInsn::new(0, 0, 0, 0); MAX_INSNS];

    for &n in SIZES.iter() {
        let len = straight_line(&mut buf, n);

        let load_attr = BpfAttr {
            prog_type: 1,
            insn_cnt: len as u32,
            insns: buf.as_ptr() as u64,
            ..Default::default()
        };

        let prog_id = bpf(
            BPF_PROG_LOAD,
            &load_attr as *const _ as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        print("loaded n=");
        print_num(n as u64);
        if prog_id < 0 {
            print(" FAILED\n");
        } else {
            print(" prog_id=");
            print_num(prog_id as u64);
            print("\n");
        }
    }

    print("=== Verifier Cost Bench Done ===\n");
    exit(0);
}

fn print(s: &str) {
    write(1, s.as_bytes());
}

fn print_num(mut n: u64) {
    if n == 0 {
        print("0");
        return;
    }
    let mut digits = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0;
    while j < i / 2 {
        digits.swap(j, i - 1 - j);
        j += 1;
    }
    write(1, &digits[..i]);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    print("Panic!\n");
    loop {}
}
