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
/// Calibration sizes — must match `cost_corpus::CALIBRATION_SIZES`.
const CALIBRATION_SIZES: [usize; 2] = [100, 1000];
const MAX_INSNS: usize = 1000;

/// BPF_MAP_CREATE / BPF_MAP_UPDATE_ELEM / BPF_PROG_LOAD command numbers.
const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_PROG_LOAD: i32 = 5;
/// BPF_BENCH_EXEC: feature-gated kernel command — run a program N times and
/// emit an `AXIOM EXEC COST` marker (kernel_abi::BPF_BENCH_EXEC).
const BPF_BENCH_EXEC: i32 = 100;

/// Back-to-back executions per timing marker.
const EXEC_RUNS: u32 = 64;

/// Runtime helper ABI ids (must match `kernel_bpf::verifier::HelperId`).
const HELPER_KTIME_GET_NS: i32 = 1;
const HELPER_MAP_LOOKUP_ELEM: i32 = 5;

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

// Calibration shapes — mirror `kernel_bpf::cost_corpus` exactly so host and
// on-device curves describe the same programs.

/// `mov r1,42 ; stx [r10-8],r1 ; (n-4)×(ldx/stx [r10-8]) ; mov r0,0 ; exit`.
fn memory_heavy(buf: &mut [BpfInsn; MAX_INSNS], n: usize) -> usize {
    let mut i = 0;
    buf[i] = BpfInsn::new(0xb7, 1, 0, 42); // mov64 r1, 42
    i += 1;
    buf[i] = BpfInsn::new(0x7b, (1 << 4) | 10, -8, 0); // stx_dw [r10-8], r1
    i += 1;
    let mut j = 0;
    while j < n - 4 {
        if j % 2 == 0 {
            buf[i] = BpfInsn::new(0x79, (10 << 4) | 1, -8, 0); // ldx_dw r1,[r10-8]
        } else {
            buf[i] = BpfInsn::new(0x7b, (1 << 4) | 10, -8, 0); // stx_dw [r10-8],r1
        }
        i += 1;
        j += 1;
    }
    buf[i] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    i += 1;
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

/// `mov r0,1000000 ; (n-2)×(r0 /= 3) ; exit`.
fn div_heavy(buf: &mut [BpfInsn; MAX_INSNS], n: usize) -> usize {
    let mut i = 0;
    buf[i] = BpfInsn::new(0xb7, 0, 0, 1_000_000); // mov64 r0
    i += 1;
    while i < n - 1 {
        buf[i] = BpfInsn::new(0x37, 0, 0, 3); // div64 r0, 3
        i += 1;
    }
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

/// `(n-1)×(call ktime) ; exit`.
fn helper_read_heavy(buf: &mut [BpfInsn; MAX_INSNS], n: usize) -> usize {
    let mut i = 0;
    while i < n - 1 {
        buf[i] = BpfInsn::new(0x85, 0, 0, HELPER_KTIME_GET_NS); // call
        i += 1;
    }
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

/// Key-init prologue, k×(mov r1,map_id ; mov r2,r10 ; add r2,-8 ; call
/// map_lookup), `mov r0,0 ; exit` — n = 4 + 4k.
fn helper_map_heavy(buf: &mut [BpfInsn; MAX_INSNS], n: usize, map_id: i32) -> usize {
    let k = (n - 4) / 4;
    let mut i = 0;
    buf[i] = BpfInsn::new(0xb7, 1, 0, 0); // mov64 r1, 0
    i += 1;
    buf[i] = BpfInsn::new(0x7b, (1 << 4) | 10, -8, 0); // stx_dw [r10-8], r1
    i += 1;
    let mut c = 0;
    while c < k {
        buf[i] = BpfInsn::new(0xb7, 1, 0, map_id); // mov64 r1, map_id
        i += 1;
        buf[i] = BpfInsn::new(0xbf, (10 << 4) | 2, 0, 0); // mov64 r2, r10
        i += 1;
        buf[i] = BpfInsn::new(0x07, 2, 0, -8); // add64 r2, -8
        i += 1;
        buf[i] = BpfInsn::new(0x85, 0, 0, HELPER_MAP_LOOKUP_ELEM); // call
        i += 1;
        c += 1;
    }
    buf[i] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    i += 1;
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

/// Load `len` instructions from `buf`; returns prog id or negative error.
fn load_prog(buf: &[BpfInsn; MAX_INSNS], len: usize) -> i32 {
    let load_attr = BpfAttr {
        prog_type: 1,
        insn_cnt: len as u32,
        insns: buf.as_ptr() as u64,
        ..Default::default()
    };
    bpf(
        BPF_PROG_LOAD,
        &load_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    )
}

/// Ask the instrumented kernel to execute `prog_id` EXEC_RUNS times and emit
/// an `AXIOM EXEC COST` marker.
fn bench_exec(prog_id: i32) {
    let attr = BpfAttr {
        attach_prog_fd: prog_id as u32,
        attach_btf_id: EXEC_RUNS,
        ..Default::default()
    };
    let res = bpf(
        BPF_BENCH_EXEC,
        &attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if res < 0 {
        print("  exec-bench FAILED (kernel built without verifier-cost?)\n");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== Verifier Cost Bench ===\n");

    let mut buf = [BpfInsn::new(0, 0, 0, 0); MAX_INSNS];

    // Phase 1: verification-cost scaling series (Track B). Each load emits an
    // `AXIOM VERIFIER COST` marker; each exec-bench an `AXIOM EXEC COST` one
    // (straight-line = the cheap-ALU calibration shape).
    for &n in SIZES.iter() {
        let len = straight_line(&mut buf, n);
        let prog_id = load_prog(&buf, len);
        print("straight n=");
        print_num(n as u64);
        if prog_id < 0 {
            print(" LOAD FAILED\n");
        } else {
            print(" prog_id=");
            print_num(prog_id as u64);
            print("\n");
            bench_exec(prog_id);
        }
    }

    // Phase 2: execution-cost calibration shapes (Track C brick 3).
    // A hash map (key 8, value 8) is created first and seeded with key 0 so
    // the map-lookup shape hits a real entry.
    print("Creating calibration map...\n");
    let map_attr = BpfAttr {
        prog_type: 1,             // overlaps map_type: 1 = hash
        insn_cnt: 8,              // overlaps key_size
        insns: (16u64 << 32) | 8, // overlaps max_entries (hi) | value_size (lo)
        ..Default::default()
    };
    let map_fd = bpf(
        BPF_MAP_CREATE,
        &map_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if map_fd < 0 {
        print("map create FAILED — skipping map shape\n");
    } else {
        let key: u64 = 0;
        let value: u64 = 42;
        let update_attr = BpfAttr {
            map_fd: map_fd as u32,
            key: &key as *const u64 as u64,
            value: &value as *const u64 as u64,
            ..Default::default()
        };
        if bpf(
            BPF_MAP_UPDATE_ELEM,
            &update_attr as *const _ as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        ) < 0
        {
            print("map seed FAILED (lookups will miss)\n");
        }
    }

    for &n in CALIBRATION_SIZES.iter() {
        for shape in 0..4u32 {
            let (name, len): (&str, usize) = match shape {
                0 => ("memory", memory_heavy(&mut buf, n)),
                1 => ("div", div_heavy(&mut buf, n)),
                2 => ("ktime", helper_read_heavy(&mut buf, n)),
                _ => {
                    if map_fd < 0 {
                        continue;
                    }
                    ("map", helper_map_heavy(&mut buf, n, map_fd))
                }
            };
            let prog_id = load_prog(&buf, len);
            print(name);
            print(" n=");
            print_num(n as u64);
            if prog_id < 0 {
                print(" LOAD FAILED\n");
            } else {
                print(" prog_id=");
                print_num(prog_id as u64);
                print("\n");
                bench_exec(prog_id);
            }
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
