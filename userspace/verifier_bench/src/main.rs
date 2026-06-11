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
/// BPF_PROG_ATTACH (kernel_abi). Attach commits the hook's utilization, so it
/// is where the admission gate fires.
const BPF_PROG_ATTACH: i32 = 8;
/// BPF_BENCH_EXEC: feature-gated kernel command — run a program N times and
/// emit an `AXIOM EXEC COST` marker (kernel_abi::BPF_BENCH_EXEC).
const BPF_BENCH_EXEC: i32 = 100;

/// `bpf_trace_printk` helper id — banned on the embedded RT fragment.
const HELPER_TRACE_PRINTK: i32 = 2;
/// Attach type used for the admission self-test (ATTACH_TYPE_TIMER).
const ATTACH_TYPE_TIMER: u32 = 1;

/// Back-to-back executions per timing marker.
const EXEC_RUNS: u32 = 64;

/// Runtime helper ABI ids (must match `kernel_bpf::verifier::HelperId`).
const HELPER_KTIME_GET_NS: i32 = 1;
const HELPER_MAP_LOOKUP_ELEM: i32 = 5;
const HELPER_RINGBUF_OUTPUT: i32 = 8;
const HELPER_GPIO_GET: i32 = 1004;

/// Ring-buffer map type + size (bytes, power of two) for the ringbuf shape.
const MAP_TYPE_RINGBUF: u64 = 27;
const RINGBUF_BYTES: u64 = 65536;

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

/// `k`×(`mov r1,0 ; call gpio_get`), then `mov r0,0 ; exit` — n = 2 + 2k.
fn helper_copy_heavy(buf: &mut [BpfInsn; MAX_INSNS], n: usize) -> usize {
    let k = (n - 2) / 2;
    let mut i = 0;
    let mut c = 0;
    while c < k {
        buf[i] = BpfInsn::new(0xb7, 1, 0, 0); // mov64 r1, 0 (pin)
        i += 1;
        buf[i] = BpfInsn::new(0x85, 0, 0, HELPER_GPIO_GET); // call gpio_get
        i += 1;
        c += 1;
    }
    buf[i] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    i += 1;
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

/// Sample prologue, then k×(mov r1,rb ; mov r2,r10 ; add r2,-8 ; mov r3,8 ;
/// mov r4,0 ; call ringbuf_output), then `mov r0,0 ; exit` — n = 4 + 6k.
fn helper_ringbuf_heavy(buf: &mut [BpfInsn; MAX_INSNS], n: usize, rb_id: i32) -> usize {
    let k = (n - 4) / 6;
    let mut i = 0;
    buf[i] = BpfInsn::new(0xb7, 1, 0, 0); // mov64 r1, 0
    i += 1;
    buf[i] = BpfInsn::new(0x7b, (1 << 4) | 10, -8, 0); // stx_dw [r10-8], r1
    i += 1;
    let mut c = 0;
    while c < k {
        buf[i] = BpfInsn::new(0xb7, 1, 0, rb_id); // mov64 r1, rb_id
        i += 1;
        buf[i] = BpfInsn::new(0xbf, (10 << 4) | 2, 0, 0); // mov64 r2, r10
        i += 1;
        buf[i] = BpfInsn::new(0x07, 2, 0, -8); // add64 r2, -8
        i += 1;
        buf[i] = BpfInsn::new(0xb7, 3, 0, 8); // mov64 r3, 8 (size)
        i += 1;
        buf[i] = BpfInsn::new(0xb7, 4, 0, 0); // mov64 r4, 0 (flags)
        i += 1;
        buf[i] = BpfInsn::new(0x85, 0, 0, HELPER_RINGBUF_OUTPUT); // call
        i += 1;
        c += 1;
    }
    buf[i] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    i += 1;
    buf[i] = BpfInsn::new(0x95, 0, 0, 0); // exit
    i += 1;
    i
}

// --- Admission self-test shapes (Track C gate check) ---

/// `mov r1,0 ; call trace_printk ; mov r0,0 ; exit` — calls the helper banned on
/// the embedded RT fragment, so the verifier rejects it at load there.
fn trace_printk_prog(buf: &mut [BpfInsn; MAX_INSNS]) -> usize {
    buf[0] = BpfInsn::new(0xb7, 1, 0, 0); // mov64 r1, 0
    buf[1] = BpfInsn::new(0x85, 0, 0, HELPER_TRACE_PRINTK); // call trace_printk
    buf[2] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    buf[3] = BpfInsn::new(0x95, 0, 0, 0); // exit
    4
}

/// `mov r0,0 ; exit` — minimal well-formed program with negligible WCET; used as
/// the control that must both load and attach.
fn tiny_prog(buf: &mut [BpfInsn; MAX_INSNS]) -> usize {
    buf[0] = BpfInsn::new(0xb7, 0, 0, 0); // mov64 r0, 0
    buf[1] = BpfInsn::new(0x95, 0, 0, 0); // exit
    2
}

/// Attach `prog_id` to `attach_type`; returns 0 on admit or negative on reject.
fn attach_prog(prog_id: i32, attach_type: u32) -> i32 {
    let attr = BpfAttr {
        attach_btf_id: attach_type,
        attach_prog_fd: prog_id as u32,
        ..Default::default()
    };
    bpf(
        BPF_PROG_ATTACH,
        &attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    )
}

/// Print a signed return code (`sys_bpf` collapses every error to -1).
fn print_rc(rc: i32) {
    if rc < 0 {
        print("-");
        print_num((-(rc as i64)) as u64);
    } else {
        print_num(rc as u64);
    }
}

/// Emit one `AXIOM ADMISSION <name> rc=<rc> PASS|FAIL` line. `pass` encodes
/// whether the observed rc matched the gate's expected polarity.
fn selftest_case(name: &str, rc: i32, pass: bool) {
    print("AXIOM ADMISSION ");
    print(name);
    print(" rc=");
    print_rc(rc);
    print(if pass { " PASS\n" } else { " FAIL\n" });
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

    // A ring-buffer map for the ringbuf-output shape. No consumer drains it, so
    // it is sized large enough to absorb the calibration runs (cost is
    // lock-dominated, so a partial fill does not skew the slope).
    print("Creating ringbuf map...\n");
    let rb_attr = BpfAttr {
        prog_type: MAP_TYPE_RINGBUF as u32,
        insn_cnt: 0,
        insns: RINGBUF_BYTES << 32, // max_entries=bytes (pow2) | value_size=0
        ..Default::default()
    };
    let rb_fd = bpf(
        BPF_MAP_CREATE,
        &rb_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if rb_fd < 0 {
        print("ringbuf create FAILED — skipping ringbuf shape\n");
    }

    for &n in CALIBRATION_SIZES.iter() {
        for shape in 0..6u32 {
            let (name, len): (&str, usize) = match shape {
                0 => ("memory", memory_heavy(&mut buf, n)),
                1 => ("div", div_heavy(&mut buf, n)),
                2 => ("ktime", helper_read_heavy(&mut buf, n)),
                3 => {
                    if map_fd < 0 {
                        continue;
                    }
                    ("map", helper_map_heavy(&mut buf, n, map_fd))
                }
                4 => ("copy", helper_copy_heavy(&mut buf, n)),
                _ => {
                    if rb_fd < 0 {
                        continue;
                    }
                    ("ringbuf", helper_ringbuf_heavy(&mut buf, n, rb_fd))
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

    // Phase 3: admission self-test (Track C gate check). Errors collapse to
    // rc=-1 in `sys_bpf`, so PASS is judged on the expected rc polarity; the
    // kernel's log lines name the exact gate on the same serial stream.
    //
    // Note on the WCET budget: the syscall load path caps a program at 4096
    // instructions, and the densest reachable shape (copy-heavy) tops out near
    // ~5.6k WCET units at 1000 insns — far below the ~166k single-program WCET
    // budget. So no *loadable* program trips that gate; the bound that actually
    // bites on this profile is the *cumulative* utilization budget, which a
    // single program also cannot reach alone (5.6k*6ns*1kHz ≈ 3.4e7 << 5e8 ns/s)
    // but a fleet of attachments can. The self-test exercises the two reachable
    // gates: the printk RT-ban (load time) and cumulative utilization (attach).
    print("=== Admission Self-Test ===\n");

    // printk-ban: loading a trace_printk caller is rejected on the RT fragment.
    let len = trace_printk_prog(&mut buf);
    let rc = load_prog(&buf, len);
    selftest_case("printk-ban", rc, rc < 0);

    // control: a negligible-WCET program both loads and attaches. Run before the
    // saturation loop, while the utilization budget still has room.
    let len = tiny_prog(&mut buf);
    let load_rc = load_prog(&buf, len);
    let attach_rc = if load_rc >= 0 {
        attach_prog(load_rc, ATTACH_TYPE_TIMER)
    } else {
        -1 // load failed unexpectedly → force FAIL below
    };
    selftest_case("control", attach_rc, load_rc >= 0 && attach_rc == 0);

    // admission (cumulative): attach copies of the densest reachable program
    // (copy-heavy at the 1000-insn cap, wcet ≈ 5.6k → ≈3.4e7 ns/s each) to the
    // same hook until the summed utilization crosses the 5e8 ns/s budget
    // (~15 attachments). PASS = some attach succeeded and a later one was
    // rejected, i.e. the budget bit.
    let len = helper_copy_heavy(&mut buf, MAX_INSNS);
    let mut attached: u32 = 0;
    let mut reject_rc: i32 = 0;
    let mut iter = 0;
    while iter < 32 {
        let pid = load_prog(&buf, len);
        if pid < 0 {
            break; // unexpected load failure → reject_rc stays 0 → FAIL
        }
        let arc = attach_prog(pid, ATTACH_TYPE_TIMER);
        if arc < 0 {
            reject_rc = arc;
            break;
        }
        attached += 1;
        iter += 1;
    }
    print("AXIOM ADMISSION admission attached=");
    print_num(attached as u64);
    print(" rc=");
    print_rc(reject_rc);
    print(if attached > 0 && reject_rc < 0 {
        " PASS\n"
    } else {
        " FAIL\n"
    });

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
