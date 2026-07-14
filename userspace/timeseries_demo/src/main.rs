#![no_std]
#![no_main]

use kernel_abi::{
    BpfAttr, BPF_ATTACH_TYPE_TIMER as ATTACH_TYPE_TIMER,
    BPF_HELPER_KTIME_GET_NS as HELPER_KTIME_GET_NS,
    BPF_HELPER_TIMESERIES_PUSH as HELPER_TIMESERIES_PUSH,
    BPF_MAP_TYPE_TIMESERIES as MAP_TYPE_TIMESERIES,
};
use minilib::{bpf, exit, sleep, write};

#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

#[allow(dead_code)]
impl BpfInsn {
    const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self {
            code: 0xb7,
            dst_src: dst,
            off: 0,
            imm,
        }
    }

    const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self {
            code: 0xbf,
            dst_src: (src << 4) | dst,
            off: 0,
            imm: 0,
        }
    }

    const fn ldx_w(dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: 0x61,
            dst_src: (src << 4) | dst,
            off,
            imm: 0,
        }
    }

    const fn stx_w(dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: 0x63,
            dst_src: (src << 4) | dst,
            off,
            imm: 0,
        }
    }

    const fn stx_dw(dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: 0x7b,
            dst_src: (src << 4) | dst,
            off,
            imm: 0,
        }
    }

    const fn call(imm: i32) -> Self {
        Self {
            code: 0x85,
            dst_src: 0,
            off: 0,
            imm,
        }
    }

    const fn exit() -> Self {
        Self {
            code: 0x95,
            dst_src: 0,
            off: 0,
            imm: 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== TimeSeries Demo ===\n");

    // ---------------------------------------------------------
    // 1. Create TimeSeries Map
    // ---------------------------------------------------------
    print("Creating TimeSeries Map...\n");
    let map_attr = BpfAttr {
        prog_type: MAP_TYPE_TIMESERIES, // overlaps map_type
        insn_cnt: 8,                    // overlaps key_size (8 bytes)
        insns: (100u64 << 32) | 8,      // overlaps max_entries (high) | value_size (low)
        ..Default::default()
    };

    let map_fd = bpf(
        0,
        &map_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if map_fd < 0 {
        print("Error: Failed to create map\n");
        exit(1);
    }
    print("Map created. FD: ");
    print_num(map_fd as u64);
    print("\n");

    // ---------------------------------------------------------
    // 2. Load Producer Program
    // ---------------------------------------------------------
    print("Loading Producer program...\n");

    // Logic:
    // u64 ts = bpf_ktime_get_ns();
    // u64 val = ts / 1000; // Just some value
    // bpf_timeseries_push(map_fd, &ts, &val);

    // We need to put ts and val on stack to pass pointers
    // R10 is frame pointer (stack top)
    // [R10 - 8] = ts
    // [R10 - 16] = val

    let insns = [
        // R6 = R1 (Context) - save if needed (not needed here)

        // Call ktime_get_ns() -> R0
        BpfInsn::call(HELPER_KTIME_GET_NS),
        // R1 = R0 (ts)
        BpfInsn::mov64_reg(1, 0),
        // Store ts at [R10 - 8]
        BpfInsn::stx_dw(10, 1, -8),
        // Create a value: val = ts
        // Store val at [R10 - 16]
        BpfInsn::stx_dw(10, 1, -16),
        // Prepare arguments for bpf_timeseries_push(map_id, key_ptr, value_ptr)
        // R1 = map_fd
        BpfInsn::mov64_imm(1, map_fd),
        // R2 = R10 - 8 (pointer to key/ts)
        BpfInsn::mov64_reg(2, 10),
        BpfInsn {
            code: 0x07,
            dst_src: 0,
            off: 0,
            imm: -8,
        }, // ADD R2, -8
        // R3 = R10 - 16 (pointer to value)
        BpfInsn::mov64_reg(3, 10),
        BpfInsn {
            code: 0x07,
            dst_src: 0,
            off: 0,
            imm: -16,
        }, // ADD R3, -16
        // Call helper
        BpfInsn::call(HELPER_TIMESERIES_PUSH),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ];

    let load_attr = BpfAttr {
        prog_type: 1,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        ..Default::default()
    };

    let prog_id = bpf(
        5,
        &load_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if prog_id < 0 {
        print("Error: Failed to load program\n");
        exit(1);
    }
    print("Program loaded. ID: ");
    print_num(prog_id as u64);
    print("\n");

    // ---------------------------------------------------------
    // 3. Attach Program to Timer
    // ---------------------------------------------------------
    print("Attaching to Timer...\n");
    let attach_attr = BpfAttr {
        attach_btf_id: ATTACH_TYPE_TIMER,
        attach_prog_fd: prog_id as u32,
        ..Default::default()
    };
    let res = bpf(
        8,
        &attach_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if res < 0 {
        print("Error: Failed to attach\n");
        exit(1);
    }

    print("Running... Reading map from userspace...\n");

    // ---------------------------------------------------------
    // 4. Read Map from Userspace
    // ---------------------------------------------------------
    // We can query the map using bpf_map_lookup_elem
    // For TimeSeriesMap, the key is (u32) number of entries to retrieve (if implemented that way in Map impl)
    // Looking at TimeSeriesMap implementation:
    // fn lookup(&self, key: &[u8]) -> Option<Vec<u8>>
    // if key.len() >= 4 { let n = u32... }
    // It returns the last N entries.
    // If n=1, it returns newest.

    loop {
        sleep(1);

        let n: u32 = 1;
        let mut value = [0u8; 16]; // Timestamp (8) + Value (8)

        // We need a lookup syscall wrapper or use bpf syscall directly
        // bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr))
        // cmd = 1

        let lookup_attr = BpfAttr {
            map_fd: map_fd as u32,
            key: &n as *const u32 as u64,
            value: value.as_mut_ptr() as u64,
            ..Default::default()
        };

        let ret = bpf(
            1,
            &lookup_attr as *const _ as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        if ret == 0 {
            // value contains [timestamp(8)][val(8)]
            let ts_bytes: [u8; 8] = value[0..8].try_into().unwrap();
            let val_bytes: [u8; 8] = value[8..16].try_into().unwrap();
            let ts = u64::from_ne_bytes(ts_bytes);
            let val = u64::from_ne_bytes(val_bytes);

            print("Latest: TS=");
            print_num(ts);
            print(" Val=");
            print_num(val);
            print("\n");
        } else {
            print("Lookup failed (empty?)\n");
        }
    }
}

fn print(s: &str) {
    write(1, s.as_bytes());
}

fn print_num(mut n: u64) {
    if n == 0 {
        print("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0;
    while j < i / 2 {
        buf.swap(j, i - 1 - j);
        j += 1;
    }
    write(1, &buf[..i]);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    print("Panic!\n");
    loop {}
}
