#![no_std]
#![no_main]

use kernel_abi::{
    BpfAttr, BPF_ATTACH_TYPE_IIO as ATTACH_TYPE_IIO,
    BPF_HELPER_RINGBUF_OUTPUT as HELPER_RINGBUF_OUTPUT,
};
use minilib::{bpf, clock_gettime, exit, msleep, timespec, write};

#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

// IioEvent struct layout (must match kernel/crates/kernel_bpf/src/attach/iio.rs)
// timestamp: u64 at offset 0
// device_id: u32 at offset 8
// channel: u32 at offset 12
// value: i32 at offset 16
// scale: u32 at offset 20
// offset: i32 at offset 24
// Total size: 28 bytes

const IIOVENT_VALUE_OFFSET: i16 = 16;
const IIOVENT_SIZE: u32 = 28;

// Filter range: accept values between 100 and 900 (out of 0-999)
const MIN_VALUE: i32 = 100;
const MAX_VALUE: i32 = 900;

// SAFETY: Entry point for the IIO demo. Called by the startup code.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== IIO Sensor Filtering Demo ===\n");
    print("Demonstrating kernel-level sensor data filtering via BPF\n\n");

    // 1. Create ringbuf map for valid sensor events
    print("Creating ringbuf map...\n");

    let map_attr = BpfAttr {
        prog_type: kernel_abi::BPF_MAP_TYPE_RINGBUF,
        insn_cnt: 4, // key_size = 4 bytes (unused for ringbuf)
        // Pack value_size and max_entries (buffer size must be power of 2)
        insns: 4096 | (4096u64 << 32), // value_size=4096, max_entries=4096
        ..Default::default()
    };

    let ringbuf_id = bpf(
        1, // BPF_MAP_CREATE
        &map_attr as *const BpfAttr as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );

    if ringbuf_id < 0 {
        print("Error: Failed to create ringbuf map\n");
        exit(1);
    }

    print("Ringbuf map created. ID: ");
    print_num(ringbuf_id as u64);
    print("\n");

    // 2. Construct BPF program to filter sensor data
    // The program:
    //   - Reads IioEvent.value from context (R1 + offset 16)
    //   - Checks if value is within valid range (100-900)
    //   - If OUT of range: return 0 (filtered/dropped)
    //   - If IN range: write entire IioEvent to ringbuf, return 1 (accepted)
    print("Building BPF filter program...\n");

    let insns = [
        // R6 = *(u64 *)(R1 + 0)  // ctx.data -> IioEvent*  (R1 is &BpfContext;
        // the per-hook IioEvent is reached through ctx.data, NOT off R1 directly
        // — R1+16 is BpfContext.data_meta, a null pointer).
        BpfInsn {
            code: 0x79,    // LDXDW (load doubleword)
            dst_src: 0x16, // dst=R6, src=R1
            off: 0,
            imm: 0,
        },
        // R0 = *(i32 *)(R6 + 16)  // Load 'value' from IioEvent via ctx.data
        BpfInsn {
            code: 0x61,    // LDXW (load word)
            dst_src: 0x60, // dst=R0, src=R6
            off: IIOVENT_VALUE_OFFSET,
            imm: 0,
        },
        // if R0 < 100 (signed), goto reject (offset +8)
        BpfInsn {
            code: 0xc5,    // JSLT_K (signed <) — 0x35 was unsigned JGE (wrong sense)
            dst_src: 0x00, // dst=R0, src=imm
            off: 8,        // skip to reject
            imm: MIN_VALUE,
        },
        // if R0 > 900 (signed), goto reject (offset +7)
        BpfInsn {
            code: 0x65,    // JSGT_K (signed >) — 0x25 was unsigned JGT
            dst_src: 0x00, // dst=R0, src=imm
            off: 7,        // skip to reject
            imm: MAX_VALUE,
        },
        // Value is in range - output to ringbuf
        // R1 = ringbuf_id
        BpfInsn {
            code: 0xb7,    // MOV64_IMM
            dst_src: 0x01, // dst=R1
            off: 0,
            imm: ringbuf_id,
        },
        // R2 = R6 (event pointer)
        BpfInsn {
            code: 0xbf,    // MOV64
            dst_src: 0x62, // dst=R2, src=R6
            off: 0,
            imm: 0,
        },
        // R3 = IioEvent size (28 bytes)
        BpfInsn {
            code: 0xb7,    // MOV64_IMM
            dst_src: 0x03, // dst=R3
            off: 0,
            imm: IIOVENT_SIZE as i32,
        },
        // R4 = 0 (flags)
        BpfInsn {
            code: 0xb7,    // MOV64_IMM
            dst_src: 0x04, // dst=R4
            off: 0,
            imm: 0,
        },
        // call bpf_ringbuf_output(ringbuf_id, event_ptr, size, flags)
        BpfInsn {
            code: 0x85, // CALL
            dst_src: 0x00,
            off: 0,
            imm: HELPER_RINGBUF_OUTPUT,
        },
        // R0 = 1 (accepted)
        BpfInsn {
            code: 0xb7,    // MOV64_IMM
            dst_src: 0x00, // dst=R0
            off: 0,
            imm: 1,
        },
        // EXIT
        BpfInsn {
            code: 0x95,
            dst_src: 0x00,
            off: 0,
            imm: 0,
        },
        // reject: R0 = 0 (filtered)
        BpfInsn {
            code: 0xb7,    // MOV64_IMM
            dst_src: 0x00, // dst=R0
            off: 0,
            imm: 0,
        },
        // EXIT
        BpfInsn {
            code: 0x95,
            dst_src: 0x00,
            off: 0,
            imm: 0,
        },
    ];

    print("Loading BPF program...\n");
    let load_attr = BpfAttr {
        prog_type: 1, // SocketFilter
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        ..Default::default()
    };

    v04_behavior("load");
    let prog_id = bpf(
        5, // BPF_PROG_LOAD
        &load_attr as *const BpfAttr as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );

    if prog_id < 0 {
        print("Error: Failed to load BPF program\n");
        exit(1);
    }
    // BPF_PROG_LOAD returns only after the kernel verified and admitted it.
    v04_behavior("verify");
    v04_behavior("admit");

    print("Program loaded. ID: ");
    print_num(prog_id as u64);
    print("\n");

    // 3. Attach Program to IIO Event
    print("Attaching to IIO device 0...\n");

    let attach_attr = BpfAttr {
        attach_btf_id: ATTACH_TYPE_IIO,
        attach_prog_fd: prog_id as u32,
        key: 0, // Device ID 0
        ..Default::default()
    };

    let res = bpf(
        8, // BPF_PROG_ATTACH
        &attach_attr as *const BpfAttr as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );

    if res < 0 {
        print("Error: Failed to attach BPF program\n");
        exit(1);
    }
    v04_behavior("attach");
    v04_behavior("active");

    print("Success! BPF filter program attached to IIO.\n");
    print("Filter range: ");
    print_num(MIN_VALUE as u64);
    print(" - ");
    print_num(MAX_VALUE as u64);
    print(" (out of 0-999)\n\n");

    // 4. Poll ringbuf for valid events
    print("Polling for filtered sensor events...\n\n");

    let mut accepted_events = 0u64;
    let max_events = 50u64;

    loop {
        // Poll ringbuf for next event
        let poll_attr = BpfAttr {
            map_fd: ringbuf_id as u32,
            ..Default::default()
        };

        let poll_res = bpf(
            37, // BPF_RINGBUF_POLL
            &poll_attr as *const BpfAttr as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        if poll_res > 0 {
            // Event received - it was accepted by the filter
            // The kernel already incremented total_events internally
            // We only see accepted events here
            accepted_events += 1;

            // In a real implementation, we would parse the event data
            // For now, just show that we received it
            print("Sensor value accepted (event #");
            print_num(accepted_events);
            print(")\n");

            if accepted_events >= max_events {
                break;
            }
        }

        // Small delay to avoid busy-waiting
        msleep(10);
    }

    // 5. Print summary statistics
    // Note: We can't get the exact total_events count from kernel without additional infrastructure
    // For the demo, we estimate based on the acceptance rate (80% in range: 100-900 out of 0-999)
    // Expected acceptance rate = (900-100+1) / 1000 = 80.1%
    let total_events = (accepted_events * 1000) / 801; // Approximate total

    print("\n=== Filter Statistics ===\n");
    print("Accepted events: ");
    print_num(accepted_events);
    print("\n");
    print("Estimated total: ");
    print_num(total_events);
    print("\n");
    let filtered = total_events - accepted_events;
    print("Filtered events: ");
    print_num(filtered);
    print("\n");
    let percent_filtered = (filtered * 100) / total_events;
    print("Filter rate: ~");
    print_num(percent_filtered);
    print("%\n\n");

    print("Demo complete! Kernel-level filtering reduces userspace processing load.\n");

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

fn v04_behavior(stage: &str) {
    let mut ts = timespec::default();
    let _ = clock_gettime(kernel_abi::CLOCK_MONOTONIC, &mut ts);
    let ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    print("V04_BEHAVIOR sample_id=1 behavior=iio-filter stage=");
    print(stage);
    print(" ts_ns=");
    print_num(ns);
    print("\n");
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    print("Panic!\n");
    loop {}
}
