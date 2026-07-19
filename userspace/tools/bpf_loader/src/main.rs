#![no_std]
#![no_main]

use core::panic::PanicInfo;

use kernel_abi::{
    BPF_ATTACH_TYPE_TIMER, BPF_HELPER_GET_KERNEL_HEAP_KB, BPF_HELPER_MAP_LOOKUP_ELEM,
    BPF_HELPER_RINGBUF_OUTPUT, BPF_HELPER_TRACE_PRINTK, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_RINGBUF,
};
use minilib::{bpf, exit, msleep, write};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}

// SAFETY: Entry point for the BPF loader. Called by the startup code.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(1, b"\n========================================\n");
    write(1, b"  axiomos BPF end-to-end demo\n");
    write(1, b"  Maps + Ringbuf + Timer Attach\n");
    write(1, b"========================================\n\n");

    #[repr(C)]
    struct BpfInsn {
        code: u8,
        dst_src: u8, // dst (low 4 bits) | src (high 4 bits)
        off: i16,
        imm: i32,
    }

    // Helper: encode dst and src register nibbles into dst_src byte.
    // dst goes in low 4 bits, src goes in high 4 bits.
    const fn regs(dst: u8, src: u8) -> u8 {
        (src << 4) | (dst & 0x0f)
    }

    use kernel_abi::BpfAttr;
    let attr_size = core::mem::size_of::<BpfAttr>() as i32;

    // ==================================================================
    // Step 1: Create an array map for the tick counter
    //
    // map_type=2 (Array), key_size=4, value_size=8, max_entries=1
    // This map stores a single u64 counter that the BPF program increments
    // on each timer tick. Userspace can also read it via MAP_LOOKUP_ELEM.
    // ==================================================================
    write(1, b"[1/5] Creating array map (counter)... ");

    let array_attr = BpfAttr {
        prog_type: BPF_MAP_TYPE_ARRAY,
        insn_cnt: 4,             // key_size = 4 bytes (u32 index)
        insns: 8 | (1u64 << 32), // value_size=8 (u64), max_entries=1
        ..Default::default()
    };

    let array_map_id = bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        &array_attr as *const BpfAttr as *const u8,
        attr_size,
    );

    if array_map_id < 0 {
        write(1, b"FAILED (error ");
        print_num((-array_map_id) as u64);
        write(1, b")\n");
        if array_map_id as isize == -isize::from(kernel_abi::EPERM) {
            write(1, b"BPF_UNPRIVILEGED_DENY_OK\n");
        }
        exit(1);
    }

    write(1, b"OK (id=");
    print_num(array_map_id as u64);
    write(1, b")\n");

    // ==================================================================
    // Step 2: Create a ringbuf map for event streaming
    //
    // map_type=27 (Ringbuf), buffer_size=4096 (must be power of 2)
    // BPF program writes event data here; userspace polls to receive it.
    // ==================================================================
    write(1, b"[2/5] Creating ringbuf map (events)... ");

    let ringbuf_attr = BpfAttr {
        prog_type: BPF_MAP_TYPE_RINGBUF,
        insn_cnt: 0,            // key_size = 0 for ringbuf
        insns: (4096u64) << 32, // value_size=0, max_entries=4096
        ..Default::default()
    };

    let ringbuf_map_id = bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        &ringbuf_attr as *const BpfAttr as *const u8,
        attr_size,
    );

    if ringbuf_map_id < 0 {
        write(1, b"FAILED (error ");
        print_num((-ringbuf_map_id) as u64);
        write(1, b")\n");
        exit(1);
    }

    write(1, b"OK (id=");
    print_num(ringbuf_map_id as u64);
    write(1, b")\n");

    // Credential-derived verifier tier probe. A caller without
    // PRIVILEGED_VERIFY must not load a program using a privileged helper.
    let privileged_insns = [
        BpfInsn {
            code: 0x85,
            dst_src: 0,
            off: 0,
            imm: BPF_HELPER_GET_KERNEL_HEAP_KB,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x95,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
    ];
    let privileged_attr = BpfAttr {
        insn_cnt: privileged_insns.len() as u32,
        insns: privileged_insns.as_ptr() as u64,
        ..Default::default()
    };
    let privileged_program = bpf(
        kernel_abi::BPF_PROG_LOAD as i32,
        (&raw const privileged_attr).cast(),
        attr_size,
    );
    if privileged_program < 0 {
        write(1, b"BPF_UNPRIVILEGED_TIER_DENY_OK\n");
        exit(0);
    }
    let unload_privileged = BpfAttr {
        attach_prog_fd: privileged_program as u32,
        ..Default::default()
    };
    if bpf(
        kernel_abi::BPF_PROG_UNLOAD as i32,
        (&raw const unload_privileged).cast(),
        attr_size,
    ) != 0
    {
        exit(1);
    }

    // ==================================================================
    // Step 3: Construct BPF program (27 instructions, 3 helpers)
    //
    // On each timer tick, this program:
    //   a) Looks up counter from array map (key=0) via bpf_map_lookup_elem
    //   b) Increments counter in-place (direct pointer write)
    //   c) Stores counter value on stack for ringbuf output
    //   d) Writes counter to ringbuf via bpf_ringbuf_output
    //   e) Calls bpf_trace_printk for serial visibility
    //   f) Returns 0
    //
    // Helper IDs (from interpreter dispatch):
    //   2 = bpf_trace_printk(fmt_ptr, size)
    //   5 = bpf_map_lookup_elem(map_id, key_ptr) -> returns *mut u8
    //   8 = bpf_ringbuf_output(map_id, data_ptr, data_size, flags)
    //
    // Stack layout (r10-relative):
    //   r10 - 4  : key (u32 = 0)       [4 bytes]
    //   r10 - 16 : counter value (u64)  [8 bytes, used as ringbuf event]
    //   r10 - 24 : "Tick!\0" string     [8 bytes padded]
    // ==================================================================
    write(1, b"[3/5] Loading BPF program... ");

    // "Tick!\0" encoded as two u32 immediates for LD_DW_IMM:
    //   bytes: 'T'=0x54 'i'=0x69 'c'=0x63 'k'=0x6B '!'=0x21 '\0'=0x00
    //   little-endian u32[0] = 0x6B636954 ("Tick")
    //   little-endian u32[1] = 0x00000021 ("!\0\0\0")
    let tick_lo: i32 = 0x6B636954_u32 as i32;
    let tick_hi: i32 = 0x00000021_u32 as i32;

    let insns = [
        // --- Store key=0 on stack at r10-4 ---
        // Insn 0: r1 = 0
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: 0,
        },
        // Insn 1: *(u32*)(r10 - 4) = r1
        BpfInsn {
            code: 0x63,
            dst_src: regs(10, 1),
            off: -4,
            imm: 0,
        },
        // --- Call bpf_map_lookup_elem(array_map_id, &key) ---
        // Insn 2: r1 = array_map_id
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: array_map_id,
        },
        // Insn 3: r2 = r10
        BpfInsn {
            code: 0xbf,
            dst_src: regs(2, 10),
            off: 0,
            imm: 0,
        },
        // Insn 4: r2 += -4  (point to key on stack)
        BpfInsn {
            code: 0x07,
            dst_src: regs(2, 0),
            off: 0,
            imm: -4,
        },
        // Insn 5: call bpf_map_lookup_elem (helper 5)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: BPF_HELPER_MAP_LOOKUP_ELEM,
        },
        // --- Check if lookup returned NULL; skip map+ringbuf if so ---
        // Insn 6: if r0 == 0 goto +11 -> target = insn 18 (trace_printk)
        //         Jump formula: target = pc + 1 + off = 6 + 1 + 11 = 18
        BpfInsn {
            code: 0x15,
            dst_src: regs(0, 0),
            off: 11,
            imm: 0,
        },
        // --- Increment counter in-place via direct pointer ---
        // Insn 7: r6 = r0  (save map value pointer in callee-saved r6)
        BpfInsn {
            code: 0xbf,
            dst_src: regs(6, 0),
            off: 0,
            imm: 0,
        },
        // Insn 8: r1 = *(u64*)(r6 + 0)  (load current counter value)
        BpfInsn {
            code: 0x79,
            dst_src: regs(1, 6),
            off: 0,
            imm: 0,
        },
        // Insn 9: r1 += 1  (increment)
        BpfInsn {
            code: 0x07,
            dst_src: regs(1, 0),
            off: 0,
            imm: 1,
        },
        // Insn 10: *(u64*)(r6 + 0) = r1  (store incremented value back)
        BpfInsn {
            code: 0x7b,
            dst_src: regs(6, 1),
            off: 0,
            imm: 0,
        },
        // --- Store counter on stack for ringbuf event data ---
        // Insn 11: *(u64*)(r10 - 16) = r1
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 1),
            off: -16,
            imm: 0,
        },
        // --- Call bpf_ringbuf_output(ringbuf_map_id, &counter, 8, 0) ---
        // Insn 12: r1 = ringbuf_map_id
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: ringbuf_map_id,
        },
        // Insn 13: r2 = r10
        BpfInsn {
            code: 0xbf,
            dst_src: regs(2, 10),
            off: 0,
            imm: 0,
        },
        // Insn 14: r2 += -16  (point to counter on stack)
        BpfInsn {
            code: 0x07,
            dst_src: regs(2, 0),
            off: 0,
            imm: -16,
        },
        // Insn 15: r3 = 8  (data size = sizeof(u64))
        BpfInsn {
            code: 0xb7,
            dst_src: regs(3, 0),
            off: 0,
            imm: BPF_HELPER_RINGBUF_OUTPUT,
        },
        // Insn 16: r4 = 0  (flags)
        BpfInsn {
            code: 0xb7,
            dst_src: regs(4, 0),
            off: 0,
            imm: 0,
        },
        // Insn 17: call bpf_ringbuf_output (helper 8)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: BPF_HELPER_RINGBUF_OUTPUT,
        },
        // --- Call bpf_trace_printk("Tick!", 6) for serial visibility ---
        // Insn 18: LD_DW_IMM r1, "Tick!\0" (occupies 2 instruction slots)
        BpfInsn {
            code: 0x18,
            dst_src: regs(1, 0),
            off: 0,
            imm: tick_lo,
        },
        // Insn 19: (continuation of LD_DW_IMM)
        BpfInsn {
            code: 0x00,
            dst_src: 0x00,
            off: 0,
            imm: tick_hi,
        },
        // Insn 20: *(u64*)(r10 - 24) = r1  (store string on stack)
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 1),
            off: -24,
            imm: 0,
        },
        // Insn 21: r1 = r10
        BpfInsn {
            code: 0xbf,
            dst_src: regs(1, 10),
            off: 0,
            imm: 0,
        },
        // Insn 22: r1 += -24  (pointer to string on stack)
        BpfInsn {
            code: 0x07,
            dst_src: regs(1, 0),
            off: 0,
            imm: -24,
        },
        // Insn 23: r2 = 6  (string length including NUL)
        BpfInsn {
            code: 0xb7,
            dst_src: regs(2, 0),
            off: 0,
            imm: 6,
        },
        // Insn 24: call bpf_trace_printk (helper 2)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: BPF_HELPER_TRACE_PRINTK,
        },
        // --- Return 0 ---
        // Insn 25: r0 = 0
        BpfInsn {
            code: 0xb7,
            dst_src: regs(0, 0),
            off: 0,
            imm: 0,
        },
        // Insn 26: exit
        BpfInsn {
            code: 0x95,
            dst_src: 0x00,
            off: 0,
            imm: 0,
        },
    ];

    // ------------------------------------------------------------------
    // Step 4: Load BPF program via sys_bpf(BPF_PROG_LOAD)
    // ------------------------------------------------------------------
    let load_attr = BpfAttr {
        prog_type: 1, // SocketFilter (accepted by our kernel)
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        ..Default::default()
    };

    let prog_id = bpf(
        kernel_abi::BPF_PROG_LOAD as i32,
        &load_attr as *const BpfAttr as *const u8,
        attr_size,
    );

    if prog_id < 0 {
        write(1, b"FAILED (error ");
        print_num((-prog_id) as u64);
        write(1, b")\n");
        exit(1);
    }

    write(1, b"OK (id=");
    print_num(prog_id as u64);
    write(1, b", ");
    print_num(insns.len() as u64);
    write(1, b" insns)\n");

    // ------------------------------------------------------------------
    // Step 5: Attach to timer via sys_bpf(BPF_PROG_ATTACH)
    // ------------------------------------------------------------------
    write(1, b"[4/5] Attaching to timer... ");

    let attach_attr = BpfAttr {
        attach_btf_id: BPF_ATTACH_TYPE_TIMER,
        attach_prog_fd: prog_id as u32, // program id
        ..Default::default()
    };

    let attach_res = bpf(
        kernel_abi::BPF_PROG_ATTACH as i32,
        &attach_attr as *const BpfAttr as *const u8,
        attr_size,
    );

    if attach_res != 0 {
        write(1, b"FAILED (error ");
        print_num((-attach_res) as u64);
        write(1, b")\n");
        if attach_res as isize == -isize::from(kernel_abi::EPERM) {
            write(1, b"BPF_ATTACH_DENY_OK\n");
        }
        exit(1);
    }

    write(1, b"OK\n");
    write(1, b"[5/5] Entering event loop...\n\n");

    // ==================================================================
    // Main event loop:
    //   - Poll ringbuf for events (counter values from BPF program)
    //   - Read array map to verify counter via syscall
    //   - Print status for each tick received
    //   - After TARGET_EVENTS events, print summary and exit
    // ==================================================================
    const TARGET_EVENTS: u64 = 10;

    let mut event_count: u64 = 0;
    let mut buf = [0u8; 64];
    let key: u32 = 0;
    let mut map_value: u64 = 0;

    loop {
        // Poll ringbuf for next event
        let poll_attr = BpfAttr {
            map_fd: ringbuf_map_id as u32,
            key: buf.as_mut_ptr() as u64,
            value: buf.len() as u64,
            ..Default::default()
        };

        let poll_res = bpf(
            kernel_abi::BPF_RINGBUF_POLL as i32,
            &poll_attr as *const BpfAttr as *const u8,
            attr_size,
        );

        if poll_res > 0 {
            event_count += 1;

            // Parse counter from 8-byte ringbuf event
            let counter = if poll_res >= 8 {
                u64::from_ne_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ])
            } else {
                0
            };

            // Also read the array map counter directly via syscall
            let lookup_attr = BpfAttr {
                map_fd: array_map_id as u32,
                key: &key as *const u32 as u64,
                value: &mut map_value as *mut u64 as u64,
                ..Default::default()
            };

            let lookup_res = bpf(
                kernel_abi::BPF_MAP_LOOKUP_ELEM as i32,
                &lookup_attr as *const BpfAttr as *const u8,
                attr_size,
            );

            // Print: "Tick #N received via ringbuf, map counter: M"
            write(1, b"  Tick #");
            print_num(event_count);
            write(1, b" received via ringbuf (counter=");
            print_num(counter);
            write(1, b")");

            if lookup_res == 0 {
                write(1, b", map counter: ");
                print_num(map_value);
            }
            write(1, b"\n");

            // After collecting enough events, print summary and exit
            if event_count >= TARGET_EVENTS {
                write(1, b"\n========================================\n");
                write(1, b"  Demo Complete!\n");
                write(1, b"  Events received: ");
                print_num(event_count);
                write(1, b"\n");
                write(1, b"  Final map counter: ");

                // One final map read
                let final_attr = BpfAttr {
                    map_fd: array_map_id as u32,
                    key: &key as *const u32 as u64,
                    value: &mut map_value as *mut u64 as u64,
                    ..Default::default()
                };
                let _ = bpf(
                    kernel_abi::BPF_MAP_LOOKUP_ELEM as i32,
                    &final_attr as *const BpfAttr as *const u8,
                    attr_size,
                );
                print_num(map_value);
                write(1, b"\n");

                write(1, b"  Pipeline: load -> verify -> attach -> execute -> maps -> ringbuf -> userspace\n");
                write(1, b"  Phase 1 BPF end-to-end: PROVEN\n");
                write(1, b"========================================\n");

                exit(0);
            }
        } else if poll_res < 0 {
            write(1, b"  [error] RINGBUF_POLL failed: ");
            print_num((-poll_res) as u64);
            write(1, b"\n");
        }

        // Sleep 100ms between polls
        msleep(100);
    }
}

fn print_num(mut n: u64) {
    if n == 0 {
        write(1, b"0");
        return;
    }

    let mut buf = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    // Reverse
    let mut j = 0;
    while j < i / 2 {
        buf.swap(j, i - 1 - j);
        j += 1;
    }

    write(1, &buf[..i]);
}
