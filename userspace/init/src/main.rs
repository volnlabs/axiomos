#![no_std]
#![no_main]

use minilib::write;

const PHASE4_EXPORT_DEMO: &str = "/bin/sched_switch_export_demo";
const PHASE4_BRIDGE_DEMO: &str = "/bin/sched_switch_bridge_demo";

// SAFETY: Entry point for the init process, called by the kernel/loader.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(1, b"=== Axiom eBPF Init ===\n");
    write(1, b"Phase 4 demo boot: ");
    write(1, PHASE4_EXPORT_DEMO.as_bytes());
    write(1, b" -> ");
    write(1, PHASE4_BRIDGE_DEMO.as_bytes());
    write(1, b"\n");

    spawn_demo(PHASE4_EXPORT_DEMO);
    minilib::msleep(100);
    spawn_demo(PHASE4_BRIDGE_DEMO);

    loop {
        minilib::pause();
    }
    /*
        use kernel_abi::BpfAttr;
        use minilib::bpf;

        #[repr(C)]
        struct BpfInsn {
            code: u8,
            dst_src: u8,
            off: i16,
            imm: i32,
        }

        // Step 1: Create an array map for the counter
        // map_type=2 (Array), key_size=4, value_size=8, max_entries=1
        write(1, b"Creating counter map...\n");

        let map_attr = BpfAttr {
            prog_type: 2, // map_type = Array
            insn_cnt: 4,  // key_size = 4 bytes (u32)
            // Pack value_size (8) and max_entries (1) into insns field
            // low 32 bits = value_size, high 32 bits = max_entries
            insns: 8 | (1u64 << 32), // value_size=8, max_entries=1
            ..Default::default()
        };

        let map_id = bpf(
            0,
            &map_attr as *const BpfAttr as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        if map_id < 0 {
            write(1, b"Failed to create map!\n");
            loop {
                minilib::pause();
            }
        }

        write(1, b"Map created with id: ");
        print_num(map_id as u64);
        write(1, b"\n");

        // Step 2: Load BPF program that increments the counter
        // This program:
        //   1. Calls bpf_map_lookup_elem(map_id, &key) to get pointer to value
        //   2. If pointer is valid, increments the value at that pointer
        //   3. Exits
        write(1, b"Loading counter BPF program...\n");

        // BPF program bytecode:
        // r6 = map_id (will be patched)
        // *(u32 *)(r10 - 4) = 0  // key = 0 on stack
        // r1 = r6                 // map_id
        // r2 = r10 - 4            // key pointer
        // call bpf_map_lookup_elem (3)
        // if r0 == 0, goto exit
        // r1 = *(u64 *)(r0)       // load current value
        // r1 += 1                  // increment
        // *(u64 *)(r0) = r1       // store back
        // exit

        let insns = [
            // r6 = map_id (0 in this case)
            BpfInsn {
                code: 0xb7,
                dst_src: 0x06,
                off: 0,
                imm: map_id,
            },
            // r1 = 0 (key value)
            BpfInsn {
                code: 0xb7,
                dst_src: 0x01,
                off: 0,
                imm: 0,
            },
            // *(u32 *)(r10 - 4) = r1 (store key on stack)
            BpfInsn {
                code: 0x63,
                dst_src: 0x1a,
                off: -4,
                imm: 0,
            },
            // r1 = r6 (map_id for helper call)
            BpfInsn {
                code: 0xbf,
                dst_src: 0x61,
                off: 0,
                imm: 0,
            },
            // r2 = r10 (frame pointer)
            BpfInsn {
                code: 0xbf,
                dst_src: 0xa2,
                off: 0,
                imm: 0,
            },
            // r2 += -4 (point to key on stack)
            BpfInsn {
                code: 0x07,
                dst_src: 0x02,
                off: 0,
                imm: -4,
            },
            // call bpf_map_lookup_elem (helper 3)
            BpfInsn {
                code: 0x85,
                dst_src: 0x00,
                off: 0,
                imm: 3,
            },
            // if r0 == 0, skip 3 (goto exit)
            BpfInsn {
                code: 0x15,
                dst_src: 0x00,
                off: 3,
                imm: 0,
            },
            // r1 = *(u64 *)(r0 + 0) (load counter)
            BpfInsn {
                code: 0x79,
                dst_src: 0x01,
                off: 0,
                imm: 0,
            },
            // r1 += 1 (increment)
            BpfInsn {
                code: 0x07,
                dst_src: 0x01,
                off: 0,
                imm: 1,
            },
            // *(u64 *)(r0 + 0) = r1 (store back)
            BpfInsn {
                code: 0x7b,
                dst_src: 0x10,
                off: 0,
                imm: 0,
            },
            // exit
            BpfInsn {
                code: 0x95,
                dst_src: 0x00,
                off: 0,
                imm: 0,
            },
        ];

        let load_attr = BpfAttr {
            prog_type: 1, // SocketFilter (or any valid type)
            insn_cnt: insns.len() as u32,
            insns: insns.as_ptr() as u64,
            ..Default::default()
        };

        let prog_id = bpf(
            5,
            &load_attr as *const BpfAttr as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        if prog_id < 0 {
            write(1, b"Failed to load BPF program!\n");
            loop {
                minilib::pause();
            }
        }

        write(1, b"BPF program loaded with id: ");
        print_num(prog_id as u64);
        write(1, b"\n");

        // Step 3: Attach program to timer
        write(1, b"Attaching to Timer...\n");

        let attach_attr = BpfAttr {
            attach_btf_id: 1, // Timer attach type
            attach_prog_fd: prog_id as u32,
            ..Default::default()
        };

        let attach_res = bpf(
            8,
            &attach_attr as *const BpfAttr as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        if attach_res != 0 {
            write(1, b"Failed to attach!\n");
            loop {
                minilib::pause();
            }
        }

        write(1, b"Attached! Reading counter every ~1M iterations...\n\n");

        // Step 4: Periodically read counter from map
        let key: u32 = 0;
        let mut value: u64 = 0;
        let mut loop_count: u64 = 0;

        loop {
            loop_count += 1;

            // Read counter every ~1 million iterations
            if loop_count % 1_000_000 == 0 {
                let lookup_attr = BpfAttr {
                    map_fd: map_id as u32,
                    key: &key as *const u32 as u64,
                    value: &mut value as *mut u64 as u64,
                    ..Default::default()
                };

                let res = bpf(
                    1,
                    &lookup_attr as *const BpfAttr as *const u8,
                    core::mem::size_of::<BpfAttr>() as i32,
                );

                if res == 0 {
                    write(1, b"Timer ticks: ");
                    print_num(value);
                    write(1, b"\n");
                }
            }

            minilib::pause();
        }
    */
}

fn spawn_demo(path: &str) {
    write(1, b"Spawning ");
    write(1, path.as_bytes());
    write(1, b"...\n");

    let pid = minilib::spawn(path);
    if pid < 0 {
        write(1, b"Failed to spawn demo, errno=");
        print_num((-pid) as u64);
        write(1, b"\n");
    } else {
        write(1, b"Spawned PID: ");
        print_num(pid as u64);
        write(1, b"\n");
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    loop {}
}
