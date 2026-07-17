#![no_std]
#![no_main]

use minilib::write;

#[cfg(feature = "bpf-unsigned-development")]
const PHASE4_EXPORT_DEMO: &str = "/bin/sched_switch_export_demo";
#[cfg(feature = "bpf-unsigned-development")]
const PHASE4_BRIDGE_DEMO: &str = "/bin/sched_switch_bridge_demo";
#[cfg(not(feature = "bpf-unsigned-development"))]
const SIGNED_BPF_LOADER: &str = "/bin/signed_bpf_loader";
const UNMAPPED_USER_ADDRESS: usize = 0x0000_7000_0000_0000;

// Private audit-diagnostics operations. They deliberately remain outside
// kernel_abi: production kernels reject them with EINVAL.
const DEBUG_OP_GET_PIPE_READ_BLOCKS: usize = 3;
const DEBUG_OP_GET_CHILD_WAIT_BLOCKS: usize = 4;

#[derive(Clone, Copy)]
struct BlockingProbeResult {
    functional: bool,
    blocked: Option<bool>,
}

impl BlockingProbeResult {
    const fn failed() -> Self {
        Self {
            functional: false,
            blocked: None,
        }
    }
}

#[cfg(feature = "bpf-unsigned-development")]
#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

// SAFETY: Entry point for the init process, called by the kernel/loader.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if usercopy_fault_probe() {
        write(1, b"USERCOPY_EFAULT_OK\n");
    } else {
        write(1, b"USERCOPY_EFAULT_FAIL\n");
    }

    if expect_errno(minilib::syscall0(usize::MAX), kernel_abi::ENOSYS) {
        write(1, b"UNKNOWN_SYSCALL_ENOSYS_OK\n");
    } else {
        write(1, b"UNKNOWN_SYSCALL_ENOSYS_FAIL\n");
    }

    if nanosleep_wait_queue_probe() {
        write(1, b"NANOSLEEP_WAITQ_OK\n");
    } else {
        write(1, b"NANOSLEEP_WAITQ_FAIL\n");
    }

    if nanosleep_interrupt_probe() {
        write(1, b"NANOSLEEP_INTERRUPT_OK\n");
    } else {
        write(1, b"NANOSLEEP_INTERRUPT_FAIL\n");
    }

    let pipe_reader_data_wake = pipe_blocked_reader_data_wake_probe();
    if pipe_reader_data_wake.functional {
        write(1, b"PIPE_WAIT_READER_DATA_OK\n");
    } else {
        write(1, b"PIPE_WAIT_READER_DATA_FAIL\n");
    }
    emit_blocked_marker(
        pipe_reader_data_wake,
        b"PIPE_WAIT_READER_DATA_BLOCKED_OK\n",
        b"PIPE_WAIT_READER_DATA_BLOCKED_FAIL\n",
    );

    let pipe_reader_eof_wake = pipe_blocked_reader_eof_wake_probe();
    if pipe_reader_eof_wake.functional {
        write(1, b"PIPE_WAIT_READER_EOF_OK\n");
    } else {
        write(1, b"PIPE_WAIT_READER_EOF_FAIL\n");
    }
    emit_blocked_marker(
        pipe_reader_eof_wake,
        b"PIPE_WAIT_READER_EOF_BLOCKED_OK\n",
        b"PIPE_WAIT_READER_EOF_BLOCKED_FAIL\n",
    );

    if pipe_reader_data_wake.functional && pipe_reader_eof_wake.functional {
        write(1, b"PIPE_WAITQ_OK\n");
    } else {
        write(1, b"PIPE_WAITQ_FAIL\n");
    }

    let child_wait_before_exit = child_wait_before_exit_probe();
    if child_wait_before_exit.functional {
        write(1, b"CHILD_WAIT_BEFORE_EXIT_OK\n");
    } else {
        write(1, b"CHILD_WAIT_BEFORE_EXIT_FAIL\n");
    }
    emit_blocked_marker(
        child_wait_before_exit,
        b"CHILD_WAIT_BEFORE_EXIT_BLOCKED_OK\n",
        b"CHILD_WAIT_BEFORE_EXIT_BLOCKED_FAIL\n",
    );

    let child_exit_before_wait = child_exit_before_wait_probe();
    if child_exit_before_wait {
        write(1, b"CHILD_EXIT_BEFORE_WAIT_OK\n");
    } else {
        write(1, b"CHILD_EXIT_BEFORE_WAIT_FAIL\n");
    }

    if child_wait_before_exit.functional && child_exit_before_wait {
        write(1, b"LIFECYCLE_EXIT_WAIT_OK\n");
    } else {
        write(1, b"LIFECYCLE_EXIT_WAIT_FAIL\n");
    }

    if lifecycle_fault_wait_probe() {
        write(1, b"LIFECYCLE_FAULT_WAIT_OK\n");
    } else {
        write(1, b"LIFECYCLE_FAULT_WAIT_FAIL\n");
    }

    if lifecycle_exec_reject_probe() {
        write(1, b"LIFECYCLE_EXEC_REJECT_OK\n");
    } else {
        write(1, b"LIFECYCLE_EXEC_REJECT_FAIL\n");
    }

    if lifecycle_exec_wait_probe() {
        write(1, b"LIFECYCLE_EXEC_WAIT_OK\n");
    } else {
        write(1, b"LIFECYCLE_EXEC_WAIT_FAIL\n");
    }

    if bpf_foreign_owner_probe() {
        write(1, b"BPF_FOREIGN_OWNER_DENY_OK\n");
    } else {
        write(1, b"BPF_FOREIGN_OWNER_DENY_FAIL\n");
    }

    #[cfg(feature = "bpf-unsigned-development")]
    if bpf_pinned_write_only_probe() {
        write(1, b"BPF_PINNED_WRITE_ONLY_OK\n");
    } else {
        write(1, b"BPF_PINNED_WRITE_ONLY_FAIL\n");
    }

    #[cfg(feature = "bpf-unsigned-development")]
    if bpf_hook_snapshot_smp_probe() {
        write(1, b"BPF_HOOK_SNAPSHOT_SMP_OK\n");
    } else {
        write(1, b"BPF_HOOK_SNAPSHOT_SMP_FAIL\n");
    }

    #[cfg(feature = "bpf-unsigned-development")]
    if bpf_smp4_scheduler_probe() {
        write(1, b"SMP4_SCHEDULER_OK\n");
    }

    #[cfg(feature = "bpf-unsigned-development")]
    if bpf_owner_exit_probe() {
        write(1, b"BPF_HANDLE_REUSE_OK\n");
        write(1, b"BPF_OWNER_EXIT_OK\n");
    } else {
        write(1, b"BPF_HANDLE_REUSE_FAIL\n");
        write(1, b"BPF_OWNER_EXIT_FAIL\n");
    }

    #[cfg(feature = "bpf-unsigned-development")]
    if bpf_capability_denial_probe() {
        write(1, b"BPF_CAPABILITY_PROBE_STARTED\n");
    } else {
        write(1, b"BPF_CAPABILITY_PROBE_START_FAIL\n");
    }

    write(1, b"=== axiomos eBPF init ===\n");
    #[cfg(feature = "bpf-unsigned-development")]
    {
        write(1, b"Phase 4 demo boot: ");
        write(1, PHASE4_EXPORT_DEMO.as_bytes());
        write(1, b" -> ");
        write(1, PHASE4_BRIDGE_DEMO.as_bytes());
        write(1, b"\n");
    }

    #[cfg(not(feature = "bpf-unsigned-development"))]
    spawn_demo(
        SIGNED_BPF_LOADER,
        kernel_abi::BPF_CAP_PROGRAM_LOAD | kernel_abi::BPF_CAP_MAP_READ,
    );

    #[cfg(feature = "bpf-unsigned-development")]
    {
        spawn_demo(
            PHASE4_EXPORT_DEMO,
            kernel_abi::BPF_CAP_PROGRAM_LOAD
                | kernel_abi::BPF_CAP_MAP_CREATE
                | kernel_abi::BPF_CAP_MAP_READ
                | kernel_abi::BPF_CAP_MAP_WRITE
                | kernel_abi::BPF_CAP_ATTACH_SCHEDULER
                | kernel_abi::BPF_CAP_OBJECT_PIN,
        );
        minilib::msleep(100);
        spawn_demo(
            PHASE4_BRIDGE_DEMO,
            kernel_abi::BPF_CAP_MAP_READ | kernel_abi::BPF_CAP_OBJECT_PIN,
        );
    }

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
            prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
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
            attach_btf_id: kernel_abi::BPF_ATTACH_TYPE_TIMER,
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

#[cfg(feature = "bpf-unsigned-development")]
fn bpf_hook_snapshot_smp_probe() -> bool {
    let attr_size = core::mem::size_of::<kernel_abi::BpfAttr>() as i32;
    let map_attr = kernel_abi::BpfAttr {
        prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
        insn_cnt: 4,
        insns: 8 | (1u64 << 32),
        ..kernel_abi::BpfAttr::default()
    };
    let map = minilib::bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        (&raw const map_attr).cast(),
        attr_size,
    );
    if map < 0 {
        return false;
    }

    const fn regs(dst: u8, src: u8) -> u8 {
        (src << 4) | (dst & 0x0f)
    }

    let instructions = [
        // key = 0 at r10 - 4
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x63,
            dst_src: regs(10, 1),
            off: -4,
            imm: 0,
        },
        // value = bpf_map_lookup_elem(map, &key)
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: map,
        },
        BpfInsn {
            code: 0xbf,
            dst_src: regs(2, 10),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x07,
            dst_src: regs(2, 0),
            off: 0,
            imm: -4,
        },
        BpfInsn {
            code: 0x85,
            dst_src: 0,
            off: 0,
            imm: kernel_abi::BPF_HELPER_MAP_LOOKUP_ELEM,
        },
        BpfInsn {
            code: 0x15,
            dst_src: regs(0, 0),
            off: 4,
            imm: 0,
        },
        BpfInsn {
            code: 0x79,
            dst_src: regs(1, 0),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x07,
            dst_src: regs(1, 0),
            off: 0,
            imm: 1,
        },
        BpfInsn {
            code: 0x7b,
            dst_src: regs(0, 1),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(0, 0),
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
    let load = kernel_abi::BpfAttr {
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        ..kernel_abi::BpfAttr::default()
    };
    let program = minilib::bpf(
        kernel_abi::BPF_PROG_LOAD as i32,
        (&raw const load).cast(),
        attr_size,
    );
    let mut probe_ok = program >= 0;
    let mut workers = [0i32; 2];
    let mut worker_count = 0;
    let mut attached = false;

    if program >= 0 {
        for worker in &mut workers {
            let child = minilib::fork();
            if child < 0 {
                probe_ok = false;
                break;
            }
            if child == 0 {
                for _ in 0..192 {
                    minilib::msleep(1);
                }
                minilib::exit(0);
            }
            *worker = child;
            worker_count += 1;
        }

        let attachment = kernel_abi::BpfAttr {
            attach_btf_id: kernel_abi::BPF_ATTACH_TYPE_SCHED_SWITCH,
            attach_prog_fd: program as u32,
            ..kernel_abi::BpfAttr::default()
        };
        if worker_count == workers.len() {
            for _ in 0..128 {
                if minilib::bpf(
                    kernel_abi::BPF_PROG_ATTACH as i32,
                    (&raw const attachment).cast(),
                    attr_size,
                ) != 0
                {
                    probe_ok = false;
                    break;
                }
                attached = true;
                minilib::msleep(1);
                if minilib::bpf(
                    kernel_abi::BPF_PROG_DETACH as i32,
                    (&raw const attachment).cast(),
                    attr_size,
                ) != 0
                {
                    probe_ok = false;
                    break;
                }
                attached = false;
            }
        } else {
            probe_ok = false;
        }
    }

    let mut workers_ok = true;
    for &child in &workers[..worker_count] {
        let mut status = 0;
        workers_ok &= minilib::waitpid(child, &raw mut status, 0) == child && status == 0;
    }
    probe_ok &= workers_ok;

    if attached {
        let attachment = kernel_abi::BpfAttr {
            attach_btf_id: kernel_abi::BPF_ATTACH_TYPE_SCHED_SWITCH,
            attach_prog_fd: program as u32,
            ..kernel_abi::BpfAttr::default()
        };
        if minilib::bpf(
            kernel_abi::BPF_PROG_DETACH as i32,
            (&raw const attachment).cast(),
            attr_size,
        ) != 0
        {
            probe_ok = false;
        }
    }

    let key = 0u32;
    let mut observed = 0u64;
    let lookup = kernel_abi::BpfAttr {
        map_fd: map as u32,
        key: (&raw const key) as u64,
        value: (&raw mut observed) as u64,
        ..kernel_abi::BpfAttr::default()
    };
    let execution_seen = minilib::bpf(
        kernel_abi::BPF_MAP_LOOKUP_ELEM as i32,
        (&raw const lookup).cast(),
        attr_size,
    ) == 0
        && observed > 0;

    let mut cleanup_ok = true;
    if program >= 0 {
        let unload = kernel_abi::BpfAttr {
            attach_prog_fd: program as u32,
            ..kernel_abi::BpfAttr::default()
        };
        cleanup_ok &= minilib::bpf(
            kernel_abi::BPF_PROG_UNLOAD as i32,
            (&raw const unload).cast(),
            attr_size,
        ) == 0;
    }
    let destroy = kernel_abi::BpfAttr {
        map_fd: map as u32,
        ..kernel_abi::BpfAttr::default()
    };
    cleanup_ok &= minilib::bpf(
        kernel_abi::BPF_MAP_DESTROY as i32,
        (&raw const destroy).cast(),
        attr_size,
    ) == 0;

    probe_ok && execution_seen && cleanup_ok
}

#[cfg(feature = "bpf-unsigned-development")]
fn bpf_smp4_scheduler_probe() -> bool {
    const CPU_COUNT: u32 = 4;
    const WORKER_COUNT: usize = 4;
    const MAX_TRACKED_PID: i32 = 255;
    const MAP_ENTRIES: u64 = (MAX_TRACKED_PID as u64 + 1) * CPU_COUNT as u64;

    let attr_size = core::mem::size_of::<kernel_abi::BpfAttr>() as i32;
    let map_attr = kernel_abi::BpfAttr {
        prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
        insn_cnt: 4,
        insns: 8 | (MAP_ENTRIES << 32),
        ..kernel_abi::BpfAttr::default()
    };
    let map = minilib::bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        (&raw const map_attr).cast(),
        attr_size,
    );
    if map < 0 {
        emit_smp4_scheduler_diagnostics(0, 0, 0);
        return false;
    }
    let mut stage = 1u64;

    const fn regs(dst: u8, src: u8) -> u8 {
        (src << 4) | (dst & 0x0f)
    }

    // R1 is `&BpfContext`; its first field is the verifier-tracked pointer to
    // SchedSwitchContext. Each CPU writes a distinct (next_pid, cpu_id) array
    // cell, so the hot path has no shared read-modify-write race.
    let instructions = [
        BpfInsn {
            code: 0x79,
            dst_src: regs(6, 1),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x79,
            dst_src: regs(7, 6),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x25,
            dst_src: regs(7, 0),
            off: 10,
            imm: (CPU_COUNT - 1) as i32,
        },
        BpfInsn {
            code: 0x79,
            dst_src: regs(8, 6),
            off: 24,
            imm: 0,
        },
        BpfInsn {
            code: 0x67,
            dst_src: regs(8, 0),
            off: 0,
            imm: 2,
        },
        BpfInsn {
            code: 0x0f,
            dst_src: regs(8, 7),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x63,
            dst_src: regs(10, 8),
            off: -4,
            imm: 0,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: map,
        },
        BpfInsn {
            code: 0xbf,
            dst_src: regs(2, 10),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x07,
            dst_src: regs(2, 0),
            off: 0,
            imm: -4,
        },
        BpfInsn {
            code: 0x85,
            dst_src: 0,
            off: 0,
            imm: kernel_abi::BPF_HELPER_MAP_LOOKUP_ELEM,
        },
        BpfInsn {
            code: 0x15,
            dst_src: regs(0, 0),
            off: 1,
            imm: 0,
        },
        BpfInsn {
            code: 0x7a,
            dst_src: regs(0, 0),
            off: 0,
            imm: 1,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(0, 0),
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
    let load = kernel_abi::BpfAttr {
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        ..kernel_abi::BpfAttr::default()
    };
    let program = minilib::bpf(
        kernel_abi::BPF_PROG_LOAD as i32,
        (&raw const load).cast(),
        attr_size,
    );
    if program >= 0 {
        stage = 2;
    }

    let attachment = kernel_abi::BpfAttr {
        attach_btf_id: kernel_abi::BPF_ATTACH_TYPE_SCHED_SWITCH,
        attach_prog_fd: program.max(0) as u32,
        ..kernel_abi::BpfAttr::default()
    };
    let mut attached = program >= 0
        && minilib::bpf(
            kernel_abi::BPF_PROG_ATTACH as i32,
            (&raw const attachment).cast(),
            attr_size,
        ) == 0;
    if attached {
        stage = 3;
    }
    let mut probe_ok = attached;
    let mut workers = [0i32; WORKER_COUNT];
    let mut worker_count = 0;

    if attached {
        for worker in &mut workers {
            let child = minilib::fork();
            if child < 0 {
                probe_ok = false;
                break;
            }
            if child == 0 {
                for _ in 0..512 {
                    minilib::msleep(1);
                }
                minilib::exit(0);
            }
            *worker = child;
            worker_count += 1;
            if child > MAX_TRACKED_PID {
                probe_ok = false;
            }
        }
    }
    probe_ok &= worker_count == WORKER_COUNT;
    if probe_ok {
        stage = 4;
    }

    let mut workers_ok = true;
    for &child in &workers[..worker_count] {
        let mut status = 0;
        workers_ok &= minilib::waitpid(child, &raw mut status, 0) == child && status == 0;
    }
    probe_ok &= workers_ok;
    if stage == 4 && workers_ok {
        stage = 5;
    }

    if attached {
        let detached = minilib::bpf(
            kernel_abi::BPF_PROG_DETACH as i32,
            (&raw const attachment).cast(),
            attr_size,
        ) == 0;
        probe_ok &= detached;
        attached = !detached;
        if stage == 5 && detached {
            stage = 6;
        }
    }

    let mut aggregate_mask = 0u8;
    for &child in &workers[..worker_count] {
        let mut worker_mask = 0u8;
        if child <= 0 || child > MAX_TRACKED_PID {
            probe_ok = false;
            continue;
        }
        for cpu in 0..CPU_COUNT {
            let key = child as u32 * CPU_COUNT + cpu;
            let mut observed = 0u64;
            let lookup = kernel_abi::BpfAttr {
                map_fd: map as u32,
                key: (&raw const key) as u64,
                value: (&raw mut observed) as u64,
                ..kernel_abi::BpfAttr::default()
            };
            if minilib::bpf(
                kernel_abi::BPF_MAP_LOOKUP_ELEM as i32,
                (&raw const lookup).cast(),
                attr_size,
            ) == 0
                && observed != 0
            {
                worker_mask |= 1 << cpu;
            }
        }
        probe_ok &= worker_mask != 0;
        aggregate_mask |= worker_mask;
    }
    probe_ok &= aggregate_mask == 0x0f;
    if stage == 6 && probe_ok {
        stage = 7;
    }

    let mut cleanup_ok = true;
    if attached {
        cleanup_ok &= minilib::bpf(
            kernel_abi::BPF_PROG_DETACH as i32,
            (&raw const attachment).cast(),
            attr_size,
        ) == 0;
    }
    if program >= 0 {
        let unload = kernel_abi::BpfAttr {
            attach_prog_fd: program as u32,
            ..kernel_abi::BpfAttr::default()
        };
        cleanup_ok &= minilib::bpf(
            kernel_abi::BPF_PROG_UNLOAD as i32,
            (&raw const unload).cast(),
            attr_size,
        ) == 0;
    }
    let destroy = kernel_abi::BpfAttr {
        map_fd: map as u32,
        ..kernel_abi::BpfAttr::default()
    };
    cleanup_ok &= minilib::bpf(
        kernel_abi::BPF_MAP_DESTROY as i32,
        (&raw const destroy).cast(),
        attr_size,
    ) == 0;
    if stage == 7 && cleanup_ok {
        stage = 8;
    }

    emit_smp4_scheduler_diagnostics(stage, worker_count, aggregate_mask);

    probe_ok && cleanup_ok
}

#[cfg(feature = "bpf-unsigned-development")]
fn emit_smp4_scheduler_diagnostics(stage: u64, workers: usize, cpu_mask: u8) {
    write(1, b"SMP4_SCHEDULER_STAGE=");
    print_num(stage);
    write(1, b"\nSMP4_SCHEDULER_WORKERS=");
    print_num(workers as u64);
    write(1, b"\nSMP4_SCHEDULER_CPU_MASK=");
    print_num(cpu_mask as u64);
    write(1, b"\n");
}

fn read_audit_counter(op: usize) -> Option<usize> {
    let value = minilib::debug_syscall(op, 0);
    (value >= 0).then_some(value as usize)
}

fn counter_increased(before: Option<usize>, after: Option<usize>) -> Option<bool> {
    Some(after? > before?)
}

fn emit_blocked_marker(result: BlockingProbeResult, ok: &[u8], fail: &[u8]) {
    if let Some(blocked) = result.blocked {
        write(
            1,
            if result.functional && blocked {
                ok
            } else {
                fail
            },
        );
    }
}

fn wait_probe_delay() -> bool {
    let delay = minilib::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    minilib::nanosleep(&raw const delay, core::ptr::null_mut()) == 0
}

fn pipe_blocked_reader_data_wake_probe() -> BlockingProbeResult {
    let mut data = [-1; 2];
    if minilib::pipe(data.as_mut_ptr()) != 0 {
        return BlockingProbeResult::failed();
    }
    let mut ready = [-1; 2];
    if minilib::pipe(ready.as_mut_ptr()) != 0 {
        let _ = minilib::close(data[0]);
        let _ = minilib::close(data[1]);
        return BlockingProbeResult::failed();
    }

    let child = minilib::fork();
    if child < 0 {
        for fd in [data[0], data[1], ready[0], ready[1]] {
            let _ = minilib::close(fd);
        }
        return BlockingProbeResult::failed();
    }
    if child == 0 {
        let setup = minilib::close(data[0]) == 0
            && minilib::close(ready[0]) == 0
            && minilib::write(ready[1], b"R") == 1
            && minilib::close(ready[1]) == 0;
        let delayed = setup && wait_probe_delay();
        let wrote_payload = delayed && minilib::write(data[1], b"wake") == 4;
        let closed_writer = minilib::close(data[1]) == 0;
        minilib::exit(if wrote_payload && closed_writer { 0 } else { 1 });
    }

    let setup = minilib::close(data[1]) == 0 && minilib::close(ready[1]) == 0;
    let mut ready_byte = [0; 1];
    let child_is_delaying =
        setup && minilib::read(ready[0], &mut ready_byte) == 1 && ready_byte == *b"R";
    let closed_ready = minilib::close(ready[0]) == 0;
    let mut payload = [0; 4];
    let block_count_before = if child_is_delaying {
        read_audit_counter(DEBUG_OP_GET_PIPE_READ_BLOCKS)
    } else {
        None
    };
    let received_payload =
        child_is_delaying && minilib::read(data[0], &mut payload) == 4 && payload == *b"wake";
    let block_count_after = if child_is_delaying {
        read_audit_counter(DEBUG_OP_GET_PIPE_READ_BLOCKS)
    } else {
        None
    };
    let closed_reader = minilib::close(data[0]) == 0;
    let mut status = 0;
    let reaped_child = minilib::waitpid(child, &raw mut status, 0) == child && status == 0;

    BlockingProbeResult {
        functional: child_is_delaying
            && closed_ready
            && received_payload
            && closed_reader
            && reaped_child,
        blocked: counter_increased(block_count_before, block_count_after),
    }
}

fn pipe_blocked_reader_eof_wake_probe() -> BlockingProbeResult {
    let mut data = [-1; 2];
    if minilib::pipe(data.as_mut_ptr()) != 0 {
        return BlockingProbeResult::failed();
    }
    let mut ready = [-1; 2];
    if minilib::pipe(ready.as_mut_ptr()) != 0 {
        let _ = minilib::close(data[0]);
        let _ = minilib::close(data[1]);
        return BlockingProbeResult::failed();
    }

    let child = minilib::fork();
    if child < 0 {
        for fd in [data[0], data[1], ready[0], ready[1]] {
            let _ = minilib::close(fd);
        }
        return BlockingProbeResult::failed();
    }
    if child == 0 {
        let setup = minilib::close(data[0]) == 0
            && minilib::close(ready[0]) == 0
            && minilib::write(ready[1], b"R") == 1
            && minilib::close(ready[1]) == 0;
        let delayed = setup && wait_probe_delay();
        let closed_writer = minilib::close(data[1]) == 0;
        minilib::exit(if delayed && closed_writer { 0 } else { 1 });
    }

    let setup = minilib::close(data[1]) == 0 && minilib::close(ready[1]) == 0;
    let mut ready_byte = [0; 1];
    let child_is_delaying =
        setup && minilib::read(ready[0], &mut ready_byte) == 1 && ready_byte == *b"R";
    let closed_ready = minilib::close(ready[0]) == 0;
    let mut eof_probe = [0; 1];
    let block_count_before = if child_is_delaying {
        read_audit_counter(DEBUG_OP_GET_PIPE_READ_BLOCKS)
    } else {
        None
    };
    let received_eof = child_is_delaying && minilib::read(data[0], &mut eof_probe) == 0;
    let block_count_after = if child_is_delaying {
        read_audit_counter(DEBUG_OP_GET_PIPE_READ_BLOCKS)
    } else {
        None
    };
    let closed_reader = minilib::close(data[0]) == 0;
    let mut status = 0;
    let reaped_child = minilib::waitpid(child, &raw mut status, 0) == child && status == 0;

    BlockingProbeResult {
        functional: child_is_delaying
            && closed_ready
            && received_eof
            && closed_reader
            && reaped_child,
        blocked: counter_increased(block_count_before, block_count_after),
    }
}

fn child_wait_before_exit_probe() -> BlockingProbeResult {
    let mut ready = [-1; 2];
    if minilib::pipe(ready.as_mut_ptr()) != 0 {
        return BlockingProbeResult::failed();
    }

    let child = minilib::fork();
    if child < 0 {
        let _ = minilib::close(ready[0]);
        let _ = minilib::close(ready[1]);
        return BlockingProbeResult::failed();
    }
    if child == 0 {
        let setup = minilib::close(ready[0]) == 0
            && minilib::write(ready[1], b"R") == 1
            && minilib::close(ready[1]) == 0;
        let delayed = setup && wait_probe_delay();
        minilib::exit(if delayed { 42 } else { 1 });
    }

    let setup = minilib::close(ready[1]) == 0;
    let mut ready_byte = [0; 1];
    let child_is_delaying =
        setup && minilib::read(ready[0], &mut ready_byte) == 1 && ready_byte == *b"R";
    let closed_ready = minilib::close(ready[0]) == 0;
    let mut status = 0;
    let observed_running =
        child_is_delaying && minilib::waitpid(child, &raw mut status, minilib::WNOHANG) == 0;
    let block_count_before = if observed_running {
        read_audit_counter(DEBUG_OP_GET_CHILD_WAIT_BLOCKS)
    } else {
        None
    };
    let reaped_child = minilib::waitpid(child, &raw mut status, 0) == child && status == 42 << 8;
    let block_count_after = if observed_running {
        read_audit_counter(DEBUG_OP_GET_CHILD_WAIT_BLOCKS)
    } else {
        None
    };

    BlockingProbeResult {
        functional: child_is_delaying && closed_ready && observed_running && reaped_child,
        blocked: counter_increased(block_count_before, block_count_after),
    }
}

fn child_exit_before_wait_probe() -> bool {
    let mut ready = [-1; 2];
    if minilib::pipe(ready.as_mut_ptr()) != 0 {
        return false;
    }

    let child = minilib::fork();
    if child < 0 {
        let _ = minilib::close(ready[0]);
        let _ = minilib::close(ready[1]);
        return false;
    }
    if child == 0 {
        let setup = minilib::close(ready[0]) == 0 && minilib::write(ready[1], b"R") == 1;
        // Leave the writer open. Process::mark_exited must publish the status
        // and close inherited descriptors before the parent can observe EOF.
        minilib::exit(if setup { 43 } else { 1 });
    }

    let setup = minilib::close(ready[1]) == 0;
    let mut ready_byte = [0; 1];
    let child_started =
        setup && minilib::read(ready[0], &mut ready_byte) == 1 && ready_byte == *b"R";
    let mut eof_probe = [0; 1];
    let exit_teardown_observed = child_started && minilib::read(ready[0], &mut eof_probe) == 0;
    let closed_ready = minilib::close(ready[0]) == 0;
    let mut status = 0;
    let reaped_without_blocking = exit_teardown_observed
        && minilib::waitpid(child, &raw mut status, minilib::WNOHANG) == child
        && status == 43 << 8;
    if !reaped_without_blocking {
        let _ = minilib::waitpid(child, &raw mut status, 0);
    }

    child_started && exit_teardown_observed && closed_ready && reaped_without_blocking
}

fn lifecycle_fault_wait_probe() -> bool {
    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        trigger_unmapped_load();
    }

    let mut status = 0;
    minilib::waitpid(child, &mut status, 0) == child && status == 139 << 8
}

fn lifecycle_exec_wait_probe() -> bool {
    static EXEC_PATH: &[u8] = b"/bin/fork_test\0";

    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        let rc = minilib::execve(EXEC_PATH.as_ptr(), core::ptr::null(), core::ptr::null());
        minilib::exit(if rc < 0 { 126 } else { 127 });
    }

    let mut status = 0;
    minilib::waitpid(child, &mut status, 0) == child && status == 0
}

fn lifecycle_exec_reject_probe() -> bool {
    static MISSING_PATH: &[u8] = b"/bin/does-not-exist\0";
    expect_errno(
        minilib::execve(MISSING_PATH.as_ptr(), core::ptr::null(), core::ptr::null()) as usize,
        kernel_abi::ENOENT,
    )
}

fn monotonic_time_ns() -> Option<u64> {
    let mut now = minilib::timespec::default();
    if minilib::clock_gettime(kernel_abi::CLOCK_MONOTONIC, &raw mut now) != 0
        || now.tv_sec < 0
        || now.tv_nsec < 0
        || now.tv_nsec >= 1_000_000_000
    {
        return None;
    }
    (now.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(now.tv_nsec as u64))
}

fn nanosleep_wait_queue_probe() -> bool {
    let zero = minilib::timespec::default();
    let before_zero = match monotonic_time_ns() {
        Some(now) => now,
        None => return false,
    };
    if minilib::nanosleep(&raw const zero, core::ptr::null_mut()) != 0
        || monotonic_time_ns().is_none_or(|after| after < before_zero)
    {
        return false;
    }

    let durations_ms = [300u64, 100, 200];
    let mut children = [0i32; 3];
    let batch_started = match monotonic_time_ns() {
        Some(now) => now,
        None => return false,
    };
    for (index, duration_ms) in durations_ms.into_iter().enumerate() {
        let child = minilib::fork();
        if child < 0 {
            return false;
        }
        if child == 0 {
            let started = monotonic_time_ns().unwrap_or(0);
            let request = minilib::timespec {
                tv_sec: 0,
                tv_nsec: (duration_ms * 1_000_000) as i64,
            };
            let slept = minilib::nanosleep(&raw const request, core::ptr::null_mut()) == 0;
            let elapsed = monotonic_time_ns().unwrap_or(0).saturating_sub(started);
            minilib::exit(if slept && elapsed >= duration_ms * 1_000_000 {
                0
            } else {
                120 + index as i32
            });
        }
        children[index] = child;
    }

    let expected_order = [children[1], children[2], children[0]];
    for expected in expected_order {
        let mut status = 0;
        if minilib::waitpid(-1, &raw mut status, 0) != expected || status != 0 {
            return false;
        }
    }
    let batch_elapsed = match monotonic_time_ns() {
        Some(now) => now.saturating_sub(batch_started),
        None => return false,
    };
    if batch_elapsed < 300_000_000 {
        return false;
    }
    write(1, b"NANOSLEEP_WAITQ_BENCH_NS=");
    print_num(batch_elapsed);
    write(1, b"\n");
    true
}

fn nanosleep_interrupt_probe() -> bool {
    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        let request = minilib::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let mut remaining = minilib::timespec::default();
        let result = minilib::nanosleep(&raw const request, &raw mut remaining);
        let remaining_ns = (remaining.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(remaining.tv_nsec as u64);
        minilib::exit(
            if result as isize == -isize::from(kernel_abi::EINTR)
                && remaining.tv_sec >= 0
                && remaining.tv_nsec >= 0
                && remaining.tv_nsec < 1_000_000_000
                && remaining_ns > 0
                && remaining_ns <= 5_000_000_000
            {
                0
            } else {
                124
            },
        );
    }

    let interrupt_started = monotonic_time_ns().unwrap_or(0);
    loop {
        let result = minilib::interrupt_sleep(child);
        if result == 0 {
            break;
        }
        if !expect_errno(result as usize, kernel_abi::EAGAIN)
            || monotonic_time_ns()
                .unwrap_or(u64::MAX)
                .saturating_sub(interrupt_started)
                > 2_000_000_000
        {
            return false;
        }
        minilib::pause();
    }

    let mut status = 0;
    minilib::waitpid(child, &raw mut status, 0) == child && status == 0
}

#[cfg(feature = "bpf-unsigned-development")]
fn bpf_owner_exit_probe() -> bool {
    #[repr(C)]
    struct BpfInsn {
        opcode: u8,
        regs: u8,
        offset: i16,
        imm: i32,
    }

    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        let map_attr = kernel_abi::BpfAttr {
            prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
            insn_cnt: 4,
            insns: 8 | (1u64 << 32),
            ..kernel_abi::BpfAttr::default()
        };
        let first_map = minilib::bpf(
            kernel_abi::BPF_MAP_CREATE as i32,
            (&raw const map_attr).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        );
        if first_map < 0 {
            minilib::exit(120);
        }
        let destroy_map = kernel_abi::BpfAttr {
            map_fd: first_map as u32,
            ..kernel_abi::BpfAttr::default()
        };
        if minilib::bpf(
            kernel_abi::BPF_MAP_DESTROY as i32,
            (&raw const destroy_map).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        ) != 0
        {
            minilib::exit(121);
        }
        let second_map = minilib::bpf(
            kernel_abi::BPF_MAP_CREATE as i32,
            (&raw const map_attr).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        );
        if second_map < 0
            || second_map == first_map
            || !expect_errno(
                minilib::bpf(
                    kernel_abi::BPF_MAP_DESTROY as i32,
                    (&raw const destroy_map).cast(),
                    core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
                ) as usize,
                kernel_abi::ENOENT,
            )
        {
            minilib::exit(122);
        }
        let insns = [
            BpfInsn {
                opcode: 0xb7,
                regs: 0,
                offset: 0,
                imm: 0,
            },
            BpfInsn {
                opcode: 0x95,
                regs: 0,
                offset: 0,
                imm: 0,
            },
        ];
        let program_attr = kernel_abi::BpfAttr {
            insn_cnt: insns.len() as u32,
            insns: insns.as_ptr() as u64,
            ..kernel_abi::BpfAttr::default()
        };
        let first_program = minilib::bpf(
            kernel_abi::BPF_PROG_LOAD as i32,
            (&raw const program_attr).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        );
        if first_program < 0 {
            minilib::exit(123);
        }
        let unload_program = kernel_abi::BpfAttr {
            attach_prog_fd: first_program as u32,
            ..kernel_abi::BpfAttr::default()
        };
        if minilib::bpf(
            kernel_abi::BPF_PROG_UNLOAD as i32,
            (&raw const unload_program).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        ) != 0
        {
            minilib::exit(124);
        }
        let second_program = minilib::bpf(
            kernel_abi::BPF_PROG_LOAD as i32,
            (&raw const program_attr).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        );
        if second_program < 0
            || second_program == first_program
            || !expect_errno(
                minilib::bpf(
                    kernel_abi::BPF_PROG_UNLOAD as i32,
                    (&raw const unload_program).cast(),
                    core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
                ) as usize,
                kernel_abi::ENOENT,
            )
        {
            minilib::exit(125);
        }
        minilib::exit(0);
    }

    let mut status = 0;
    minilib::waitpid(child, &mut status, 0) == child && status == 0
}

fn bpf_foreign_owner_probe() -> bool {
    let map_attr = kernel_abi::BpfAttr {
        prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
        insn_cnt: 4,
        insns: 8 | (1u64 << 32),
        ..kernel_abi::BpfAttr::default()
    };
    let map_id = minilib::bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        (&raw const map_attr).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    );
    if map_id < 0 {
        return false;
    }

    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        let key = 0u32;
        let mut value = 0u64;
        let lookup = kernel_abi::BpfAttr {
            map_fd: map_id as u32,
            key: (&raw const key) as u64,
            value: (&raw mut value) as u64,
            ..kernel_abi::BpfAttr::default()
        };
        let result = minilib::bpf(
            kernel_abi::BPF_MAP_LOOKUP_ELEM as i32,
            (&raw const lookup).cast(),
            core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
        );
        minilib::exit(if expect_errno(result as usize, kernel_abi::EPERM) {
            0
        } else {
            126
        });
    }

    let mut status = 0;
    let child_denied = minilib::waitpid(child, &mut status, 0) == child && status == 0;
    let destroy = kernel_abi::BpfAttr {
        map_fd: map_id as u32,
        ..kernel_abi::BpfAttr::default()
    };
    let destroyed = minilib::bpf(
        kernel_abi::BPF_MAP_DESTROY as i32,
        (&raw const destroy).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    ) == 0;
    child_denied && destroyed
}

#[cfg(feature = "bpf-unsigned-development")]
fn bpf_pinned_write_only_probe() -> bool {
    static PATH: &[u8] = b"/audit/write-only\0";
    let attr_size = core::mem::size_of::<kernel_abi::BpfAttr>() as i32;
    let map_attr = kernel_abi::BpfAttr {
        prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
        insn_cnt: 4,
        insns: 8 | (1u64 << 32),
        ..kernel_abi::BpfAttr::default()
    };
    let map_id = minilib::bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        (&raw const map_attr).cast(),
        attr_size,
    );
    if map_id < 0 {
        return false;
    }

    let pin = kernel_abi::BpfAttr {
        map_fd: map_id as u32,
        pathname: PATH.as_ptr() as u64,
        path_len: PATH.len() as u32,
        file_flags: kernel_abi::BPF_OBJ_ACCESS_WRITE,
        ..kernel_abi::BpfAttr::default()
    };
    if minilib::bpf(
        kernel_abi::BPF_OBJ_PIN as i32,
        (&raw const pin).cast(),
        attr_size,
    ) != 0
    {
        return false;
    }

    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        let open = kernel_abi::BpfAttr {
            pathname: PATH.as_ptr() as u64,
            path_len: PATH.len() as u32,
            file_flags: kernel_abi::BPF_OBJ_ACCESS_WRITE,
            ..kernel_abi::BpfAttr::default()
        };
        let foreign_map = minilib::bpf(
            kernel_abi::BPF_OBJ_GET as i32,
            (&raw const open).cast(),
            attr_size,
        );
        if foreign_map < 0 {
            minilib::exit(120);
        }

        let key = 0u32;
        let value = 7u64;
        let update = kernel_abi::BpfAttr {
            map_fd: foreign_map as u32,
            key: (&raw const key) as u64,
            value: (&raw const value) as u64,
            ..kernel_abi::BpfAttr::default()
        };
        if minilib::bpf(
            kernel_abi::BPF_MAP_UPDATE_ELEM as i32,
            (&raw const update).cast(),
            attr_size,
        ) != 0
        {
            minilib::exit(121);
        }

        let mut observed = 0u64;
        let lookup = kernel_abi::BpfAttr {
            map_fd: foreign_map as u32,
            key: (&raw const key) as u64,
            value: (&raw mut observed) as u64,
            ..kernel_abi::BpfAttr::default()
        };
        let denied = expect_errno(
            minilib::bpf(
                kernel_abi::BPF_MAP_LOOKUP_ELEM as i32,
                (&raw const lookup).cast(),
                attr_size,
            ) as usize,
            kernel_abi::EPERM,
        );
        minilib::exit(if denied { 0 } else { 122 });
    }

    let mut status = 0;
    let child_ok = minilib::waitpid(child, &mut status, 0) == child && status == 0;
    let unpin = kernel_abi::BpfAttr {
        pathname: PATH.as_ptr() as u64,
        path_len: PATH.len() as u32,
        ..kernel_abi::BpfAttr::default()
    };
    let unpinned = minilib::bpf(
        kernel_abi::BPF_OBJ_UNPIN as i32,
        (&raw const unpin).cast(),
        attr_size,
    ) == 0;
    let destroy = kernel_abi::BpfAttr {
        map_fd: map_id as u32,
        ..kernel_abi::BpfAttr::default()
    };
    let destroyed = minilib::bpf(
        kernel_abi::BPF_MAP_DESTROY as i32,
        (&raw const destroy).cast(),
        attr_size,
    ) == 0;

    child_ok && unpinned && destroyed
}

#[cfg(feature = "bpf-unsigned-development")]
fn bpf_capability_denial_probe() -> bool {
    let unprivileged_denied = run_restricted_bpf_probe(0, unprivileged_bpf_probe);
    if unprivileged_denied {
        write(1, b"BPF_UNPRIVILEGED_DENY_OK\n");
    }

    let tier_denied = run_restricted_bpf_probe(
        kernel_abi::BPF_CAP_PROGRAM_LOAD,
        unprivileged_verifier_tier_probe,
    );
    if tier_denied {
        write(1, b"BPF_UNPRIVILEGED_TIER_DENY_OK\n");
    }

    let attach_denied = run_restricted_bpf_probe(
        kernel_abi::BPF_CAP_PROGRAM_LOAD | kernel_abi::BPF_CAP_PRIVILEGED_VERIFY,
        unauthorized_attach_probe,
    );
    if attach_denied {
        write(1, b"BPF_ATTACH_DENY_OK\n");
    }

    unprivileged_denied && tier_denied && attach_denied
}

#[cfg(feature = "bpf-unsigned-development")]
fn run_restricted_bpf_probe(capabilities: u32, probe: fn() -> bool) -> bool {
    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        let retained = minilib::restrict_bpf_capabilities(capabilities);
        if retained < 0 || retained as u32 != capabilities {
            minilib::exit(126);
        }
        minilib::exit(if probe() { 0 } else { 125 });
    }

    let mut status = 0;
    minilib::waitpid(child, &mut status, 0) == child && status == 0
}

#[cfg(feature = "bpf-unsigned-development")]
fn unprivileged_bpf_probe() -> bool {
    let attr = kernel_abi::BpfAttr {
        prog_type: kernel_abi::BPF_MAP_TYPE_ARRAY,
        insn_cnt: 4,
        insns: 8 | (1u64 << 32),
        ..kernel_abi::BpfAttr::default()
    };
    let result = minilib::bpf(
        kernel_abi::BPF_MAP_CREATE as i32,
        (&raw const attr).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    );
    expect_errno(result as usize, kernel_abi::EPERM)
}

#[cfg(feature = "bpf-unsigned-development")]
fn unprivileged_verifier_tier_probe() -> bool {
    let instructions = [
        BpfInsn {
            code: 0x85,
            dst_src: 0,
            off: 0,
            imm: kernel_abi::BPF_HELPER_GET_KERNEL_HEAP_KB,
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
    let attr = kernel_abi::BpfAttr {
        prog_type: 1,
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        ..kernel_abi::BpfAttr::default()
    };
    let result = minilib::bpf(
        kernel_abi::BPF_PROG_LOAD as i32,
        (&raw const attr).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    );
    expect_errno(result as usize, kernel_abi::EINVAL)
}

#[cfg(feature = "bpf-unsigned-development")]
fn unauthorized_attach_probe() -> bool {
    let instructions = [
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
    let load = kernel_abi::BpfAttr {
        prog_type: 1,
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        ..kernel_abi::BpfAttr::default()
    };
    let program = minilib::bpf(
        kernel_abi::BPF_PROG_LOAD as i32,
        (&raw const load).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    );
    if program < 0 {
        return false;
    }

    let attach = kernel_abi::BpfAttr {
        attach_btf_id: kernel_abi::BPF_ATTACH_TYPE_TIMER,
        attach_prog_fd: program as u32,
        ..kernel_abi::BpfAttr::default()
    };
    let attach_result = minilib::bpf(
        kernel_abi::BPF_PROG_ATTACH as i32,
        (&raw const attach).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    );
    let unload = kernel_abi::BpfAttr {
        attach_prog_fd: program as u32,
        ..kernel_abi::BpfAttr::default()
    };
    let unload_result = minilib::bpf(
        kernel_abi::BPF_PROG_UNLOAD as i32,
        (&raw const unload).cast(),
        core::mem::size_of::<kernel_abi::BpfAttr>() as i32,
    );

    expect_errno(attach_result as usize, kernel_abi::EPERM) && unload_result == 0
}

fn trigger_unmapped_load() -> ! {
    let value: usize;
    // SAFETY: This is an intentional userspace fault probe. The kernel must
    // terminate only this forked child rather than panic or retry forever.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov {value}, qword ptr [{address}]",
            value = out(reg) value,
            address = in(reg) UNMAPPED_USER_ADDRESS,
            options(nostack, readonly)
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "ldr {value}, [{address}]",
            value = out(reg) value,
            address = in(reg) UNMAPPED_USER_ADDRESS,
            options(nostack, readonly)
        );
    }
    core::hint::black_box(value);
    minilib::exit(125)
}

fn usercopy_fault_probe() -> bool {
    let bad = UNMAPPED_USER_ADDRESS;

    [
        minilib::syscall3(kernel_abi::SYS_WRITE, 1, bad, 1),
        minilib::syscall3(kernel_abi::SYS_WRITEV, 1, bad, 1),
        minilib::syscall4(
            kernel_abi::SYS_OPEN,
            bad,
            1,
            kernel_abi::O_RDONLY as usize,
            0,
        ),
        minilib::syscall2(
            kernel_abi::SYS_CLOCK_GETTIME,
            kernel_abi::CLOCK_MONOTONIC as usize,
            bad,
        ),
        minilib::syscall2(kernel_abi::SYS_NANOSLEEP, bad, 0),
    ]
    .into_iter()
    .all(|result| expect_errno(result, kernel_abi::EFAULT))
}

fn expect_errno(result: usize, errno: kernel_abi::Errno) -> bool {
    result as isize == -isize::from(errno)
}

fn spawn_demo(path: &str, bpf_capabilities: u32) {
    write(1, b"Spawning ");
    write(1, path.as_bytes());
    write(1, b"...\n");

    let pid = minilib::spawn_restricted(path, bpf_capabilities);
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
