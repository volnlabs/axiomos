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

    if lifecycle_exit_wait_probe() {
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

    write(1, b"=== Axiom eBPF Init ===\n");
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

fn lifecycle_exit_wait_probe() -> bool {
    let child = minilib::fork();
    if child < 0 {
        return false;
    }
    if child == 0 {
        minilib::exit(42);
    }

    let mut status = 0;
    minilib::waitpid(child, &mut status, 0) == child && status == 42 << 8
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
            prog_type: 2,
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
        prog_type: 2,
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
        prog_type: 2,
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
        prog_type: 2,
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
            imm: 16,
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
        attach_btf_id: 1,
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
