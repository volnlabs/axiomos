#![no_std]
#![no_main]

use core::panic::PanicInfo;

use minilib::{bpf, clock_gettime, exit, pause, timespec, write};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}

#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

const fn regs(dst: u8, src: u8) -> u8 {
    (src << 4) | (dst & 0x0f)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(1, b"\n");
    write(1, b"========================================\n");
    write(1, b"  AXIOM BENCHMARK RESULTS\n");
    write(1, b"========================================\n");
    write(1, b"\n");

    // Note: Boot time and memory footprint are printed by kernel during boot
    // We focus on BPF load time and timer interval measurements here

    let attr_size = core::mem::size_of::<kernel_abi::BpfAttr>() as i32;

    // ================================================================
    // Benchmark 1: BPF Program Load Time
    // ================================================================
    write(1, b"[Benchmark 1] BPF Program Load Time\n");
    write(1, b"Loading test program 10 times...\n");

    // Simple test program: just returns 42
    let test_insns = [
        BpfInsn {
            code: 0xb7,
            dst_src: regs(0, 0),
            off: 0,
            imm: 42,
        }, // r0 = 42
        BpfInsn {
            code: 0x95,
            dst_src: 0x00,
            off: 0,
            imm: 0,
        }, // exit
    ];

    let mut load_times_us = [0u64; 10];
    let mut min_us = u64::MAX;
    let mut max_us = 0u64;
    let mut total_us = 0u64;

    for (i, time) in load_times_us.iter_mut().enumerate() {
        let mut start = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        clock_gettime(kernel_abi::CLOCK_MONOTONIC, &mut start as *mut timespec);

        let load_attr = kernel_abi::BpfAttr {
            prog_type: 1,
            insn_cnt: test_insns.len() as u32,
            insns: test_insns.as_ptr() as u64,
            ..Default::default()
        };

        let prog_id = bpf(
            5, // BPF_PROG_LOAD
            &load_attr as *const kernel_abi::BpfAttr as *const u8,
            attr_size,
        );

        let mut end = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        clock_gettime(kernel_abi::CLOCK_MONOTONIC, &mut end as *mut timespec);

        if prog_id < 0 {
            write(1, b"  [ERROR] Load failed\n");
            exit(1);
        }

        // Calculate elapsed time in microseconds
        let elapsed_ns =
            (end.tv_sec - start.tv_sec) * 1_000_000_000 + (end.tv_nsec - start.tv_nsec);
        let elapsed_us = (elapsed_ns / 1000) as u64;

        *time = elapsed_us;
        if elapsed_us < min_us {
            min_us = elapsed_us;
        }
        if elapsed_us > max_us {
            max_us = elapsed_us;
        }
        total_us += elapsed_us;

        write(1, b"  Run ");
        print_num((i + 1) as u64);
        write(1, b": ");
        print_num(elapsed_us);
        write(1, b" us\n");
    }

    let avg_us = total_us / 10;

    write(1, b"\nBPF Load Time Summary:\n");
    write(1, b"  Min: ");
    print_num(min_us);
    write(1, b" us\n");
    write(1, b"  Max: ");
    print_num(max_us);
    write(1, b" us\n");
    write(1, b"  Avg: ");
    print_num(avg_us);
    write(1, b" us\n");
    write(1, b"\n");

    // ================================================================
    // Benchmark 2: Timer Interrupt Interval (via BPF)
    // ================================================================
    write(1, b"[Benchmark 2] Timer Interrupt Interval\n");
    write(1, b"Measuring via BPF program attached to timer...\n");

    // Create ringbuf for timestamp events
    let ringbuf_attr = kernel_abi::BpfAttr {
        prog_type: 27, // BPF_MAP_TYPE_RINGBUF
        insn_cnt: 0,
        insns: (4096u64) << 32,
        ..Default::default()
    };

    let ringbuf_map_id = bpf(0, &ringbuf_attr as *const _ as *const u8, attr_size);
    if ringbuf_map_id < 0 {
        write(1, b"  [ERROR] Failed to create ringbuf\n");
        exit(1);
    }

    // BPF program that writes timestamp, latency, boot time, heap, and image size to ringbuf
    //
    // Data format in ringbuf:
    // [u64 timestamp, u64 latency_ns, u64 boot_time_ms, u64 heap_kb, u64 image_mb] (40 bytes)
    let timer_insns = [
        // 1. Get timestamp (helper 1)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: 1,
        },
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 0),
            off: -40,
            imm: 0,
        }, // *(u64*)(r10-40) = r0
        // 2. Get interrupt latency (helper 13)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: 13,
        },
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 0),
            off: -32,
            imm: 0,
        }, // *(u64*)(r10-32) = r0
        // 3. Get boot time (helper 15)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: 15,
        },
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 0),
            off: -24,
            imm: 0,
        }, // *(u64*)(r10-24) = r0
        // 4. Get heap usage (helper 16)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: 16,
        },
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 0),
            off: -16,
            imm: 0,
        }, // *(u64*)(r10-16) = r0
        // 5. Get image size (helper 17)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: 17,
        },
        BpfInsn {
            code: 0x7b,
            dst_src: regs(10, 0),
            off: -8,
            imm: 0,
        }, // *(u64*)(r10-8) = r0
        // 6. Call bpf_ringbuf_output(map_id, &data, 40, 0)
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: ringbuf_map_id,
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
            imm: -40,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(3, 0),
            off: 0,
            imm: 40,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(4, 0),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: 8,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(0, 0),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x95,
            dst_src: 0x00,
            off: 0,
            imm: 0,
        },
    ];

    let timer_load_attr = kernel_abi::BpfAttr {
        prog_type: 1,
        insn_cnt: timer_insns.len() as u32,
        insns: timer_insns.as_ptr() as u64,
        ..Default::default()
    };

    let timer_prog_id = bpf(5, &timer_load_attr as *const _ as *const u8, attr_size);
    if timer_prog_id < 0 {
        write(1, b"  [ERROR] Failed to load timer program\n");
        exit(1);
    }

    // Attach to timer
    let attach_attr = kernel_abi::BpfAttr {
        attach_btf_id: 1, // ATTACH_TYPE_TIMER
        attach_prog_fd: timer_prog_id as u32,
        ..Default::default()
    };

    let attach_res = bpf(8, &attach_attr as *const _ as *const u8, attr_size);
    if attach_res != 0 {
        write(1, b"  [ERROR] Failed to attach timer program\n");
        exit(1);
    }

    write(1, b"  Collecting 100 timer samples...\n");

    let mut timestamps = [0u64; 100];
    let mut latencies = [0u64; 100];
    let mut boot_time_ms = 0u64;
    let mut kernel_heap_kb = 0u64;
    let mut kernel_image_mb = 0u64;
    let mut collected = 0;
    let mut buf = [0u8; 64];
    let mut poll_attempts: u32 = 0;
    let mut poll_errors: u32 = 0;
    let mut last_poll_res: i32 = 0;
    const MAX_POLLS: u32 = 5_000;
    const POLL_PAUSE_ITERS: u32 = 50_000;

    // Collect up to 100 timestamps with a bounded wait.
    while collected < 100 && poll_attempts < MAX_POLLS {
        let poll_attr = kernel_abi::BpfAttr {
            map_fd: ringbuf_map_id as u32,
            key: buf.as_mut_ptr() as u64,
            value: buf.len() as u64,
            ..Default::default()
        };

        let poll_res = bpf(37, &poll_attr as *const _ as *const u8, attr_size);
        last_poll_res = poll_res;

        if poll_res >= 40 {
            // Parse timestamp, latency, and kernel metrics
            let ts = u64::from_ne_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let lat = u64::from_ne_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            boot_time_ms = u64::from_ne_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]);
            kernel_heap_kb = u64::from_ne_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]);
            kernel_image_mb = u64::from_ne_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]);

            timestamps[collected] = ts;
            latencies[collected] = lat;
            collected += 1;
        } else if poll_res < 0 {
            poll_errors += 1;
        }

        poll_attempts += 1;
        for _ in 0..POLL_PAUSE_ITERS {
            pause();
        }
    }

    if collected < 100 {
        write(1, b"  [WARN] Timer sample collection incomplete\n");
        write(1, b"  Collected: ");
        print_num(collected as u64);
        write(1, b"/100\n");
        write(1, b"  Poll attempts: ");
        print_num(poll_attempts as u64);
        write(1, b"\n");
        write(1, b"  Poll errors: ");
        print_num(poll_errors as u64);
        write(1, b"\n");
        write(1, b"  Last poll result: ");
        print_i32(last_poll_res);
        write(1, b"\n\n");
    }

    if collected < 2 {
        write(
            1,
            b"  [ERROR] Not enough timer samples for interval stats\n",
        );
        exit(1);
    }

    // Calculate intervals between consecutive timestamps
    let interval_count = collected - 1;
    let mut min_interval_us = u64::MAX;
    let mut max_interval_us = 0u64;
    let mut total_interval_us = 0u64;

    for i in 0..interval_count {
        let interval_ns = timestamps[i + 1].saturating_sub(timestamps[i]);
        let interval_us = interval_ns / 1000;
        if interval_us < min_interval_us {
            min_interval_us = interval_us;
        }
        if interval_us > max_interval_us {
            max_interval_us = interval_us;
        }
        total_interval_us += interval_us;
    }

    let avg_interval_us = total_interval_us / interval_count as u64;

    // Calculate latency stats
    let mut min_latency_ns = u64::MAX;
    let mut max_latency_ns = 0u64;
    let mut total_latency_ns = 0u64;

    for &lat in latencies.iter().take(collected) {
        if lat < min_latency_ns {
            min_latency_ns = lat;
        }
        if lat > max_latency_ns {
            max_latency_ns = lat;
        }
        total_latency_ns += lat;
    }
    let avg_latency_ns = total_latency_ns / collected as u64;

    write(1, b"\nTimer Interrupt Interval Summary:\n");
    write(1, b"  Samples: ");
    print_num(collected as u64);
    write(1, b"\n");
    write(1, b"  Min: ");
    print_num(min_interval_us);
    write(1, b" us\n");
    write(1, b"  Max: ");
    print_num(max_interval_us);
    write(1, b" us\n");
    write(1, b"  Avg: ");
    print_num(avg_interval_us);
    write(1, b" us\n");

    write(1, b"\nInterrupt Latency Summary (Hardware to BPF):\n");
    write(1, b"  Min: ");
    print_num(min_latency_ns);
    write(1, b" ns\n");
    write(1, b"  Max: ");
    print_num(max_latency_ns);
    write(1, b" ns\n");
    write(1, b"  Avg: ");
    print_num(avg_latency_ns);
    write(1, b" ns\n");
    write(1, b"\n");

    // ================================================================
    // Summary Table
    // ================================================================
    write(1, b"========================================\n");
    write(1, b"  BENCHMARK SUMMARY\n");
    write(1, b"========================================\n");
    write(1, b"Boot to init:        ");
    print_num(boot_time_ms);
    write(1, b" ms\n");
    write(1, b"Kernel heap:         ");
    print_num(kernel_heap_kb);
    write(1, b" KB\n");
    write(1, b"Kernel image:        ");
    print_num(kernel_image_mb);
    write(1, b" MB\n");
    write(1, b"BPF load time:       ");
    print_num(avg_us);
    write(1, b" us (avg of 10)\n");
    write(1, b"Timer interval:      ");
    print_num(avg_interval_us);
    write(1, b" us (avg of ");
    print_num(interval_count as u64);
    write(1, b")\n");
    write(1, b"Interrupt latency:   ");
    print_num(avg_latency_ns);
    write(1, b" ns (avg of ");
    print_num(collected as u64);
    write(1, b")\n");
    write(1, b"========================================\n");
    write(1, b"\n");

    exit(0);
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

fn print_i32(n: i32) {
    if n < 0 {
        write(1, b"-");
        print_num((-n) as u64);
    } else {
        print_num(n as u64);
    }
}
