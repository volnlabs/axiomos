#![no_std]
#![no_main]

use kernel_abi::{
    BpfAttr, BPF_ATTACH_TYPE_PWM as ATTACH_TYPE_PWM, BPF_ATTACH_TYPE_TIMER as ATTACH_TYPE_TIMER,
    BPF_HELPER_KTIME_GET_NS as HELPER_KTIME_GET_NS, BPF_HELPER_PWM_WRITE as HELPER_PWM_WRITE,
    BPF_HELPER_RINGBUF_OUTPUT as HELPER_RINGBUF_OUTPUT, BPF_MAP_TYPE_RINGBUF as MAP_TYPE_RINGBUF,
};
use minilib::{bpf, exit, write};

// BPF commands
const BPF_MAP_CREATE: i32 = kernel_abi::BPF_MAP_CREATE as i32;
const BPF_PROG_LOAD: i32 = kernel_abi::BPF_PROG_LOAD as i32;
const BPF_PROG_ATTACH: i32 = kernel_abi::BPF_PROG_ATTACH as i32;
const BPF_RINGBUF_POLL: i32 = kernel_abi::BPF_RINGBUF_POLL as i32;

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

    const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self {
            code: 0x07,
            dst_src: dst,
            off: 0,
            imm,
        }
    }

    /// Load 32-bit from memory: dst = *(u32*)(src + off)
    const fn ldx_w(dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: 0x61,
            dst_src: (src << 4) | dst,
            off,
            imm: 0,
        }
    }

    /// Load 64-bit from memory: dst = *(u64*)(src + off)
    const fn ldx_dw(dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: 0x79,
            dst_src: (src << 4) | dst,
            off,
            imm: 0,
        }
    }

    /// Store 32-bit register to memory: *(u32*)(dst + off) = src
    const fn stx_w(dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: 0x63,
            dst_src: (src << 4) | dst,
            off,
            imm: 0,
        }
    }

    /// Store 64-bit register to memory: *(u64*)(dst + off) = src
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

/// Ringbuf event structure (20 bytes):
///   timestamp: u64  (offset 0)
///   channel:   u32  (offset 8)
///   duty_ns:   u32  (offset 12)
///   period_ns: u32  (offset 16)
const TRACE_EVENT_SIZE: usize = 20;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== PWM Tracing Demo ===\n");
    print("BPF-based PWM event tracing with nanosecond timestamps\n\n");

    // ---------------------------------------------------------
    // 1. Create ringbuf map for event tracing
    // ---------------------------------------------------------
    print("Creating ringbuf map...\n");

    // map_type=27 (RINGBUF), key_size=0, value_size=0, max_entries=4096 (buffer size)
    let map_attr = BpfAttr {
        prog_type: MAP_TYPE_RINGBUF, // map_type
        insn_cnt: 0,                 // key_size (unused for ringbuf)
        insns: 4096u64 << 32,        // value_size=0, max_entries=4096
        ..Default::default()
    };

    let map_id = bpf(
        BPF_MAP_CREATE,
        &map_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if map_id < 0 {
        print("Error: Failed to create ringbuf map\n");
        exit(1);
    }
    print("Ringbuf map created, ID: ");
    print_num(map_id as u64);
    print("\n");

    // ---------------------------------------------------------
    // 2. Load PWM Observer Program (traces events to ringbuf)
    // ---------------------------------------------------------
    print("Loading PWM Observer program...\n");

    // PwmEvent context layout (passed in R1):
    //   offset 0:  timestamp (u64)
    //   offset 8:  chip_id (u32)
    //   offset 12: channel (u32)
    //   offset 16: period_ns (u32)
    //   offset 20: duty_ns (u32)
    //   offset 24: polarity (u32)
    //   offset 28: enabled (u32)
    //
    // Observer builds a TraceEvent on stack and outputs via ringbuf:
    //   stack[-24..-16]: timestamp (u64)
    //   stack[-16..-12]: channel (u32)
    //   stack[-12..-8]:  duty_ns (u32)
    //   stack[-8..-4]:   period_ns (u32)
    //   stack[-4..0]:    padding (u32) - for alignment
    //
    // We use 20 bytes of meaningful data at stack[-24..-4].

    let observer_insns = [
        // R6 = R1 (save context pointer)
        BpfInsn::mov64_reg(6, 1),
        // Load timestamp from context: R7 = *(u64*)(R6 + 0)
        BpfInsn::ldx_dw(7, 6, 0),
        // Store timestamp to stack: *(u64*)(R10 - 24) = R7
        BpfInsn::stx_dw(10, 7, -24),
        // Load channel from context: R7 = *(u32*)(R6 + 12)
        BpfInsn::ldx_w(7, 6, 12),
        // Store channel to stack: *(u32*)(R10 - 16) = R7
        BpfInsn::stx_w(10, 7, -16),
        // Load duty_ns from context: R7 = *(u32*)(R6 + 20)
        BpfInsn::ldx_w(7, 6, 20),
        // Store duty_ns to stack: *(u32*)(R10 - 12) = R7
        BpfInsn::stx_w(10, 7, -12),
        // Load period_ns from context: R7 = *(u32*)(R6 + 16)
        BpfInsn::ldx_w(7, 6, 16),
        // Store period_ns to stack: *(u32*)(R10 - 8) = R7
        BpfInsn::stx_w(10, 7, -8),
        // Call bpf_ringbuf_output(map_id, data_ptr, data_size, flags)
        // R1 = map_id
        BpfInsn::mov64_imm(1, map_id),
        // R2 = R10 - 24 (pointer to event data on stack)
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::add64_imm(2, -24),
        // R3 = 20 (event size: 8 + 4 + 4 + 4 = 20 bytes)
        BpfInsn::mov64_imm(3, TRACE_EVENT_SIZE as i32),
        // R4 = 0 (flags)
        BpfInsn::mov64_imm(4, 0),
        // call bpf_ringbuf_output
        BpfInsn::call(HELPER_RINGBUF_OUTPUT),
        // Return 0
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ];

    let load_attr = BpfAttr {
        prog_type: 1,
        insn_cnt: observer_insns.len() as u32,
        insns: observer_insns.as_ptr() as u64,
        ..Default::default()
    };

    let obs_id = bpf(
        BPF_PROG_LOAD,
        &load_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if obs_id < 0 {
        print("Error: Failed to load observer\n");
        exit(1);
    }
    print("Observer loaded, ID: ");
    print_num(obs_id as u64);
    print("\n");

    // ---------------------------------------------------------
    // 3. Attach Observer to PWM
    // ---------------------------------------------------------
    print("Attaching Observer to PWM0 Channel 1...\n");
    let attach_attr = BpfAttr {
        attach_btf_id: ATTACH_TYPE_PWM,
        attach_prog_fd: obs_id as u32,
        key: 0,   // Chip 0
        value: 1, // Channel 1
        ..Default::default()
    };
    let res = bpf(
        BPF_PROG_ATTACH,
        &attach_attr as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if res < 0 {
        print("Error: Failed to attach observer\n");
        exit(1);
    }
    print("Observer attached to PWM0:1\n");

    // ---------------------------------------------------------
    // 4. Load Controller Program (Timer-driven duty cycle changes)
    // ---------------------------------------------------------
    print("Loading Controller program...\n");

    // Controller: called on timer tick, varies PWM duty cycle
    // Uses ktime_get_ns masked to 0-100 range for duty %
    let ctrl_insns = [
        // R0 = bpf_ktime_get_ns()
        BpfInsn::call(HELPER_KTIME_GET_NS),
        // R1 = R0
        BpfInsn::mov64_reg(1, 0),
        // R1 = R1 & 127 (mask to 0-127 range)
        BpfInsn {
            code: 0x47,
            dst_src: 0x01,
            off: 0,
            imm: 127,
        }, // AND64 R1, 127
        // If R1 > 100, R1 = 100
        BpfInsn {
            code: 0x25,
            dst_src: 0x01,
            off: 1,
            imm: 100,
        }, // JGT R1, 100, +1
        BpfInsn {
            code: 0x05,
            dst_src: 0,
            off: 1,
            imm: 0,
        }, // JA +1
        BpfInsn::mov64_imm(1, 100),
        // R3 = R1 (duty %)
        BpfInsn::mov64_reg(3, 1),
        // R1 = 0 (PWM Chip)
        BpfInsn::mov64_imm(1, 0),
        // R2 = 1 (Channel)
        BpfInsn::mov64_imm(2, 1),
        // Call bpf_pwm_write(0, 1, duty)
        BpfInsn::call(HELPER_PWM_WRITE),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ];

    let load_ctrl = BpfAttr {
        prog_type: 1,
        insn_cnt: ctrl_insns.len() as u32,
        insns: ctrl_insns.as_ptr() as u64,
        ..Default::default()
    };

    let ctrl_id = bpf(
        BPF_PROG_LOAD,
        &load_ctrl as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if ctrl_id < 0 {
        print("Error: Failed to load controller\n");
        exit(1);
    }
    print("Controller loaded, ID: ");
    print_num(ctrl_id as u64);
    print("\n");

    // ---------------------------------------------------------
    // 5. Attach Controller to Timer
    // ---------------------------------------------------------
    print("Attaching Controller to Timer...\n");
    let attach_ctrl = BpfAttr {
        attach_btf_id: ATTACH_TYPE_TIMER,
        attach_prog_fd: ctrl_id as u32,
        ..Default::default()
    };
    let res = bpf(
        BPF_PROG_ATTACH,
        &attach_ctrl as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if res < 0 {
        print("Error: Failed to attach controller\n");
        exit(1);
    }
    print("Controller attached to Timer\n\n");

    // ---------------------------------------------------------
    // 6. Event polling loop: read ringbuf and print trace events
    // ---------------------------------------------------------
    print("Polling for PWM trace events...\n\n");

    // Buffer to receive ringbuf events (>= TRACE_EVENT_SIZE)
    let mut event_buf = [0u8; 32];
    let mut event_count: u64 = 0;

    loop {
        // Poll ringbuf: sys_bpf(BPF_RINGBUF_POLL, attr)
        // attr.map_fd = map_id, attr.key = buf_ptr, attr.value = buf_size
        let poll_attr = BpfAttr {
            map_fd: map_id as u32,
            key: event_buf.as_mut_ptr() as u64,
            value: event_buf.len() as u64,
            ..Default::default()
        };

        let n = bpf(
            BPF_RINGBUF_POLL,
            &poll_attr as *const _ as *const u8,
            core::mem::size_of::<BpfAttr>() as i32,
        );

        if n >= TRACE_EVENT_SIZE as i32 {
            // Parse the event: timestamp(u64), channel(u32), duty_ns(u32), period_ns(u32)
            let timestamp = u64::from_le_bytes([
                event_buf[0],
                event_buf[1],
                event_buf[2],
                event_buf[3],
                event_buf[4],
                event_buf[5],
                event_buf[6],
                event_buf[7],
            ]);
            let channel =
                u32::from_le_bytes([event_buf[8], event_buf[9], event_buf[10], event_buf[11]]);
            let duty_ns =
                u32::from_le_bytes([event_buf[12], event_buf[13], event_buf[14], event_buf[15]]);
            let period_ns =
                u32::from_le_bytes([event_buf[16], event_buf[17], event_buf[18], event_buf[19]]);

            // Calculate duty percentage
            let duty_pct = if period_ns > 0 {
                (duty_ns as u64 * 100) / period_ns as u64
            } else {
                0
            };

            event_count += 1;

            // Print: "PWM [ch] duty=[X]% ([duty_ns]ns/[period_ns]ns) at t=[timestamp]ns"
            print("[");
            print_num(event_count);
            print("] PWM ch=");
            print_num(channel as u64);
            print(" duty=");
            print_num(duty_pct);
            print("% (");
            print_num(duty_ns as u64);
            print("ns/");
            print_num(period_ns as u64);
            print("ns) at t=");
            print_num(timestamp);
            print("ns\n");
        } else {
            // No event available, sleep briefly to avoid busy-spinning
            minilib::msleep(100);
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
