// Axiom-side forwarder. Polls the pinned sched_switch ring buffer and emits
// newline-delimited JSON lines to stdout (which is the UART when run from
// init on Pi5). Host-side `rk_bridge --input` consumes the same stream and
// publishes to ROS2.
//
// Wire format: see docs/rk_bridge_protocol.md.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use kernel_abi::{BpfAttr, BPF_OBJ_GET, BPF_RINGBUF_POLL};
use minilib::{bpf, exit, msleep, write};

const PINNED_RINGBUF_PATH: &[u8] = b"/sys/fs/bpf/maps/sched_switch_events\0";
const SCHED_SWITCH_EVENT_BYTES: usize = 40;
const POLL_BUF_BYTES: usize = 64;
const PROTOCOL_VERSION: u32 = 1;

#[repr(C)]
struct SchedSwitchEvent {
    cpu_id: u64,
    prev_pid: u64,
    prev_tid: u64,
    next_pid: u64,
    next_tid: u64,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    emit_banner();

    let map_fd = match open_pinned_ringbuf() {
        Some(fd) => fd,
        None => {
            write(
                2,
                b"rk_uart_forwarder: BPF_OBJ_GET failed; run sched_switch_export_demo first\n",
            );
            exit(1);
        }
    };

    emit_ready(map_fd);

    let attr_size = core::mem::size_of::<BpfAttr>() as i32;
    let mut buf = [0u8; POLL_BUF_BYTES];
    let mut seen: u64 = 0;

    loop {
        let attr = BpfAttr {
            map_fd: map_fd as u32,
            key: buf.as_mut_ptr() as u64,
            value: buf.len() as u64,
            ..Default::default()
        };

        let rc = bpf(
            BPF_RINGBUF_POLL as i32,
            &attr as *const BpfAttr as *const u8,
            attr_size,
        );

        if rc as usize >= SCHED_SWITCH_EVENT_BYTES {
            let event = decode_sched_switch(&buf);
            seen += 1;
            emit_sched_switch(seen, &event);
        } else if rc < 0 {
            write(2, b"rk_uart_forwarder: ringbuf poll failed\n");
            exit(1);
        } else {
            // No events ready. Backing off avoids hot-spinning on the syscall.
            msleep(10);
        }
    }
}

fn open_pinned_ringbuf() -> Option<i32> {
    let attr = BpfAttr {
        pathname: PINNED_RINGBUF_PATH.as_ptr() as u64,
        path_len: PINNED_RINGBUF_PATH.len() as u32,
        ..Default::default()
    };
    let rc = bpf(
        BPF_OBJ_GET as i32,
        &attr as *const BpfAttr as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if rc < 0 {
        None
    } else {
        Some(rc)
    }
}

fn decode_sched_switch(buf: &[u8; POLL_BUF_BYTES]) -> SchedSwitchEvent {
    SchedSwitchEvent {
        cpu_id: read_u64(buf, 0),
        prev_pid: read_u64(buf, 8),
        prev_tid: read_u64(buf, 16),
        next_pid: read_u64(buf, 24),
        next_tid: read_u64(buf, 32),
    }
}

fn read_u64(buf: &[u8; POLL_BUF_BYTES], offset: usize) -> u64 {
    u64::from_ne_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

fn emit_banner() {
    // Sentinel line marks the start of the forwarder stream so a host-side
    // consumer can discard any preceding kernel/init log noise on the same
    // UART before the JSON stream begins.
    write(1, b"\n--- rk_uart_forwarder begin ---\n");
    write(1, b"{\"type\":\"meta\",\"protocol\":");
    write_u64(PROTOCOL_VERSION as u64);
    write(1, b",\"source\":\"sched_switch\"}\n");
}

fn emit_ready(map_fd: i32) {
    write(1, b"{\"type\":\"ready\",\"map_fd\":");
    write_u64(map_fd as u64);
    write(1, b"}\n");
}

fn emit_sched_switch(seq: u64, event: &SchedSwitchEvent) {
    write(1, b"{\"type\":\"sched_switch\",\"seq\":");
    write_u64(seq);
    write(1, b",\"cpu\":");
    write_u64(event.cpu_id);
    write(1, b",\"prev_pid\":");
    write_u64(event.prev_pid);
    write(1, b",\"prev_tid\":");
    write_u64(event.prev_tid);
    write(1, b",\"next_pid\":");
    write_u64(event.next_pid);
    write(1, b",\"next_tid\":");
    write_u64(event.next_tid);
    write(1, b"}\n");
}

fn write_u64(mut n: u64) {
    if n == 0 {
        write(1, b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0usize;
    while j < i / 2 {
        buf.swap(j, i - 1 - j);
        j += 1;
    }
    write(1, &buf[..i]);
}
