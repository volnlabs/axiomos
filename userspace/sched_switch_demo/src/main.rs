#![no_std]
#![no_main]

use core::panic::PanicInfo;

use kernel_abi::{BpfAttr, BPF_MAP_CREATE, BPF_PROG_ATTACH, BPF_PROG_LOAD, BPF_RINGBUF_POLL};
use minilib::{bpf, exit, msleep, spawn, write};

const BPF_MAP_TYPE_RINGBUF: u32 = 27;
const HELPER_RINGBUF_OUTPUT: i32 = 8;
const ATTACH_TYPE_SCHED_SWITCH: u32 = 7;

const SCHED_SWITCH_CONTEXT_SIZE: usize = 40;

#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

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
    write(1, b"\n========================================\n");
    write(1, b"  Axiom sched_switch Hook Demo\n");
    write(1, b"  Live scheduler hook -> ringbuf -> userspace\n");
    write(1, b"========================================\n\n");

    let attr_size = core::mem::size_of::<BpfAttr>() as i32;

    write(1, b"[1/4] Creating ringbuf map... ");
    let ringbuf_attr = BpfAttr {
        prog_type: BPF_MAP_TYPE_RINGBUF,
        insn_cnt: 0,
        insns: (4096u64) << 32,
        ..Default::default()
    };
    let ringbuf_map_id = bpf(
        BPF_MAP_CREATE as i32,
        &ringbuf_attr as *const BpfAttr as *const u8,
        attr_size,
    );
    if ringbuf_map_id < 0 {
        write(1, b"FAILED\n");
        exit(1);
    }
    write(1, b"OK (id=");
    print_num(ringbuf_map_id as u64);
    write(1, b")\n");

    write(1, b"[2/4] Loading sched_switch trace program... ");
    let insns = build_program(ringbuf_map_id);
    let load_attr = BpfAttr {
        prog_type: 1,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        ..Default::default()
    };
    let prog_id = bpf(
        BPF_PROG_LOAD as i32,
        &load_attr as *const BpfAttr as *const u8,
        attr_size,
    );
    if prog_id < 0 {
        write(1, b"FAILED\n");
        exit(1);
    }
    write(1, b"OK (id=");
    print_num(prog_id as u64);
    write(1, b")\n");

    write(1, b"[3/4] Attaching to sched_switch... ");
    let attach_attr = BpfAttr {
        attach_btf_id: ATTACH_TYPE_SCHED_SWITCH,
        attach_prog_fd: prog_id as u32,
        ..Default::default()
    };
    let attach_res = bpf(
        BPF_PROG_ATTACH as i32,
        &attach_attr as *const BpfAttr as *const u8,
        attr_size,
    );
    if attach_res != 0 {
        write(1, b"FAILED\n");
        exit(1);
    }
    write(1, b"OK\n");

    write(
        1,
        b"[4/4] Launching workload, then collecting scheduler events...\n",
    );
    launch_workload("/bin/fork_test");
    msleep(50);
    launch_workload("/bin/fork_test");
    msleep(50);
    launch_workload("/bin/syscall_demo");
    msleep(150);

    write(1, b"\nCollecting sched_switch events...\n");

    let mut ringbuf_buf = [0u8; 64];
    let mut seen = 0u32;
    let mut polls = 0u32;
    const MAX_POLLS: u32 = 120;
    while polls < MAX_POLLS && seen < 12 {
        polls += 1;
        let poll_attr = BpfAttr {
            map_fd: ringbuf_map_id as u32,
            key: ringbuf_buf.as_mut_ptr() as u64,
            value: ringbuf_buf.len() as u64,
            ..Default::default()
        };
        let poll_res = bpf(
            BPF_RINGBUF_POLL as i32,
            &poll_attr as *const BpfAttr as *const u8,
            attr_size,
        );

        if poll_res as usize >= SCHED_SWITCH_CONTEXT_SIZE {
            let event = parse_event(&ringbuf_buf);
            seen += 1;
            write(1, b"  Event #");
            print_num(seen as u64);
            write(1, b": cpu=");
            print_num(event.cpu_id);
            write(1, b" prev(pid=");
            print_num(event.prev_pid);
            write(1, b", tid=");
            print_num(event.prev_tid);
            write(1, b") -> next(pid=");
            print_num(event.next_pid);
            write(1, b", tid=");
            print_num(event.next_tid);
            write(1, b")\n");
        } else if poll_res < 0 {
            write(1, b"  ringbuf poll failed\n");
            exit(1);
        } else {
            msleep(25);
        }
    }

    write(1, b"\nPoll summary: polls=");
    print_num(polls as u64);
    write(1, b" events=");
    print_num(seen as u64);
    write(1, b"\n");

    if seen == 0 {
        write(1, b"No sched_switch events received before timeout.\n");
        exit(2);
    }

    write(
        1,
        b"Pipeline proven: runtime attach -> sched_switch -> ringbuf -> userspace\n",
    );
    exit(0);
}

fn build_program(ringbuf_map_id: i32) -> [BpfInsn; 9] {
    [
        BpfInsn {
            code: 0xbf,
            dst_src: regs(6, 1),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x79,
            dst_src: regs(6, 1),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(1, 0),
            off: 0,
            imm: ringbuf_map_id,
        },
        BpfInsn {
            code: 0xbf,
            dst_src: regs(2, 6),
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0xb7,
            dst_src: regs(3, 0),
            off: 0,
            imm: SCHED_SWITCH_CONTEXT_SIZE as i32,
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
            imm: HELPER_RINGBUF_OUTPUT,
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
    ]
}

fn launch_workload(path: &str) {
    write(1, b"  launch ");
    write(1, path.as_bytes());
    write(1, b" -> pid=");
    let pid = spawn(path);
    if pid < 0 {
        print_i32(pid);
        write(1, b" (spawn failed)\n");
        exit(1);
    }

    print_i32(pid);
    write(1, b"\n");
}

const fn regs(dst: u8, src: u8) -> u8 {
    (src << 4) | (dst & 0x0f)
}

fn parse_event(buf: &[u8; 64]) -> SchedSwitchEvent {
    let cpu_id = u64::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let prev_pid = u64::from_ne_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let prev_tid = u64::from_ne_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    let next_pid = u64::from_ne_bytes([
        buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
    ]);
    let next_tid = u64::from_ne_bytes([
        buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
    ]);
    SchedSwitchEvent {
        cpu_id,
        prev_pid,
        prev_tid,
        next_pid,
        next_tid,
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
    reverse(&mut buf, i);
    write(1, &buf[..i]);
}

fn print_i32(n: i32) {
    if n < 0 {
        write(1, b"-");
        print_num(n.wrapping_neg() as u64);
    } else {
        print_num(n as u64);
    }
}

fn reverse(buf: &mut [u8; 20], len: usize) {
    let mut i = 0;
    while i < len / 2 {
        buf.swap(i, len - 1 - i);
        i += 1;
    }
}
