#![no_std]
#![no_main]

use core::panic::PanicInfo;

use kernel_abi::{BpfAttr, BPF_MAP_CREATE, BPF_OBJ_PIN, BPF_PROG_ATTACH, BPF_PROG_LOAD};
use minilib::{bpf, exit, write};

const BPF_MAP_TYPE_RINGBUF: u32 = 27;
const HELPER_RINGBUF_OUTPUT: i32 = 8;
const ATTACH_TYPE_SCHED_SWITCH: u32 = 7;
const SCHED_SWITCH_CONTEXT_SIZE: usize = 40;
const PINNED_RINGBUF_PATH: &[u8] = b"/sys/fs/bpf/maps/sched_switch_events\0";

#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write(1, b"\n========================================\n");
    write(1, b"  Axiom sched_switch Export Demo\n");
    write(1, b"  Runtime attach + pinned object export\n");
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

    write(1, b"[4/4] Pinning ringbuf map object... ");
    let pin_attr = BpfAttr {
        map_fd: ringbuf_map_id as u32,
        pathname: PINNED_RINGBUF_PATH.as_ptr() as u64,
        path_len: PINNED_RINGBUF_PATH.len() as u32,
        ..Default::default()
    };
    let pin_res = bpf(
        BPF_OBJ_PIN as i32,
        &pin_attr as *const BpfAttr as *const u8,
        attr_size,
    );
    if pin_res != 0 {
        write(1, b"FAILED\n");
        exit(1);
    }
    write(1, b"OK\n\n");

    write(1, b"Next step:\n");
    write(
        1,
        b"  run /bin/sched_switch_bridge_demo to consume the pinned object\n",
    );
    write(
        1,
        b"  this process can now exit; hook and pinned map stay live in-kernel\n",
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

const fn regs(dst: u8, src: u8) -> u8 {
    (src << 4) | (dst & 0x0f)
}

fn print_num(mut n: u64) {
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
