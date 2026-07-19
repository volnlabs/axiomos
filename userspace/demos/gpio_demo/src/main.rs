#![no_std]
#![no_main]

use kernel_abi::{
    BpfAttr, BPF_HELPER_GPIO_GET as HELPER_GPIO_READ, BPF_HELPER_GPIO_SET as HELPER_GPIO_WRITE,
};
use minilib::{bpf, exit, write};

// Hardcoded for RPi5 GPIO demo
const BUTTON_PIN: u32 = 17;
const LED_PIN: u32 = 18;

#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

// SAFETY: Entry point for the GPIO demo. Called by the startup code.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== GPIO Interactivity Demo ===\n");
    print("Setting up BPF program for Button (GPIO 17) -> LED (GPIO 18)\n");

    // 1. Define BPF Program
    // Logic:
    //   - Read event context (R1 = GpioEvent*)
    //   - Load 'line' field (offset 12)
    //   - If line != BUTTON_PIN, exit
    //   - Read current LED state
    //   - Toggle state
    //   - Write new LED state

    #[allow(clippy::identity_op)]
    let insns = [
        // R6 = R1 (Save context pointer)
        BpfInsn {
            code: 0xbf,
            dst_src: 0x61,
            off: 0,
            imm: 0,
        },
        // R2 = *(u32 *)(R6 + 12)  // Load 'line' from GpioEvent
        BpfInsn {
            code: 0x61,
            dst_src: 0x26,
            off: 12,
            imm: 0,
        },
        // If R2 != BUTTON_PIN, goto EXIT (skip next 7 instructions)
        BpfInsn {
            code: 0x55,
            dst_src: 0x02,
            off: 7,
            imm: BUTTON_PIN as i32,
        },
        // --- Button Pressed Logic ---

        // R1 = LED_PIN
        BpfInsn {
            code: 0xb7,
            dst_src: 0x01,
            off: 0,
            imm: LED_PIN as i32,
        },
        // Call bpf_gpio_read(R1) -> R0
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: HELPER_GPIO_READ,
        },
        // Calculate toggle: R2 = (R0 == 0) ? 1 : 0
        // We'll use a trick or simple branching. Let's use branching.
        // If R0 != 0, goto SET_LOW (skip 1)
        BpfInsn {
            code: 0x55,
            dst_src: 0x00,
            off: 1,
            imm: 0,
        },
        // R2 = 1 (was 0, set to 1)
        BpfInsn {
            code: 0xb7,
            dst_src: 0x02,
            off: 0,
            imm: 1,
        },
        // Goto WRITE (skip 1)
        BpfInsn {
            code: 0x05,
            dst_src: 0x00,
            off: 1,
            imm: 0,
        },
        // SET_LOW: R2 = 0
        BpfInsn {
            code: 0xb7,
            dst_src: 0x02,
            off: 0,
            imm: 0,
        },
        // WRITE:
        // R1 = LED_PIN
        BpfInsn {
            code: 0xb7,
            dst_src: 0x01,
            off: 0,
            imm: LED_PIN as i32,
        },
        // Call bpf_gpio_write(R1, R2)
        BpfInsn {
            code: 0x85,
            dst_src: 0x00,
            off: 0,
            imm: HELPER_GPIO_WRITE,
        },
        // EXIT:
        BpfInsn {
            code: 0x95,
            dst_src: 0x00,
            off: 0,
            imm: 0,
        },
    ];

    print("Loading BPF program...\n");
    let load_attr = BpfAttr {
        prog_type: 1, // SocketFilter (generic)
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        ..Default::default()
    };

    let prog_id = bpf(
        5, // BPF_PROG_LOAD
        &load_attr as *const BpfAttr as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );

    if prog_id < 0 {
        print("Error: Failed to load BPF program\n");
        exit(1);
    }

    print("Program loaded. ID: ");
    print_num(prog_id as u64);
    print("\n");

    // 2. Attach Program to GPIO Interrupt
    print("Attaching to GPIO 17 (Rising Edge)...\n");

    let attach_attr = BpfAttr {
        attach_btf_id: kernel_abi::BPF_ATTACH_TYPE_GPIO,
        attach_prog_fd: prog_id as u32,
        key: BUTTON_PIN as u64, // Pin number
        value: 1,               // 1=Rising Edge, 2=Falling, 3=Both
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

    print("Success! BPF program attached.\n");
    print("Press the button on GPIO 17 to toggle LED on GPIO 18.\n");
    print("Running indefinitely... (Press Ctrl-C to exit if running in emulator)\n");

    loop {
        // Sleep to save CPU while BPF handles interrupts in background
        minilib::sleep(1);
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
    print("Panic!\n");
    loop {}
}
