#![no_std]
#![no_main]

use kernel_abi::BpfAttr;
use minilib::{bpf, exit, write};

// === Configuration ===
// Limit switch pin (GPIO 17 — configurable for different wiring)
const LIMIT_SWITCH_PIN: u32 = 17;
// PWM configuration for simulated motor
const PWM_CHIP: u32 = 0;
const PWM_CHANNEL: u32 = 1;
const MOTOR_DUTY: i32 = 50; // 50% duty cycle simulates running motor

// === BPF Helper IDs (from interpreter/JIT dispatch tables) ===
const HELPER_TRACE_PRINTK: i32 = 2;
const HELPER_MOTOR_STOP: i32 = 1000;
const HELPER_PWM_WRITE: i32 = 1005;

// === BPF commands ===
const BPF_PROG_LOAD: i32 = 5;
const BPF_PROG_ATTACH: i32 = 8;

// === Attach types ===
const ATTACH_TYPE_TIMER: u32 = 1;
const ATTACH_TYPE_GPIO: u32 = 2;

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

    /// Store 8-bit immediate to memory: *(u8*)(dst + off) = imm
    const fn st_b(dst: u8, off: i16, imm: i32) -> Self {
        Self {
            code: 0x72,
            dst_src: dst,
            off,
            imm,
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

// SAFETY: Entry point for the safety interlock demo. Called by the startup code.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("\n");
    print("========================================\n");
    print("  Axiom Safety Interlock Demo\n");
    print("========================================\n");
    print("\n");
    print("This demo proves: kernel-level BPF safety interlocks\n");
    print("survive userspace exit. The interrupt -> BPF -> hardware\n");
    print("path has ZERO userspace dependency.\n");
    print("\n");

    // ---------------------------------------------------------
    // Step 1: Start Motor — load a BPF program on the timer hook
    //         that sets PWM0 channel 1 to 50% duty cycle.
    //
    // On each timer tick this program writes 50% to the PWM,
    // simulating a running motor.
    // ---------------------------------------------------------
    print("[1/4] Starting motor (PWM0 Ch1 @ 50% duty)...\n");

    let motor_insns = [
        // R1 = PWM_CHIP (0)
        BpfInsn::mov64_imm(1, PWM_CHIP as i32),
        // R2 = PWM_CHANNEL (1)
        BpfInsn::mov64_imm(2, PWM_CHANNEL as i32),
        // R3 = duty (50%)
        BpfInsn::mov64_imm(3, MOTOR_DUTY),
        // call bpf_pwm_write(chip, channel, duty)
        BpfInsn::call(HELPER_PWM_WRITE),
        // R0 = 0 (success)
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ];

    let load_motor = BpfAttr {
        prog_type: 1,
        insn_cnt: motor_insns.len() as u32,
        insns: motor_insns.as_ptr() as u64,
        ..Default::default()
    };

    let motor_id = bpf(
        BPF_PROG_LOAD,
        &load_motor as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if motor_id < 0 {
        print("  ERROR: Failed to load motor program\n");
        exit(1);
    }
    print("  Motor program loaded (ID: ");
    print_num(motor_id as u64);
    print(")\n");

    // Attach motor program to timer so it runs on each tick
    let attach_motor = BpfAttr {
        attach_btf_id: ATTACH_TYPE_TIMER,
        attach_prog_fd: motor_id as u32,
        ..Default::default()
    };

    let res = bpf(
        BPF_PROG_ATTACH,
        &attach_motor as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if res < 0 {
        print("  ERROR: Failed to attach motor to timer\n");
        exit(1);
    }
    print("  Motor running on timer hook. PWM active.\n\n");

    // ---------------------------------------------------------
    // Step 2: Create E-Stop BPF program for GPIO interrupt
    //
    // When the limit switch fires (rising edge on LIMIT_SWITCH_PIN):
    //   1. Call bpf_motor_emergency_stop(reason=1)
    //   2. Call bpf_trace_printk("SAFETY: Motor stopped by limit switch!")
    //   3. Return 0
    //
    // The trace_printk message will appear in kernel log, proving
    // the BPF program executed in kernel interrupt context.
    // ---------------------------------------------------------
    print("[2/4] Loading E-Stop BPF program...\n");

    // Build the trace message on the BPF stack.
    // Message: "SAFETY: Motor stopped!\0" (22 bytes including NUL)
    // We store it byte-by-byte using ST_B (store immediate byte).
    // Stack layout: R10-32 .. R10-11 = message (22 bytes)
    //
    // "SAFETY: Motor stopped!\0"
    // S=83 A=65 F=70 E=69 T=84 Y=89 :=58  =32
    // M=77 o=111 t=116 o=111 r=114  =32
    // s=115 t=116 o=111 p=112 p=112 e=101 d=100 !=33 \0=0

    let estop_insns = [
        // --- 1. Call bpf_motor_emergency_stop(reason=1) ---
        // R1 = 1 (reason: limit switch triggered)
        BpfInsn::mov64_imm(1, 1),
        // call bpf_motor_emergency_stop
        BpfInsn::call(HELPER_MOTOR_STOP),
        // --- 2. Build trace message on stack and call bpf_trace_printk ---
        // Store "SAFETY: Motor stopped!\0" at R10-24
        BpfInsn::st_b(10, -24, b'S' as i32),
        BpfInsn::st_b(10, -23, b'A' as i32),
        BpfInsn::st_b(10, -22, b'F' as i32),
        BpfInsn::st_b(10, -21, b'E' as i32),
        BpfInsn::st_b(10, -20, b'T' as i32),
        BpfInsn::st_b(10, -19, b'Y' as i32),
        BpfInsn::st_b(10, -18, b':' as i32),
        BpfInsn::st_b(10, -17, b' ' as i32),
        BpfInsn::st_b(10, -16, b'M' as i32),
        BpfInsn::st_b(10, -15, b'o' as i32),
        BpfInsn::st_b(10, -14, b't' as i32),
        BpfInsn::st_b(10, -13, b'o' as i32),
        BpfInsn::st_b(10, -12, b'r' as i32),
        BpfInsn::st_b(10, -11, b' ' as i32),
        BpfInsn::st_b(10, -10, b's' as i32),
        BpfInsn::st_b(10, -9, b't' as i32),
        BpfInsn::st_b(10, -8, b'o' as i32),
        BpfInsn::st_b(10, -7, b'p' as i32),
        BpfInsn::st_b(10, -6, b'!' as i32),
        BpfInsn::st_b(10, -5, 0), // NUL terminator
        // R1 = pointer to string (R10 - 24)
        BpfInsn::mov64_reg(1, 10),
        BpfInsn::add64_imm(1, -24),
        // R2 = size (20 = length of "SAFETY: Motor stop!" + NUL)
        BpfInsn::mov64_imm(2, 20),
        // call bpf_trace_printk
        BpfInsn::call(HELPER_TRACE_PRINTK),
        // --- 3. Return 0 ---
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ];

    let load_estop = BpfAttr {
        prog_type: 1,
        insn_cnt: estop_insns.len() as u32,
        insns: estop_insns.as_ptr() as u64,
        ..Default::default()
    };

    let estop_id = bpf(
        BPF_PROG_LOAD,
        &load_estop as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if estop_id < 0 {
        print("  ERROR: Failed to load E-Stop program\n");
        exit(1);
    }
    print("  E-Stop program loaded (ID: ");
    print_num(estop_id as u64);
    print(")\n");
    print("  Actions: bpf_motor_emergency_stop + bpf_trace_printk\n\n");

    // ---------------------------------------------------------
    // Step 3: Attach E-Stop to GPIO (limit switch pin, rising edge)
    //
    // The kernel's BPF_PROG_ATTACH handler for GPIO type will:
    //   - Configure the pin as input
    //   - Enable rising edge interrupt on the pin
    //   - Register the BPF program for GPIO hook execution
    // ---------------------------------------------------------
    print("[3/4] Attaching E-Stop to GPIO ");
    print_num(LIMIT_SWITCH_PIN as u64);
    print(" (rising edge)...\n");

    let attach_estop = BpfAttr {
        attach_btf_id: ATTACH_TYPE_GPIO,
        attach_prog_fd: estop_id as u32,
        key: LIMIT_SWITCH_PIN as u64, // Pin number
        value: 1,                     // 1 = Rising Edge
        ..Default::default()
    };

    let res = bpf(
        BPF_PROG_ATTACH,
        &attach_estop as *const _ as *const u8,
        core::mem::size_of::<BpfAttr>() as i32,
    );
    if res < 0 {
        print("  ERROR: Failed to attach E-Stop to GPIO\n");
        exit(1);
    }
    print("  E-Stop attached. GPIO interrupt armed.\n\n");

    // ---------------------------------------------------------
    // Step 4: EXIT — proving the safety thesis
    //
    // The BPF programs are now in the kernel:
    //   - Motor program: timer hook -> PWM at 50%
    //   - E-Stop program: GPIO interrupt -> motor emergency stop
    //
    // After this process exits:
    //   - Programs PERSIST in the kernel's BpfManager
    //   - GPIO interrupt -> BPF execute -> bpf_motor_emergency_stop
    //   - This entire path is in kernel interrupt context
    //   - ZERO userspace dependency
    //
    // Trigger the limit switch on GPIO 17 to verify.
    // ---------------------------------------------------------
    print("[4/4] Safety interlock ARMED.\n");
    print("\n");
    print("  Motor:     PWM0 Ch1 @ 50% (via timer BPF hook)\n");
    print("  E-Stop:    GPIO ");
    print_num(LIMIT_SWITCH_PIN as u64);
    print(" rising edge -> bpf_motor_emergency_stop\n");
    print("  Trace:     Kernel log will show 'SAFETY: Motor stop!'\n");
    print("\n");
    print("  >> Userspace will now EXIT. <<\n");
    print("  >> Safety interlock remains active in the kernel. <<\n");
    print("  >> Trigger limit switch on GPIO ");
    print_num(LIMIT_SWITCH_PIN as u64);
    print(" to stop motor. <<\n");
    print("\n");
    print("========================================\n");
    print("  Exiting userspace. BPF persists.\n");
    print("========================================\n");

    exit(0);
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
