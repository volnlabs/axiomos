//! GPIO Integration Tests
//!
//! Verify that BPF programs can correctly process GPIO events.

#![cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]

use kernel_bpf::attach::GpioEvent;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, ProgramBuilder};
use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::VerifyConfig;

// Stubs for resolving linker errors during integration testing

// SAFETY: Test stub for BPF helper. Safe to be called from C/BPF context in tests.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_ktime_get_ns() -> u64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_interrupt_latency_ns(_ctx: *const BpfContext) -> u64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_boot_time_ms(_ctx: *const BpfContext) -> u64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_kernel_heap_kb(_ctx: *const BpfContext) -> u64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_kernel_image_mb(_ctx: *const BpfContext) -> u64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_trace_printk(_fmt: *const u8, _len: u32) -> i32 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_map_lookup_elem(_map_id: u32, _key: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_map_update_elem(
    _map_id: u32,
    _key: *const u8,
    _value: *const u8,
    _flags: u64,
) -> i32 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_map_delete_elem(_map_id: u32, _key: *const u8) -> i32 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_ringbuf_output(
    _map_id: u32,
    _data: *const u8,
    _size: u64,
    _flags: u64,
) -> i64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_gpio_read(_pin: u32) -> i64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_gpio_write(_pin: u32, _value: u32) -> i64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_pwm_write(_pwm_id: u32, _channel: u32, _duty: u32) -> i64 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn bpf_motor_pair_v1(_left: i32, _right: i32) -> i64 {
    0
}

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_timeseries_push(_map_id: u32, _key: *const u8, _value: *const u8) -> i64 {
    0
}

/// Helper to create an interpreter
fn interpreter() -> Interpreter<ActiveProfile> {
    Interpreter::new()
}

#[test]
fn test_gpio_event_processing() {
    // 1. Create a simulated GPIO event
    // Structure layout (repr(C)):
    // - timestamp: u64 (0)
    // - chip_id: u32 (8)
    // - line: u32 (12)
    // - edge: u32 (16)
    // - value: u32 (20)
    let event = GpioEvent {
        timestamp: 123456789,
        chip_id: 0,
        line: 17,
        edge: 1,  // Rising
        value: 1, // High
    };

    let ctx = BpfContext::from_struct(&event);

    // 2. Create a BPF program to check for a specific pin event
    //
    // The program will:
    // - Read line (offset 12) from context (R1)
    // - If line == 17, return 1 (pass)
    // - Else return 0 (fail)

    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        // R1 points to context (BpfContext)
        // 1. Load data pointer from BpfContext.data (offset 0) into R4
        .insn(BpfInsn::new(0x79, 4, 1, 0, 0)) // LDX_DW R4, [R1+0]
        // 2. Load line into R2 (LDX_W) from R4 at offset 12
        .insn(BpfInsn::new(0x61, 2, 4, 12, 0))
        // 3. Compare R2 with 17. Note: dst_reg must be 2 (R2)
        .insn(BpfInsn::jne_imm(2, 17, 2)) // JNE R2, 17, +2
        // Match: return 1
        .insn(BpfInsn::mov64_imm(0, 1))
        .insn(BpfInsn::exit())
        // No match: return 0
        .insn(BpfInsn::mov64_imm(0, 0))
        .insn(BpfInsn::exit())
        .build_raw()
        .verify_with_config(VerifyConfig {
            ctx_size: core::mem::size_of::<BpfContext<'static>>() as u32,
            ctx_data_size: core::mem::size_of::<GpioEvent>() as u32,
            ..VerifyConfig::default()
        })
        .expect("valid program");

    // 3. Execute program
    let interp = interpreter();
    let result = interp.execute(&program, &ctx);

    // 4. Verify result (1 = match)
    assert_eq!(result, Ok(1));
}

#[test]
fn test_gpio_event_edge_filtering() {
    // Test checking the edge type

    // Event: Falling edge (2) on pin 22
    let event = GpioEvent {
        timestamp: 0,
        chip_id: 0,
        line: 22,
        edge: 2, // Falling
        value: 0,
    };

    let ctx = BpfContext::from_struct(&event);

    // Program: return 1 if edge == 2 (Falling), else 0
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        // 1. Load data pointer from BpfContext.data (offset 0) into R4
        .insn(BpfInsn::new(0x79, 4, 1, 0, 0)) // LDX_DW R4, [R1+0]
        // 2. Load edge from offset 16 (LDX_W) from R4 into R2
        .insn(BpfInsn::new(0x61, 2, 4, 16, 0))
        // If edge != 2, jump to exit (return 0)
        .insn(BpfInsn::jne_imm(2, 2, 2)) // JNE R2, 2, +2
        // Match: return 1
        .insn(BpfInsn::mov64_imm(0, 1))
        .insn(BpfInsn::exit())
        // No match: return 0
        .insn(BpfInsn::mov64_imm(0, 0))
        .insn(BpfInsn::exit())
        .build_raw()
        .verify_with_config(VerifyConfig {
            ctx_size: core::mem::size_of::<BpfContext<'static>>() as u32,
            ctx_data_size: core::mem::size_of::<GpioEvent>() as u32,
            ..VerifyConfig::default()
        })
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &ctx);

    // Edge is 2, so should return 1
    assert_eq!(result, Ok(1));
}
