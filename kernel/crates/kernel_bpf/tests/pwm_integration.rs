//! PWM Integration Tests
//!
//! Verify that BPF programs can correctly process PWM events.

#![cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]

use kernel_bpf::attach::PwmEvent;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, ProgramBuilder};
use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
use kernel_bpf::profile::ActiveProfile;
use kernel_bpf::verifier::VerifyConfig;

// Stubs for resolving linker errors during integration testing

// SAFETY: Test stub for BPF helper.
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
fn test_pwm_event_processing() {
    // 1. Create a simulated PWM event
    let event = PwmEvent {
        timestamp: 123456789,
        chip_id: 0,
        channel: 1,
        period_ns: 1_000_000, // 1ms
        duty_ns: 250_000,     // 25% duty
        polarity: 0,
        enabled: 1,
    };

    let ctx = BpfContext::from_struct(&event);

    // 2. Create a BPF program to read duty cycle
    //
    // The program will:
    // - Read duty_ns (offset 20) from context (R1)
    // - Read period_ns (offset 16) from context (R1)
    // - Calculate duty percentage: (duty * 100) / period
    // - Return the percentage
    //
    // PwmEvent layout (repr(C)):
    // - timestamp: u64 (0)
    // - chip_id: u32 (8)
    // - channel: u32 (12)
    // - period_ns: u32 (16)
    // - duty_ns: u32 (20)
    // - polarity: u32 (24)
    // - enabled: u32 (28)

    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        // R1 points to context (BpfContext)
        // 1. Load data pointer from BpfContext.data (offset 0) into R4
        .insn(BpfInsn::new(0x79, 4, 1, 0, 0)) // LDX_DW R4, [R1+0]
        // 2. Load duty_ns into R2 (LDX_W) from R4
        .insn(BpfInsn::new(0x61, 2, 4, 20, 0))
        // 3. Load period_ns into R3 (LDX_W) from R4
        .insn(BpfInsn::new(0x61, 3, 4, 16, 0))
        // A zero period is invalid; return 0 instead of dividing by zero.
        .insn(BpfInsn::jeq_imm(3, 0, 4))
        // Calculate (duty * 100)
        .insn(BpfInsn::mul64_imm(2, 100))
        // Calculate result / period (DIV64_REG)
        .insn(BpfInsn::new(0x3F, 2, 3, 0, 0))
        // Move result to R0 and exit
        .insn(BpfInsn::mov64_reg(0, 2))
        .insn(BpfInsn::exit())
        .insn(BpfInsn::mov64_imm(0, 0))
        .insn(BpfInsn::exit())
        .build_raw()
        .verify_with_config(VerifyConfig {
            ctx_size: core::mem::size_of::<BpfContext<'static>>() as u32,
            ctx_data_size: core::mem::size_of::<PwmEvent>() as u32,
            ..VerifyConfig::default()
        })
        .expect("valid program");

    // 3. Execute program
    let interp = interpreter();
    let result = interp.execute(&program, &ctx);

    // 4. Verify result (25%)
    assert_eq!(result, Ok(25));
}

#[test]
fn test_pwm_event_filtering() {
    // Test filtering for a specific channel

    // Event for channel 2
    let event = PwmEvent {
        timestamp: 0,
        chip_id: 0,
        channel: 2,
        period_ns: 1000,
        duty_ns: 500,
        polarity: 0,
        enabled: 1,
    };

    let ctx = BpfContext::from_struct(&event);

    // Program: return 1 if channel == 1, else 0
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        // 1. Load data pointer from BpfContext.data (offset 0) into R4
        .insn(BpfInsn::new(0x79, 4, 1, 0, 0)) // LDX_DW R4, [R1+0]
        // 2. Load channel from offset 12 (LDX_W) from R4
        .insn(BpfInsn::new(0x61, 2, 4, 12, 0))
        // If channel != 1, jump to exit (return 0)
        .insn(BpfInsn::jne_imm(2, 1, 2)) // JNE R2, 1, +2
        // Match: return 1
        .insn(BpfInsn::mov64_imm(0, 1))
        .insn(BpfInsn::exit())
        // No match: return 0
        .insn(BpfInsn::mov64_imm(0, 0))
        .insn(BpfInsn::exit())
        .build_raw()
        .verify_with_config(VerifyConfig {
            ctx_size: core::mem::size_of::<BpfContext<'static>>() as u32,
            ctx_data_size: core::mem::size_of::<PwmEvent>() as u32,
            ..VerifyConfig::default()
        })
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &ctx);

    // Channel is 2, so should return 0
    assert_eq!(result, Ok(0));
}
