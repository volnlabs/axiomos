//! Semantic Consistency Tests
//!
//! These tests verify that the same BPF bytecode produces the same results
//! regardless of profile. This ensures zero semantic drift between cloud
//! and embedded deployments.
//!
//! The tests in this file should be identical in both profiles and produce
//! the same results.

#![cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]

use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, ProgramBuilder};
use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
use kernel_bpf::profile::ActiveProfile;

/// Helper to create an interpreter for the active profile.
fn interpreter() -> Interpreter<ActiveProfile> {
    Interpreter::new()
}

/// Helper to create a context with a data buffer.
#[allow(dead_code)]
fn context_with_data(data: &[u8]) -> BpfContext<'_> {
    BpfContext::from_slice(data)
}

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

// SAFETY: Test stub for BPF helper.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_timeseries_push(_map_id: u32, _key: *const u8, _value: *const u8) -> i64 {
    0
}

#[test]
fn semantic_return_constant() {
    // Program: return 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 42))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    // Must return exactly 42 in both profiles
    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_arithmetic_add() {
    // Program: r0 = 10 + 32 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 10))
        .insn(BpfInsn::add64_imm(0, 32))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_arithmetic_sub() {
    // Program: r0 = 100 - 58 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 100))
        .insn(BpfInsn::sub64_imm(0, 58))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_arithmetic_mul() {
    // Program: r0 = 6 * 7 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 6))
        .insn(BpfInsn::mul64_imm(0, 7))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_arithmetic_div() {
    // Program: r0 = 126 / 3 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 126))
        .insn(BpfInsn::div64_imm(0, 3))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_bitwise_and() {
    // Program: r0 = 0xFF & 0x2A = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 0xFF))
        .insn(BpfInsn::and64_imm(0, 0x2A))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_bitwise_or() {
    // Program: r0 = 0x20 | 0x0A = 42 (0x2A)
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 0x20))
        .insn(BpfInsn::or64_imm(0, 0x0A))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_conditional_jump_equal() {
    // Program: if r1 == 1 then r0 = 42 else r0 = 0
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(1, 1)) // r1 = 1
        .insn(BpfInsn::mov64_imm(0, 0)) // r0 = 0
        .insn(BpfInsn::jeq_imm(1, 1, 1)) // if r1 == 1, skip 1 instruction
        .insn(BpfInsn::exit()) // exit with 0 (skipped)
        .insn(BpfInsn::mov64_imm(0, 42)) // r0 = 42
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_conditional_jump_not_equal() {
    // Program: if r1 != 0 then r0 = 42 else r0 = 0
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(1, 5)) // r1 = 5
        .insn(BpfInsn::mov64_imm(0, 0)) // r0 = 0
        .insn(BpfInsn::jne_imm(1, 0, 1)) // if r1 != 0, skip 1 instruction
        .insn(BpfInsn::exit()) // exit with 0 (skipped)
        .insn(BpfInsn::mov64_imm(0, 42)) // r0 = 42
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_register_copy() {
    // Program: r1 = 42; r0 = r1
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(1, 42))
        .insn(BpfInsn::mov64_reg(0, 1))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_register_chain() {
    // Program: chain through registers r1 -> r2 -> r3 -> r0
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(1, 42))
        .insn(BpfInsn::mov64_reg(2, 1))
        .insn(BpfInsn::mov64_reg(3, 2))
        .insn(BpfInsn::mov64_reg(0, 3))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_negation() {
    // Program: r0 = -(-42) = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, -42i32 as i32))
        .insn(BpfInsn::neg64(0))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_shift_left() {
    // Program: r0 = 21 << 1 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 21))
        .insn(BpfInsn::lsh64_imm(0, 1))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_shift_right() {
    // Program: r0 = 84 >> 1 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 84))
        .insn(BpfInsn::rsh64_imm(0, 1))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_modulo() {
    // Program: r0 = 142 % 100 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 142))
        .insn(BpfInsn::mod64_imm(0, 100))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_xor() {
    // Program: r0 = 0x55 ^ 0x7F = 42 (0x2A)
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 0x55))
        .insn(BpfInsn::xor64_imm(0, 0x7F))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn semantic_complex_expression() {
    // Program: r0 = ((10 + 5) * 3 - 3) / 1 = 42
    // 10 + 5 = 15, 15 * 3 = 45, 45 - 3 = 42
    let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 10))
        .insn(BpfInsn::add64_imm(0, 5))
        .insn(BpfInsn::mul64_imm(0, 3))
        .insn(BpfInsn::sub64_imm(0, 3))
        .insn(BpfInsn::exit())
        .build()
        .expect("valid program");

    let interp = interpreter();
    let result = interp.execute(&program, &BpfContext::empty());

    assert_eq!(result, Ok(42));
}

#[test]
fn verifier_rejects_loop_that_exhausts_state_budget() {
    let result = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
        .insn(BpfInsn::mov64_imm(0, 0)) // r0 = 0 (counter)
        .insn(BpfInsn::mov64_imm(1, 42)) // r1 = 42 (limit)
        // Loop start (insn 2)
        .insn(BpfInsn::jeq_reg(0, 1, 2)) // if r0 == r1, exit (skip 2)
        .insn(BpfInsn::add64_imm(0, 1)) // r0++
        .insn(BpfInsn::ja(-3)) // jump back to loop start
        // Exit
        .insn(BpfInsn::exit())
        .build();

    assert!(result.is_err());
}
