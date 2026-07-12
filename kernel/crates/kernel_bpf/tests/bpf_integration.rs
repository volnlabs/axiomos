//! BPF Integration Tests
//!
//! These tests verify the integration between different BPF components:
//! - Program creation and execution
//! - Map operations
//! - Error handling
//!
//! These tests exercise the full BPF subsystem as used by the kernel syscall layer.

#![cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]

use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::{BpfProgType, ProgramBuilder, ProgramError};
use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
use kernel_bpf::maps::{ArrayMap, BpfMap, HashMap, MapError, RingBufMap};
use kernel_bpf::profile::ActiveProfile;

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

/// Helper to create an interpreter for the active profile.
fn interpreter() -> Interpreter<ActiveProfile> {
    Interpreter::new()
}

// ============================================================================
// Program Lifecycle Tests
// ============================================================================

mod program_lifecycle {
    use super::*;

    #[test]
    fn create_minimal_program() {
        // Minimal valid program: return 0
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        assert_eq!(program.insn_count(), 2);
        assert_eq!(program.prog_type(), BpfProgType::SocketFilter);
    }

    #[test]
    fn create_program_with_name() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::Kprobe)
            .name("my_kprobe")
            .insn(BpfInsn::mov64_imm(0, 1))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        assert_eq!(program.name(), Some("my_kprobe"));
    }

    #[test]
    fn empty_program_rejected() {
        let result = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter).build();

        assert!(matches!(result, Err(ProgramError::EmptyProgram)));
    }

    #[test]
    fn execute_return_immediate() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 42))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(42));
    }

    #[test]
    fn execute_with_multiple_registers() {
        // r1 = 10, r2 = 20, r3 = r1 + r2, r0 = r3
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(1, 10))
            .insn(BpfInsn::mov64_imm(2, 20))
            .insn(BpfInsn::mov64_reg(3, 1))
            .insn(BpfInsn::add64_reg(3, 2))
            .insn(BpfInsn::mov64_reg(0, 3))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(30));
    }
}

// ============================================================================
// Arithmetic Operations Tests
// ============================================================================

mod arithmetic_operations {
    use super::*;

    #[test]
    fn addition_overflow_wraps() {
        // r0 = MAX + 1 = 0 (wrapping)
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, -1)) // 0xFFFFFFFFFFFFFFFF
            .insn(BpfInsn::add64_imm(0, 1))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(0));
    }

    #[test]
    fn subtraction_underflow_wraps() {
        // r0 = 0 - 1 = MAX (wrapping)
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::sub64_imm(0, 1))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(u64::MAX));
    }

    #[test]
    fn multiplication_large_numbers() {
        // r0 = 1000 * 1000 = 1000000
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 1000))
            .insn(BpfInsn::mul64_imm(0, 1000))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(1_000_000));
    }

    #[test]
    fn division_integer_truncation() {
        // r0 = 7 / 2 = 3 (integer division)
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 7))
            .insn(BpfInsn::div64_imm(0, 2))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(3));
    }

    #[test]
    fn modulo_operation() {
        // r0 = 17 % 5 = 2
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 17))
            .insn(BpfInsn::mod64_imm(0, 5))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(2));
    }
}

// ============================================================================
// Bitwise Operations Tests
// ============================================================================

mod bitwise_operations {
    use super::*;

    #[test]
    fn left_shift_by_immediate() {
        // r0 = 1 << 2 = 4
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 1))
            .insn(BpfInsn::lsh64_imm(0, 2))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(4));
    }

    #[test]
    fn right_shift_logical() {
        // r0 = 128 >> 3 = 16
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 128))
            .insn(BpfInsn::rsh64_imm(0, 3))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(16));
    }

    #[test]
    fn and_mask() {
        // r0 = 0xFF & 0x0F = 0x0F
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0xFF))
            .insn(BpfInsn::and64_imm(0, 0x0F))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(0x0F));
    }

    #[test]
    fn or_combine() {
        // r0 = 0xF0 | 0x0F = 0xFF
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0xF0))
            .insn(BpfInsn::or64_imm(0, 0x0F))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(0xFF));
    }

    #[test]
    fn xor_toggle() {
        // r0 = 0xFF ^ 0xFF = 0
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0xFF))
            .insn(BpfInsn::xor64_imm(0, 0xFF))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(0));
    }
}

// ============================================================================
// Control Flow Tests
// ============================================================================

mod control_flow {
    use super::*;

    #[test]
    fn unreachable_after_unconditional_jump_is_rejected() {
        let result = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::ja(1)) // Jump over next instruction
            .insn(BpfInsn::mov64_imm(0, 99)) // Unreachable
            .insn(BpfInsn::mov64_imm(0, 42))
            .insn(BpfInsn::exit())
            .build();

        assert!(matches!(result, Err(ProgramError::VerificationFailed(_))));
    }

    #[test]
    fn conditional_equal_taken() {
        // if r1 == 5, set r0 = 100, else r0 = 0
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(1, 5))
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::jeq_imm(1, 5, 1)) // if r1 == 5, skip 1
            .insn(BpfInsn::exit()) // Skipped
            .insn(BpfInsn::mov64_imm(0, 100))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(100));
    }

    #[test]
    fn conditional_equal_not_taken() {
        // if r1 == 5, set r0 = 100, else exit with 0
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(1, 3)) // r1 = 3 (not 5)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::jeq_imm(1, 5, 1)) // if r1 == 5, skip 1 (not taken)
            .insn(BpfInsn::exit()) // Executed
            .insn(BpfInsn::mov64_imm(0, 100)) // Not reached
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(0));
    }

    #[test]
    fn compare_greater_than() {
        // r0 = 1 if r1 > 5, else r0 = 0
        // Using jne since jgt_imm is not available
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(1, 10))
            .insn(BpfInsn::mov64_imm(0, 0))
            // Use BpfInsn::new to create jgt_imm: opcode 0x25
            .insn(BpfInsn::new(0x25, 1, 0, 1, 5)) // if r1 > 5, skip 1
            .insn(BpfInsn::exit())
            .insn(BpfInsn::mov64_imm(0, 1))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(1));
    }

    #[test]
    fn loop_with_counter() {
        // Sum 1 + 2 + 3 + 4 + 5 = 15
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0)) // r0 = sum = 0
            .insn(BpfInsn::mov64_imm(1, 1)) // r1 = counter = 1
            .insn(BpfInsn::mov64_imm(2, 5)) // r2 = limit = 5
            // Loop:
            .insn(BpfInsn::add64_reg(0, 1)) // sum += counter
            .insn(BpfInsn::add64_imm(1, 1)) // counter++
            // jle_reg: opcode 0xbd (JLE with reg source)
            .insn(BpfInsn::new(0xbd, 1, 2, -3, 0)) // if counter <= limit, jump back
            .insn(BpfInsn::exit())
            .build();

        #[cfg(feature = "embedded-profile")]
        {
            assert!(program.is_err());
            return;
        }

        #[cfg(feature = "cloud-profile")]
        let program = program.expect("cloud profile permits loops with a runtime limit");

        #[cfg(feature = "cloud-profile")]
        let interp = interpreter();
        #[cfg(feature = "cloud-profile")]
        let result = interp.execute(&program, &BpfContext::empty());

        #[cfg(feature = "cloud-profile")]
        assert_eq!(result, Ok(15));
    }
}

// ============================================================================
// Map Operations Tests
// ============================================================================

mod map_operations {
    use super::*;

    #[test]
    fn array_map_basic_operations() {
        let map = ArrayMap::<ActiveProfile>::with_entries(8, 10).expect("create map");

        // Update index 3
        let key = 3u32.to_ne_bytes();
        let value = 0xDEADBEEFu64.to_ne_bytes();
        map.update(&key, &value, 0).expect("update");

        // Lookup index 3
        let result = map.lookup(&key).expect("lookup");
        assert_eq!(result, value);

        // Lookup uninitialized index returns zeros
        let key2 = 5u32.to_ne_bytes();
        let result2 = map.lookup(&key2).expect("lookup zeros");
        assert_eq!(result2, [0u8; 8]);
    }

    #[test]
    fn array_map_boundary_access() {
        let map = ArrayMap::<ActiveProfile>::with_entries(4, 5).expect("create map");

        // Access last valid index
        let key = 4u32.to_ne_bytes();
        let value = 42u32.to_ne_bytes();
        map.update(&key, &value, 0).expect("update last index");

        // Access out of bounds
        let bad_key = 5u32.to_ne_bytes();
        assert!(map.lookup(&bad_key).is_none());
    }

    #[test]
    fn hash_map_insert_lookup_delete() {
        let map = HashMap::<ActiveProfile>::with_sizes(8, 8, 100).expect("create map");

        // Insert
        let key = 12345u64.to_ne_bytes();
        let value = 67890u64.to_ne_bytes();
        map.update(&key, &value, 0).expect("insert");
        assert_eq!(map.len(), 1);

        // Lookup
        let result = map.lookup(&key).expect("lookup");
        assert_eq!(result, value);

        // Delete
        map.delete(&key).expect("delete");
        assert!(map.lookup(&key).is_none());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn hash_map_collision_handling() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 4, 100).expect("create map");

        // Insert many entries to trigger collisions
        for i in 0u32..50 {
            let key = i.to_ne_bytes();
            let value = (i * 2).to_ne_bytes();
            map.update(&key, &value, 0).expect("insert");
        }

        // Verify all entries
        for i in 0u32..50 {
            let key = i.to_ne_bytes();
            let result = map.lookup(&key).expect("lookup");
            let expected = (i * 2).to_ne_bytes();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn hash_map_update_flags() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 4, 10).expect("create map");

        let key = 1u32.to_ne_bytes();
        let value1 = 100u32.to_ne_bytes();
        let value2 = 200u32.to_ne_bytes();

        // BPF_NOEXIST (1): Create only if key doesn't exist
        map.update(&key, &value1, 1).expect("create");

        // Second create should fail
        let result = map.update(&key, &value2, 1);
        assert!(matches!(result, Err(MapError::KeyExists)));

        // BPF_EXIST (2): Update only if key exists
        map.update(&key, &value2, 2).expect("update existing");

        // Verify updated value
        let result = map.lookup(&key).expect("lookup");
        assert_eq!(result, value2);

        // Update non-existent key should fail
        let key2 = 2u32.to_ne_bytes();
        let result = map.update(&key2, &value1, 2);
        assert!(matches!(result, Err(MapError::KeyNotFound)));
    }

    #[test]
    fn ringbuf_single_event() {
        let ringbuf = RingBufMap::<ActiveProfile>::new(4096).expect("create ringbuf");

        let data = b"test event data";
        ringbuf.output(data, 0).expect("output");

        let result = ringbuf.poll().expect("poll");
        assert_eq!(result, data);

        // Buffer should be empty now
        assert!(ringbuf.poll().is_none());
    }

    #[test]
    fn ringbuf_fifo_order() {
        let ringbuf = RingBufMap::<ActiveProfile>::new(4096).expect("create ringbuf");

        // Write events
        for i in 0u32..5 {
            ringbuf.output(&i.to_ne_bytes(), 0).expect("output");
        }

        // Read in FIFO order
        for i in 0u32..5 {
            let result = ringbuf.poll().expect("poll");
            let value = u32::from_ne_bytes(result.try_into().unwrap());
            assert_eq!(value, i);
        }
    }

    #[test]
    fn ringbuf_buffer_full() {
        // Small buffer
        let ringbuf = RingBufMap::<ActiveProfile>::new(64).expect("create ringbuf");

        // Fill the buffer
        let data = [0u8; 32];
        ringbuf.output(&data, 0).expect("first output");

        // Second should fail (buffer full)
        let result = ringbuf.output(&data, 0);
        assert!(matches!(result, Err(MapError::MapFull)));

        assert_eq!(ringbuf.dropped_count(), 1);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling {
    use super::*;

    #[test]
    fn map_invalid_key_size() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 10).expect("create map");

        // Wrong key size
        let bad_key = [1u8, 2, 3]; // 3 bytes instead of 4
        let value = [0u8; 8];

        let result = map.update(&bad_key, &value, 0);
        assert!(matches!(result, Err(MapError::InvalidKey)));
    }

    #[test]
    fn map_invalid_value_size() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 10).expect("create map");

        let key = [1u8; 4];
        let bad_value = [0u8; 4]; // 4 bytes instead of 8

        let result = map.update(&key, &bad_value, 0);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }

    #[test]
    fn map_delete_nonexistent() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 4, 10).expect("create map");

        let key = [1u8; 4];
        let result = map.delete(&key);
        assert!(matches!(result, Err(MapError::KeyNotFound)));
    }

    #[test]
    fn array_map_delete_not_supported() {
        let map = ArrayMap::<ActiveProfile>::with_entries(4, 10).expect("create map");

        let key = 0u32.to_ne_bytes();
        let result = map.delete(&key);
        assert!(matches!(result, Err(MapError::NotSupported)));
    }

    #[test]
    fn ringbuf_non_power_of_two() {
        let result = RingBufMap::<ActiveProfile>::new(1000);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }

    #[test]
    fn map_creation_zero_key_size() {
        let result = HashMap::<ActiveProfile>::with_sizes(0, 8, 10);
        assert!(matches!(result, Err(MapError::InvalidKey)));
    }

    #[test]
    fn map_creation_zero_value_size() {
        let result = HashMap::<ActiveProfile>::with_sizes(4, 0, 10);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }

    #[test]
    fn map_creation_zero_entries() {
        let result = HashMap::<ActiveProfile>::with_sizes(4, 8, 0);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }
}

// ============================================================================
// Context Tests
// ============================================================================

mod context_tests {
    use super::*;

    #[test]
    fn empty_context() {
        let ctx = BpfContext::empty();
        assert_eq!(ctx.data_len(), 0);
    }

    #[test]
    fn context_from_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let ctx = BpfContext::from_slice(&data);
        assert_eq!(ctx.data_len(), 5);
    }

    #[test]
    fn program_with_context() {
        // Test that program receives a context pointer in R1
        // R1 contains pointer to BpfContext struct
        let data = [0u8; 100];
        let ctx = BpfContext::from_slice(&data);

        // Simple program that just returns a constant
        // (Since accessing context struct fields would require memory loads,
        // we just verify that the program can execute with a context)
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 123)) // return constant
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &ctx);

        assert_eq!(result, Ok(123));
    }
}

// ============================================================================
// 32-bit Operations Tests
// ============================================================================

mod operations_32bit {
    use super::*;

    #[test]
    fn mov32_immediate() {
        // mov32 r0, 42 - should zero upper 32 bits
        // mov32_imm opcode: 0xb4
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, -1)) // Set all bits
            .insn(BpfInsn::new(0xb4, 0, 0, 0, 42)) // 32-bit move clears upper bits
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(42));
    }

    #[test]
    fn add32_wraps_at_32_bits() {
        // 0xFFFFFFFF + 1 should wrap to 0 in 32-bit mode
        // mov32_imm opcode: 0xb4, add32_imm opcode: 0x04
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::new(0xb4, 0, 0, 0, -1)) // mov32 r0, 0xFFFFFFFF
            .insn(BpfInsn::new(0x04, 0, 0, 0, 1)) // add32 r0, 1
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let interp = interpreter();
        let result = interp.execute(&program, &BpfContext::empty());

        assert_eq!(result, Ok(0));
    }
}

// ============================================================================
// Program Type Tests
// ============================================================================

mod program_types {
    use super::*;

    #[test]
    fn socket_filter_type() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        assert_eq!(program.prog_type(), BpfProgType::SocketFilter);
        assert!(!program.prog_type().requires_realtime());
    }

    #[test]
    fn kprobe_type() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::Kprobe)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        assert_eq!(program.prog_type(), BpfProgType::Kprobe);
    }

    #[test]
    fn tracepoint_type() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::Tracepoint)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        assert_eq!(program.prog_type(), BpfProgType::Tracepoint);
    }

    #[test]
    fn xdp_type() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::Xdp)
            .insn(BpfInsn::mov64_imm(0, 0))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        assert_eq!(program.prog_type(), BpfProgType::Xdp);
    }
}
