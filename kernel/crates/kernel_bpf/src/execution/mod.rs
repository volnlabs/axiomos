//! BPF Program Execution
//!
//! This module provides execution engines for BPF programs. The execution
//! strategy is determined at build time by the profile:
//!
//! | Mode        | Cloud Build | Embedded Build |
//! |-------------|-------------|----------------|
//! | JIT         | default     | **erased**     |
//! | Interpreter | fallback    | primary        |
//! | AOT         | rare        | encouraged     |
//!
//! # Compile-Time Erasure
//!
//! The JIT module is completely erased from embedded builds. This ensures
//! that embedded deployments cannot accidentally enable JIT compilation.

extern crate alloc;

mod interpreter;

#[cfg(test)]
#[allow(clippy::missing_safety_doc, improper_ctypes_definitions)]
pub mod helpers_stub {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::BpfContext;

    static TEST_MAP_VALUE: AtomicU64 = AtomicU64::new(0);

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_ktime_get_ns() -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_interrupt_latency_ns(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).interrupt_latency_ns }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_boot_time_ms(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).boot_time_ms }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_kernel_heap_kb(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).kernel_heap_kb }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_kernel_image_mb(ctx: *const BpfContext) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).kernel_image_mb }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_trace_printk(_fmt: *const u8, _len: u32) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_lookup_elem(_map_id: u32, _key: *const u8) -> *mut u8 {
        TEST_MAP_VALUE.as_ptr() as *mut u8
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_update_elem(
        _map_id: u32,
        _key: *const u8,
        value: *const u8,
        _flags: u64,
    ) -> i32 {
        if !value.is_null() {
            let val = unsafe { *(value as *const u64) };
            TEST_MAP_VALUE.store(val, Ordering::SeqCst);
        }
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_delete_elem(_map_id: u32, _key: *const u8) -> i32 {
        TEST_MAP_VALUE.store(0, Ordering::SeqCst);
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_ringbuf_output(
        _map_id: u32,
        _data: *const u8,
        _size: u64,
        _flags: u64,
    ) -> i64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_gpio_read(_pin: u32) -> i64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_gpio_write(_pin: u32, _value: u32) -> i64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_pwm_write(_pwm_id: u32, _channel: u32, _duty: u32) -> i64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_timeseries_push(_map_id: u32, _key: *const u8, _value: *const u8) -> i64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_motor_emergency_stop(_reason: u32) -> i64 {
        0
    }

    pub fn get_test_map_value() -> u64 {
        TEST_MAP_VALUE.load(Ordering::SeqCst)
    }

    pub fn reset_test_map() {
        TEST_MAP_VALUE.store(0, Ordering::SeqCst);
    }
}

// JIT is only available for cloud profile
#[cfg(all(feature = "cloud-profile", target_arch = "x86_64"))]
pub mod jit;

// ARM64 JIT is available for aarch64 target or for testing on any platform
#[cfg(any(target_arch = "aarch64", test))]
pub mod jit_aarch64;

pub use interpreter::Interpreter;
#[cfg(any(target_arch = "aarch64", test))]
pub use jit_aarch64::{Arm64JitCompiler, Arm64JitExecutor};

use crate::bytecode::program::BpfProgram;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Execution context passed to BPF programs.
///
/// This contains pointers to the program's input data and metadata.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfContext {
    /// Pointer to start of packet/data
    pub data: *const u8,
    /// Pointer to end of packet/data
    pub data_end: *const u8,
    /// Pointer to packet metadata
    pub data_meta: *const u8,
    /// Interrupt latency in nanoseconds (time from IRQ entry to BPF execution)
    pub interrupt_latency_ns: u64,
    /// Boot time in milliseconds (kernel start to init)
    pub boot_time_ms: u64,
    /// Kernel heap usage in KB
    pub kernel_heap_kb: u64,
    /// Kernel image size in MB
    pub kernel_image_mb: u64,
}

/// Context for syscall tracepoints.
///
/// This structure matches the layout expected by BPF programs attaching to
/// syscall entry tracepoints.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallTraceContext {
    pub syscall_nr: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
}

/// Context for syscall exit hooks.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallExitContext {
    pub syscall_nr: u64,
    pub result: i64,
}

/// Context for scheduler task switch hooks.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SchedSwitchContext {
    pub cpu_id: u64,
    pub prev_pid: u64,
    pub prev_tid: u64,
    pub next_pid: u64,
    pub next_tid: u64,
}

impl BpfContext {
    /// Create an empty context.
    pub const fn empty() -> Self {
        Self {
            data: core::ptr::null(),
            data_end: core::ptr::null(),
            data_meta: core::ptr::null(),
            interrupt_latency_ns: 0,
            boot_time_ms: 0,
            kernel_heap_kb: 0,
            kernel_image_mb: 0,
        }
    }

    /// Create a context from a data slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.as_ptr(),
            // SAFETY: data is a valid slice, so adding its length to the pointer remains within the object.
            data_end: unsafe { data.as_ptr().add(data.len()) },
            data_meta: core::ptr::null(),
            interrupt_latency_ns: 0,
            boot_time_ms: 0,
            kernel_heap_kb: 0,
            kernel_image_mb: 0,
        }
    }

    /// Create a context from any `repr(C)` POD-like value.
    pub fn from_struct<T>(value: &T) -> Self {
        let data = unsafe {
            core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
        };
        Self::from_slice(data)
    }

    /// Get the data length.
    pub fn data_len(&self) -> usize {
        if self.data.is_null() || self.data_end.is_null() {
            0
        } else {
            // SAFETY: data and data_end are pointers derived from the same object (slice),
            // so offset_from is well-defined.
            unsafe { self.data_end.offset_from(self.data) as usize }
        }
    }
}

// SAFETY: BpfContext only contains raw pointers that are used read-only
unsafe impl Send for BpfContext {}
// SAFETY: BpfContext only contains raw pointers that are used read-only
unsafe impl Sync for BpfContext {}

/// Result of BPF program execution.
pub type BpfResult = Result<u64, BpfError>;

/// Errors that can occur during BPF program execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfError {
    /// Division by zero
    DivisionByZero,

    /// Out of bounds memory access
    OutOfBounds,

    /// Stack overflow
    StackOverflow,

    /// Invalid helper function
    InvalidHelper(i32),

    /// Execution timeout (instruction limit exceeded)
    Timeout,

    /// Invalid instruction
    InvalidInstruction,

    /// Program not loaded
    NotLoaded,

    /// Out of memory
    OutOfMemory,

    /// The program failed static verification and was rejected at load time.
    VerificationFailed,

    /// The program failed signature authentication (untrusted signer, bad
    /// signature, tampered data, or unsigned while enforcement is enabled).
    SignatureRejected,
}

impl core::fmt::Display for BpfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::OutOfBounds => write!(f, "out of bounds memory access"),
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::InvalidHelper(id) => write!(f, "invalid helper function: {}", id),
            Self::Timeout => write!(f, "execution timeout"),
            Self::InvalidInstruction => write!(f, "invalid instruction"),
            Self::NotLoaded => write!(f, "program not loaded"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::VerificationFailed => write!(f, "program failed verification"),
            Self::SignatureRejected => write!(f, "program failed signature authentication"),
        }
    }
}

/// Trait for BPF execution engines.
///
/// This trait defines the interface for executing BPF programs.
/// Different implementations (interpreter, JIT, AOT) provide
/// different performance characteristics.
pub trait BpfExecutor<P: PhysicalProfile = ActiveProfile> {
    /// Execute a BPF program with the given context.
    ///
    /// # Arguments
    ///
    /// * `program` - The verified BPF program to execute
    /// * `ctx` - The execution context (packet data, etc.)
    ///
    /// # Returns
    ///
    /// The return value from the BPF program (R0) on success,
    /// or a `BpfError` on failure.
    fn execute(&self, program: &BpfProgram<P>, ctx: &BpfContext) -> BpfResult;
}

/// Get the default executor for the active profile.
///
/// - Cloud: JIT (if available) or interpreter
/// - Embedded: interpreter only
pub fn default_executor<P: PhysicalProfile>() -> impl BpfExecutor<P> {
    // For now, always return interpreter
    // JIT would be selected based on profile in a full implementation
    Interpreter::<P>::new()
}

/// Helper function registry.
///
/// BPF programs can call helper functions by ID. This registry
/// maps helper IDs to function pointers.
pub type HelperFn = fn(u64, u64, u64, u64, u64) -> u64;

/// Built-in helper function IDs.
///
/// Alias of the verifier's [`HelperId`](crate::verifier::HelperId) — the single
/// source of truth for helper numbering. The interpreter's `call_helper`
/// dispatch and the verifier's signature lookup therefore reference the same
/// values, so they cannot drift (the #121 unsoundness). Use
/// `HelperFunc::from_raw(n)` to resolve a raw call number.
pub use crate::verifier::HelperId as HelperFunc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_stubs_linked() {
        // Explicitly reference a stub to ensure the module and its no_mangle symbols
        // are not optimized away by the linker during host tests.
        assert_eq!(helpers_stub::bpf_ktime_get_ns(), 0);
    }

    #[test]
    fn context_from_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let ctx = BpfContext::from_slice(&data);
        assert_eq!(ctx.data_len(), 5);
    }

    #[test]
    fn empty_context() {
        let ctx = BpfContext::empty();
        assert_eq!(ctx.data_len(), 0);
    }
}
