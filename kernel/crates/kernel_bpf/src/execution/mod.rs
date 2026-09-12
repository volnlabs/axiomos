//! BPF Program Execution
//!
//! This module provides execution engines for BPF programs. The execution
//! strategy is determined at build time by the profile:
//!
//! | Mode        | Cloud Build | Embedded Build |
//! |-------------|-------------|----------------|
//! | JIT         | **erased**  | **erased**     |
//! | Interpreter | primary     | primary        |
//! | AOT         | rare        | encouraged     |
//!
//! # Compile-Time Erasure
//!
//! The unsafe AArch64 JIT is erased from shipped builds. It is available only
//! to explicit `experimental-aarch64-jit` builds while its code-image lifetime
//! and W^X design are being replaced.

extern crate alloc;

mod interpreter;

#[cfg(test)]
#[allow(clippy::missing_safety_doc, improper_ctypes_definitions)]
pub mod helpers_stub {
    extern crate std;

    use core::cell::Cell;
    use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};

    use super::BpfContext;

    std::thread_local! {
        // Each test's synchronous execution owns its map, including raw value pointers.
        static TEST_MAP_VALUE: Cell<u64> = const { Cell::new(0) };
    }

    // PWM-call recorder for behavior semantic tests. Sessions are serialized by
    // REC_LOCK and gated by RECORDING, so concurrent cargo-test threads can't
    // corrupt a recording (no other test executes a pwm program).
    static REC_LOCK: AtomicBool = AtomicBool::new(false);
    static RECORDING: AtomicBool = AtomicBool::new(false);
    static PWM_CH1: AtomicI64 = AtomicI64::new(-1);
    static PWM_CH2: AtomicI64 = AtomicI64::new(-1);

    /// Run `f` with PWM recording on, returning `(left_duty, right_duty)` — the
    /// last duty written to channel 1 / channel 2, or `-1` if none.
    pub fn record_pwm<R>(f: impl FnOnce() -> R) -> (i64, i64) {
        while REC_LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        PWM_CH1.store(-1, Ordering::Relaxed);
        PWM_CH2.store(-1, Ordering::Relaxed);
        RECORDING.store(true, Ordering::Relaxed);
        let _ = f();
        RECORDING.store(false, Ordering::Relaxed);
        let out = (
            PWM_CH1.load(Ordering::Relaxed),
            PWM_CH2.load(Ordering::Relaxed),
        );
        REC_LOCK.store(false, Ordering::Release);
        out
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_ktime_get_ns() -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_interrupt_latency_ns(ctx: *const BpfContext<'_>) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).interrupt_latency_ns() }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_boot_time_ms(ctx: *const BpfContext<'_>) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).boot_time_ms() }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_kernel_heap_kb(ctx: *const BpfContext<'_>) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).kernel_heap_kb() }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_kernel_image_mb(ctx: *const BpfContext<'_>) -> u64 {
        if ctx.is_null() {
            return 0;
        }
        unsafe { (*ctx).kernel_image_mb() }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_trace_printk(_fmt: *const u8, _len: u32) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_lookup_elem(_map_id: u32, _key: *const u8) -> *mut u8 {
        TEST_MAP_VALUE.with(|value| value.as_ptr().cast::<u8>())
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_update_elem(
        _map_id: u32,
        _key: *const u8,
        value: *const u8,
        _flags: u64,
    ) -> i32 {
        if !value.is_null() {
            // SAFETY: The test supplies an initialized eight-byte value through
            // the interpreter's helper ABI. Read the payload so Miri checks that
            // the interpreter actually preserves its pointer's provenance.
            let val = unsafe { core::ptr::read_unaligned(value.cast::<u64>()) };
            TEST_MAP_VALUE.with(|value| value.set(val));
        }
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_map_delete_elem(_map_id: u32, _key: *const u8) -> i32 {
        TEST_MAP_VALUE.with(|value| value.set(0));
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
    pub extern "C" fn bpf_pwm_write(_pwm_id: u32, channel: u32, duty: u32) -> i64 {
        if RECORDING.load(Ordering::Relaxed) {
            match channel {
                1 => PWM_CH1.store(duty as i64, Ordering::Relaxed),
                2 => PWM_CH2.store(duty as i64, Ordering::Relaxed),
                _ => {}
            }
        }
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_motor_pair_v1(left: i32, right: i32) -> i64 {
        if RECORDING.load(Ordering::Relaxed) {
            PWM_CH1.store(left as i64, Ordering::Relaxed);
            PWM_CH2.store(right as i64, Ordering::Relaxed);
        }
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_timeseries_push(_map_id: u32, _key: *const u8, _value: *const u8) -> i64 {
        0
    }

    pub fn get_test_map_value() -> u64 {
        TEST_MAP_VALUE.with(Cell::get)
    }

    pub fn reset_test_map() {
        TEST_MAP_VALUE.with(|value| value.set(0));
    }
}

// JIT is only available for cloud profile
#[cfg(all(feature = "cloud-profile", target_arch = "x86_64"))]
pub mod jit;

// Never select the AArch64 JIT implicitly through a production profile.
#[cfg(any(
    all(target_arch = "aarch64", feature = "experimental-aarch64-jit"),
    test
))]
pub mod jit_aarch64;

use core::marker::PhantomData;

pub use interpreter::Interpreter;
#[cfg(any(
    all(target_arch = "aarch64", feature = "experimental-aarch64-jit"),
    test
))]
pub use jit_aarch64::{Arm64JitCompiler, Arm64JitExecutor};

use crate::bytecode::program::VerifiedProgram;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Private ABI representation passed to BPF programs.
///
/// Keeping the pointers private prevents safe code from forging unrelated
/// `data`/`data_end` pairs. `BpfContext` is transparent over this value, so the
/// bytecode ABI remains data/data_end/data_meta followed by the metric fields.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct RawBpfContext {
    data: *const u8,
    data_end: *const u8,
    data_meta: *const u8,
    interrupt_latency_ns: u64,
    boot_time_ms: u64,
    kernel_heap_kb: u64,
    kernel_image_mb: u64,
}

mod pod_private {
    pub trait Sealed {}
}

/// Marker for context payloads whose complete object representation is
/// initialized data (no implicit or uninitialized padding).
///
/// This trait is sealed; only layouts audited in this crate can be passed to
/// [`BpfContext::from_struct`].
///
/// # Safety
///
/// Implementors must have no uninitialized bytes in their object
/// representation for any valid value.
pub unsafe trait BpfPod: pod_private::Sealed {}

macro_rules! impl_bpf_pod {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl pod_private::Sealed for $ty {}
            // SAFETY: These repr(C) records contain only integer fields and
            // have no implicit padding (IioEvent names its trailing padding).
            unsafe impl BpfPod for $ty {}
        )+
    };
}

/// Execution context passed to BPF programs.
///
/// The lifetime prevents the context from outliving the payload referenced by
/// its private raw pointers. Raw-pointer auto traits are intentionally not
/// overridden; the additional `Rc` marker makes the synchronous context
/// explicitly `!Send + !Sync`.
///
/// ```compile_fail
/// use kernel_bpf::execution::BpfContext;
///
/// fn dangling() -> BpfContext<'static> {
///     let bytes = [1_u8, 2, 3];
///     BpfContext::from_slice(&bytes)
/// }
/// ```
///
/// ```compile_fail
/// use kernel_bpf::execution::BpfContext;
///
/// struct HasPadding {
///     small: u8,
///     large: u64,
/// }
/// let value = HasPadding { small: 1, large: 2 };
/// let _ = BpfContext::from_struct(&value);
/// ```
///
/// ```compile_fail
/// use kernel_bpf::execution::BpfContext;
///
/// fn require_send<T: Send>() {}
/// require_send::<BpfContext<'static>>();
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct BpfContext<'data> {
    raw: RawBpfContext,
    _data: PhantomData<&'data [u8]>,
    _not_send_sync: PhantomData<alloc::rc::Rc<()>>,
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

impl_bpf_pod!(
    SyscallTraceContext,
    SyscallExitContext,
    SchedSwitchContext,
    crate::attach::GpioEvent,
    crate::attach::IioEvent,
    crate::attach::PwmEvent,
);

impl BpfContext<'static> {
    /// Create an empty context.
    pub const fn empty() -> Self {
        Self {
            raw: RawBpfContext {
                data: core::ptr::null(),
                data_end: core::ptr::null(),
                data_meta: core::ptr::null(),
                interrupt_latency_ns: 0,
                boot_time_ms: 0,
                kernel_heap_kb: 0,
                kernel_image_mb: 0,
            },
            _data: PhantomData,
            _not_send_sync: PhantomData,
        }
    }
}

impl<'data> BpfContext<'data> {
    /// Create a context from a data slice.
    pub fn from_slice(data: &'data [u8]) -> Self {
        Self {
            raw: RawBpfContext {
                data: data.as_ptr(),
                // SAFETY: the pointer and length come from the same valid slice.
                data_end: unsafe { data.as_ptr().add(data.len()) },
                data_meta: core::ptr::null(),
                interrupt_latency_ns: 0,
                boot_time_ms: 0,
                kernel_heap_kb: 0,
                kernel_image_mb: 0,
            },
            _data: PhantomData,
            _not_send_sync: PhantomData,
        }
    }

    /// Create a context from an audited byte-safe record.
    pub fn from_struct<T: BpfPod>(value: &'data T) -> Self {
        // SAFETY: BpfPod is sealed to audited layouts with no uninitialized
        // padding, and the returned context retains `value`'s lifetime.
        let data = unsafe {
            core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
        };
        Self::from_slice(data)
    }

    /// Get the data length.
    pub fn data_len(&self) -> usize {
        (self.raw.data_end as usize).saturating_sub(self.raw.data as usize)
    }

    /// Interrupt latency in nanoseconds.
    pub const fn interrupt_latency_ns(&self) -> u64 {
        self.raw.interrupt_latency_ns
    }

    /// Boot time in milliseconds.
    pub const fn boot_time_ms(&self) -> u64 {
        self.raw.boot_time_ms
    }

    /// Kernel heap usage in KiB.
    pub const fn kernel_heap_kb(&self) -> u64 {
        self.raw.kernel_heap_kb
    }

    /// Kernel image size in MiB.
    pub const fn kernel_image_mb(&self) -> u64 {
        self.raw.kernel_image_mb
    }

    /// Set metrics sampled for this synchronous execution.
    pub fn set_kernel_metrics(&mut self, boot_time_ms: u64, heap_kb: u64, image_mb: u64) {
        self.raw.boot_time_ms = boot_time_ms;
        self.raw.kernel_heap_kb = heap_kb;
        self.raw.kernel_image_mb = image_mb;
    }

    /// Set the sampled interrupt latency.
    pub fn set_interrupt_latency_ns(&mut self, latency_ns: u64) {
        self.raw.interrupt_latency_ns = latency_ns;
    }

    pub(crate) const fn data_ptr(&self) -> *const u8 {
        self.raw.data
    }

    pub(crate) const fn data_end_ptr(&self) -> *const u8 {
        self.raw.data_end
    }
}

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

    /// A manager-wide object, byte, dimension, or ID-space quota was reached.
    ResourceLimit,

    /// An object cannot be reclaimed while attached, pinned, or executing.
    ObjectBusy,

    /// The caller does not own the requested object or capability.
    PermissionDenied,

    /// The same CPU attempted nested BPF execution while its scratch stack was live.
    ReentrantExecution,

    /// The program failed static verification and was rejected at load time.
    VerificationFailed,

    /// The program failed signature authentication (untrusted signer, bad
    /// signature, tampered data, or unsigned while enforcement is enabled).
    SignatureRejected,

    /// Attach refused: the hook's WCET admission capacity would be exceeded
    /// (#43). The program is safe but not schedulable on this hook.
    AdmissionRejected,

    /// GPIO attach refused: the route would exceed the fixed IRQ dispatch
    /// fan-out buffer.
    GpioFanoutExceeded,

    /// A map mutation targeted a kernel-marked read-only map.
    ReadOnlyMap,
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
            Self::ResourceLimit => write!(f, "BPF resource limit exceeded"),
            Self::ObjectBusy => write!(f, "BPF object is still in use"),
            Self::PermissionDenied => write!(f, "BPF object permission denied"),
            Self::ReentrantExecution => write!(f, "nested BPF execution on one CPU"),
            Self::VerificationFailed => write!(f, "program failed verification"),
            Self::SignatureRejected => write!(f, "program failed signature authentication"),
            Self::AdmissionRejected => write!(f, "attach exceeds hook WCET admission capacity"),
            Self::GpioFanoutExceeded => write!(f, "GPIO attach exceeds IRQ fan-out capacity"),
            Self::ReadOnlyMap => write!(f, "map is read-only"),
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
    fn execute(&self, program: &VerifiedProgram<P>, ctx: &BpfContext<'_>) -> BpfResult;
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
