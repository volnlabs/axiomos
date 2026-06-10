//! Helper Function Registry
//!
//! This module defines BPF helper function signatures and provides validation
//! for helper calls during verification. Each helper has a defined signature
//! specifying argument types and return type.
//!
//! # Helper Categories
//!
//! - **Core**: Basic operations (time, random, CPU ID)
//! - **Map**: Map operations (lookup, update, delete)
//! - **Probe**: Memory probing (probe_read)
//! - **Process**: Process information (PID, UID, comm)
//! - **Robotics**: rkBPF-specific helpers for robotics use cases
//!
//! # Profile Availability
//!
//! Some helpers are only available in certain profiles:
//! - Cloud: All helpers available
//! - Embedded: Restricted set (no dynamic allocation helpers)

use super::state::{RegState, RegType};

/// Helper function identifier.
///
/// These IDs match the standard BPF helper IDs where applicable,
/// with rkBPF extensions starting at 1000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum HelperId {
    // ===== Core Helpers =====
    // SINGLE SOURCE OF TRUTH for helper IDs. These numbers ARE the runtime ABI:
    // the interpreter's `call_helper` dispatch (execution/interpreter.rs) matches
    // on these exact values, and `execution::HelperFunc` aliases this enum. Do not
    // renumber without changing dispatch — the verifier would then type-check
    // against the wrong helper (the #121 unsoundness). Guarded by
    // `helper_ids_match_runtime_abi`.
    /// Get current time in nanoseconds
    KtimeGetNs = 1,
    /// Print debug message (debug builds only)
    TracePrintk = 2,
    /// Get pseudo-random u32
    GetPrandomU32 = 3,
    /// Get current CPU ID
    GetSmpProcessorId = 4,
    /// Look up element in map
    MapLookupElem = 5,
    /// Update element in map
    MapUpdateElem = 6,
    /// Delete element from map
    MapDeleteElem = 7,
    /// Output to ring buffer (reserve + submit)
    RingbufOutput = 8,
    /// Push value to time-series map
    TimeseriesPush = 9,

    // ===== Process Helpers =====
    /// Get current PID and TGID
    GetCurrentPidTgid = 10,
    /// Get current UID and GID
    GetCurrentUidGid = 11,
    /// Get current process command name
    GetCurrentComm = 12,

    // ===== Kernel Introspection Helpers =====
    /// Get interrupt latency in nanoseconds
    GetInterruptLatencyNs = 13,
    /// Read from arbitrary memory (with safety checks)
    ProbeRead = 14,
    /// Get boot time in milliseconds
    GetBootTimeMs = 15,
    /// Get kernel heap usage in KB
    GetKernelHeapKb = 16,
    /// Get kernel image size in MB
    GetKernelImageMb = 17,

    // ===== Ring Buffer Helpers (Advanced) =====
    // Verifier-known but not yet dispatched by the interpreter; numbers reserved.
    /// Reserve space in ring buffer
    RingbufReserve = 40,
    /// Submit reserved ring buffer entry
    RingbufSubmit = 41,
    /// Discard reserved ring buffer entry
    RingbufDiscard = 42,

    // ===== rkBPF Robotics Helpers (1000+) =====
    /// Emergency stop all motors
    MotorEmergencyStop = 1000,
    /// Get last timestamp from sensor
    SensorLastTimestamp = 1002,
    /// Set GPIO pin state
    GpioSet = 1003,
    /// Read GPIO pin state
    GpioGet = 1004,
    /// Write to PWM channel
    PwmWrite = 1005,
    /// Read IIO sensor value
    IioRead = 1006,
    /// Send CAN message
    CanSend = 1007,
}

impl HelperId {
    /// Try to convert from raw helper ID.
    pub fn from_raw(id: i32) -> Option<Self> {
        match id {
            1 => Some(Self::KtimeGetNs),
            2 => Some(Self::TracePrintk),
            3 => Some(Self::GetPrandomU32),
            4 => Some(Self::GetSmpProcessorId),
            5 => Some(Self::MapLookupElem),
            6 => Some(Self::MapUpdateElem),
            7 => Some(Self::MapDeleteElem),
            8 => Some(Self::RingbufOutput),
            9 => Some(Self::TimeseriesPush),
            10 => Some(Self::GetCurrentPidTgid),
            11 => Some(Self::GetCurrentUidGid),
            12 => Some(Self::GetCurrentComm),
            13 => Some(Self::GetInterruptLatencyNs),
            14 => Some(Self::ProbeRead),
            15 => Some(Self::GetBootTimeMs),
            16 => Some(Self::GetKernelHeapKb),
            17 => Some(Self::GetKernelImageMb),
            40 => Some(Self::RingbufReserve),
            41 => Some(Self::RingbufSubmit),
            42 => Some(Self::RingbufDiscard),
            1000 => Some(Self::MotorEmergencyStop),
            1002 => Some(Self::SensorLastTimestamp),
            1003 => Some(Self::GpioSet),
            1004 => Some(Self::GpioGet),
            1005 => Some(Self::PwmWrite),
            1006 => Some(Self::IioRead),
            1007 => Some(Self::CanSend),
            _ => None,
        }
    }

    /// Get the helper name for error messages.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::KtimeGetNs => "bpf_ktime_get_ns",
            Self::TracePrintk => "bpf_trace_printk",
            Self::GetPrandomU32 => "bpf_get_prandom_u32",
            Self::GetSmpProcessorId => "bpf_get_smp_processor_id",
            Self::MapLookupElem => "bpf_map_lookup_elem",
            Self::MapUpdateElem => "bpf_map_update_elem",
            Self::MapDeleteElem => "bpf_map_delete_elem",
            Self::ProbeRead => "bpf_probe_read",
            Self::GetCurrentPidTgid => "bpf_get_current_pid_tgid",
            Self::GetCurrentUidGid => "bpf_get_current_uid_gid",
            Self::GetCurrentComm => "bpf_get_current_comm",
            Self::GetInterruptLatencyNs => "bpf_get_interrupt_latency_ns",
            Self::GetBootTimeMs => "bpf_get_boot_time_ms",
            Self::GetKernelHeapKb => "bpf_get_kernel_heap_kb",
            Self::GetKernelImageMb => "bpf_get_kernel_image_mb",
            Self::RingbufReserve => "bpf_ringbuf_reserve",
            Self::RingbufSubmit => "bpf_ringbuf_submit",
            Self::RingbufDiscard => "bpf_ringbuf_discard",
            Self::RingbufOutput => "bpf_ringbuf_output",
            Self::MotorEmergencyStop => "bpf_motor_emergency_stop",
            Self::TimeseriesPush => "bpf_timeseries_push",
            Self::SensorLastTimestamp => "bpf_sensor_last_timestamp",
            Self::GpioSet => "bpf_gpio_set",
            Self::GpioGet => "bpf_gpio_get",
            Self::PwmWrite => "bpf_pwm_write",
            Self::IioRead => "bpf_iio_read",
            Self::CanSend => "bpf_can_send",
        }
    }

    /// Check if this helper is available in embedded profile.
    #[cfg(feature = "embedded-profile")]
    pub const fn available_in_embedded(&self) -> bool {
        match self {
            // Core helpers - all available
            Self::KtimeGetNs => true,
            Self::GetPrandomU32 => true,
            Self::GetSmpProcessorId => true,

            // Map helpers - all available
            Self::MapLookupElem => true,
            Self::MapUpdateElem => true,
            Self::MapDeleteElem => true,

            // Debug helpers - disabled in embedded
            Self::TracePrintk => false,

            // Probe helpers - available but restricted
            Self::ProbeRead => true,

            // Process helpers - available
            Self::GetCurrentPidTgid => true,
            Self::GetCurrentUidGid => true,
            Self::GetCurrentComm => true,

            // Kernel introspection - available
            Self::GetInterruptLatencyNs => true,
            Self::GetBootTimeMs => true,
            Self::GetKernelHeapKb => true,
            Self::GetKernelImageMb => true,

            // Ring buffer - reserve disabled (dynamic alloc)
            Self::RingbufReserve => false,
            Self::RingbufSubmit => true,
            Self::RingbufDiscard => true,
            Self::RingbufOutput => true,

            // Robotics helpers - all available
            Self::MotorEmergencyStop => true,
            Self::TimeseriesPush => true,
            Self::SensorLastTimestamp => true,
            Self::GpioSet => true,
            Self::GpioGet => true,
            Self::PwmWrite => true,
            Self::IioRead => true,
            Self::CanSend => true,
        }
    }

    /// Check if this helper is available in cloud profile.
    #[cfg(feature = "cloud-profile")]
    pub const fn available_in_cloud(&self) -> bool {
        // All helpers available in cloud profile
        true
    }

    /// Check if helper is available in the current profile.
    pub const fn is_available(&self) -> bool {
        #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
        {
            self.available_in_embedded()
        }
        #[cfg(feature = "cloud-profile")]
        {
            self.available_in_cloud()
        }
    }
}

/// Argument type for helper functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// Any scalar value (integer)
    Scalar,
    /// Pointer to map
    PtrToMap,
    /// Pointer to map key (read-only)
    PtrToMapKey,
    /// Pointer to map value
    PtrToMapValue,
    /// Pointer to stack memory
    PtrToStack,
    /// Pointer to memory (generic, with size)
    PtrToMem,
    /// Pointer to memory or null
    PtrToMemOrNull,
    /// Size of memory buffer (paired with PtrToMem)
    MemSize,
    /// Pointer to context
    PtrToCtx,
    /// Any pointer type
    AnyPtr,
    /// Constant value (flags, etc.)
    Const,
    /// Ring buffer pointer
    PtrToRingbuf,
    /// Reserved ring buffer entry
    PtrToRingbufSample,
}

impl ArgType {
    /// Check if a register type is compatible with this argument type.
    pub fn is_compatible(&self, reg_type: RegType) -> bool {
        match self {
            Self::Scalar | Self::MemSize | Self::Const => {
                matches!(reg_type, RegType::Scalar)
            }
            Self::PtrToMap => matches!(reg_type, RegType::ConstPtrToMap),
            // Frame-pointer-derived pointers (`mov rX, r10` keeps `PtrToFp`)
            // are stack pointers and accepted wherever one is — consistent
            // with the `PtrToStack` arm below.
            Self::PtrToMapKey => {
                matches!(
                    reg_type,
                    RegType::PtrToMapKey | RegType::PtrToStack | RegType::PtrToFp
                )
            }
            Self::PtrToMapValue => {
                matches!(
                    reg_type,
                    RegType::PtrToMapValue | RegType::PtrToStack | RegType::PtrToFp
                )
            }
            Self::PtrToStack => matches!(reg_type, RegType::PtrToStack | RegType::PtrToFp),
            Self::PtrToMem => {
                matches!(
                    reg_type,
                    RegType::PtrToStack
                        | RegType::PtrToMapValue
                        | RegType::PtrToPacket
                        | RegType::PtrToCtx
                )
            }
            Self::PtrToMemOrNull => {
                matches!(
                    reg_type,
                    RegType::PtrToStack
                        | RegType::PtrToMapValue
                        | RegType::PtrToPacket
                        | RegType::PtrToCtx
                        | RegType::NullPtr
                        | RegType::Scalar // Allow scalar 0 as null
                )
            }
            Self::PtrToCtx => matches!(reg_type, RegType::PtrToCtx),
            Self::AnyPtr => reg_type.is_pointer(),
            Self::PtrToRingbuf => {
                // Ring buffer map pointer
                matches!(reg_type, RegType::ConstPtrToMap | RegType::PtrToMapValue)
            }
            Self::PtrToRingbufSample => {
                // Reserved sample pointer (returned by ringbuf_reserve)
                matches!(reg_type, RegType::PtrToMapValue)
            }
        }
    }
}

/// Return type for helper functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnType {
    /// Returns an integer/scalar
    Integer,
    /// Returns pointer to map value (may be NULL)
    PtrToMapValueOrNull,
    /// Returns pointer to allocated memory (may be NULL)
    PtrToAllocMemOrNull,
    /// Returns void (always 0)
    Void,
}

impl ReturnType {
    /// Convert return type to register state.
    ///
    /// `map_value_size` is the accessible byte size attached to map-value /
    /// allocated-memory pointers (from `VerifyConfig::map_value_size`). Those
    /// pointers are marked **maybe-null** because `bpf_map_lookup_elem` /
    /// `bpf_ringbuf_reserve` can return NULL; `verify_memory` rejects any
    /// dereference until a null check (`if r != 0`) clears the flag on that
    /// branch. This replaces the previous behavior of collapsing every
    /// pointer return to an untracked scalar.
    pub fn to_reg_state(&self, map_value_size: u32) -> RegState {
        match self {
            Self::Integer | Self::Void => {
                RegState::scalar(Some(super::state::ScalarValue::unknown()))
            }
            Self::PtrToMapValueOrNull | Self::PtrToAllocMemOrNull => {
                RegState::map_value(map_value_size, true)
            }
        }
    }
}

/// Helper function signature.
#[derive(Debug, Clone)]
pub struct HelperSignature {
    /// Helper ID
    pub id: HelperId,
    /// Argument types (up to 5 arguments, R1-R5)
    pub args: &'static [ArgType],
    /// Return type
    pub ret: ReturnType,
}

impl HelperSignature {
    /// Create a new helper signature.
    const fn new(id: HelperId, args: &'static [ArgType], ret: ReturnType) -> Self {
        Self { id, args, ret }
    }

    /// Number of arguments.
    pub fn arg_count(&self) -> usize {
        self.args.len()
    }
}

/// Get the signature for a helper function.
pub fn get_helper_signature(id: HelperId) -> HelperSignature {
    match id {
        // Core helpers
        HelperId::KtimeGetNs => HelperSignature::new(id, &[], ReturnType::Integer),

        HelperId::TracePrintk => HelperSignature::new(
            id,
            &[ArgType::PtrToMem, ArgType::MemSize],
            ReturnType::Integer,
        ),

        HelperId::GetPrandomU32 => HelperSignature::new(id, &[], ReturnType::Integer),

        HelperId::GetSmpProcessorId => HelperSignature::new(id, &[], ReturnType::Integer),

        // Map helpers
        HelperId::MapLookupElem => HelperSignature::new(
            id,
            &[ArgType::Scalar, ArgType::PtrToMapKey],
            ReturnType::PtrToMapValueOrNull,
        ),

        HelperId::MapUpdateElem => HelperSignature::new(
            id,
            &[
                ArgType::Scalar,
                ArgType::PtrToMapKey,
                ArgType::PtrToMapValue,
                ArgType::Const,
            ],
            ReturnType::Integer,
        ),

        HelperId::MapDeleteElem => HelperSignature::new(
            id,
            &[ArgType::Scalar, ArgType::PtrToMapKey],
            ReturnType::Integer,
        ),

        // Memory helpers
        HelperId::ProbeRead => HelperSignature::new(
            id,
            &[ArgType::PtrToStack, ArgType::MemSize, ArgType::AnyPtr],
            ReturnType::Integer,
        ),

        // Process helpers
        HelperId::GetCurrentPidTgid => HelperSignature::new(id, &[], ReturnType::Integer),

        HelperId::GetCurrentUidGid => HelperSignature::new(id, &[], ReturnType::Integer),

        HelperId::GetCurrentComm => HelperSignature::new(
            id,
            &[ArgType::PtrToStack, ArgType::MemSize],
            ReturnType::Integer,
        ),

        // Kernel introspection helpers (interpreter injects ctx; no BPF args)
        HelperId::GetInterruptLatencyNs => HelperSignature::new(id, &[], ReturnType::Integer),
        HelperId::GetBootTimeMs => HelperSignature::new(id, &[], ReturnType::Integer),
        HelperId::GetKernelHeapKb => HelperSignature::new(id, &[], ReturnType::Integer),
        HelperId::GetKernelImageMb => HelperSignature::new(id, &[], ReturnType::Integer),

        // Ring buffer helpers
        HelperId::RingbufReserve => HelperSignature::new(
            id,
            &[ArgType::PtrToRingbuf, ArgType::Scalar, ArgType::Const],
            ReturnType::PtrToAllocMemOrNull,
        ),

        HelperId::RingbufSubmit => HelperSignature::new(
            id,
            &[ArgType::PtrToRingbufSample, ArgType::Const],
            ReturnType::Void,
        ),

        HelperId::RingbufDiscard => HelperSignature::new(
            id,
            &[ArgType::PtrToRingbufSample, ArgType::Const],
            ReturnType::Void,
        ),

        HelperId::RingbufOutput => HelperSignature::new(
            id,
            &[
                ArgType::Scalar,
                ArgType::PtrToMem,
                ArgType::MemSize,
                ArgType::Const,
            ],
            ReturnType::Integer,
        ),

        // Robotics helpers
        HelperId::MotorEmergencyStop => {
            HelperSignature::new(id, &[ArgType::Scalar], ReturnType::Integer)
        }

        HelperId::TimeseriesPush => HelperSignature::new(
            id,
            &[
                ArgType::Scalar,
                ArgType::PtrToMapKey,
                ArgType::PtrToMapValue,
            ],
            ReturnType::Integer,
        ),

        HelperId::SensorLastTimestamp => {
            HelperSignature::new(id, &[ArgType::Scalar], ReturnType::Integer)
        }

        HelperId::GpioSet => {
            HelperSignature::new(id, &[ArgType::Scalar, ArgType::Scalar], ReturnType::Integer)
        }

        HelperId::GpioGet => HelperSignature::new(id, &[ArgType::Scalar], ReturnType::Integer),

        HelperId::PwmWrite => HelperSignature::new(
            id,
            &[ArgType::Scalar, ArgType::Scalar, ArgType::Scalar],
            ReturnType::Integer,
        ),

        HelperId::IioRead => HelperSignature::new(
            id,
            &[ArgType::Scalar, ArgType::PtrToStack, ArgType::MemSize],
            ReturnType::Integer,
        ),

        HelperId::CanSend => HelperSignature::new(
            id,
            &[ArgType::Scalar, ArgType::PtrToMem, ArgType::MemSize],
            ReturnType::Integer,
        ),
    }
}

/// Result of helper validation.
#[derive(Debug, Clone)]
pub enum HelperValidation {
    /// Helper call is valid
    Valid(HelperSignature),
    /// Unknown helper ID
    UnknownHelper(i32),
    /// Helper not available in current profile
    NotAvailable(HelperId),
    /// Wrong number of arguments
    WrongArgCount {
        helper: HelperId,
        expected: usize,
        got: usize,
    },
    /// Argument type mismatch
    ArgTypeMismatch {
        helper: HelperId,
        arg_idx: usize,
        expected: ArgType,
        got: RegType,
    },
}

/// Validate a helper call.
///
/// # Arguments
///
/// * `helper_id` - Raw helper ID from the call instruction
/// * `arg_types` - Register types for R1-R5 (only used args need valid types)
///
/// # Returns
///
/// `HelperValidation::Valid` with signature if valid, or specific error.
pub fn validate_helper_call(helper_id: i32, arg_types: &[RegType; 5]) -> HelperValidation {
    // Check if helper ID is known
    let Some(id) = HelperId::from_raw(helper_id) else {
        return HelperValidation::UnknownHelper(helper_id);
    };

    // Check profile availability
    if !id.is_available() {
        return HelperValidation::NotAvailable(id);
    }

    // Get signature
    let sig = get_helper_signature(id);

    // Validate arguments
    for (idx, expected_type) in sig.args.iter().enumerate() {
        let got_type = arg_types[idx];
        if !expected_type.is_compatible(got_type) {
            return HelperValidation::ArgTypeMismatch {
                helper: id,
                arg_idx: idx,
                expected: *expected_type,
                got: got_type,
            };
        }
    }

    HelperValidation::Valid(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_id_from_raw() {
        assert_eq!(HelperId::from_raw(1), Some(HelperId::KtimeGetNs));
        assert_eq!(HelperId::from_raw(5), Some(HelperId::MapLookupElem));
        assert_eq!(HelperId::from_raw(1000), Some(HelperId::MotorEmergencyStop));
        assert_eq!(HelperId::from_raw(9999), None);
    }

    /// Regression guard for #121: the verifier's helper IDs MUST equal the
    /// interpreter's `call_helper` dispatch numbers (execution/interpreter.rs).
    /// If they diverge, the verifier type-checks a call against the wrong
    /// helper's signature — a live unsoundness on every load.
    #[test]
    fn helper_ids_match_runtime_abi() {
        assert_eq!(HelperId::from_raw(3), Some(HelperId::GetPrandomU32));
        assert_eq!(HelperId::from_raw(4), Some(HelperId::GetSmpProcessorId));
        assert_eq!(HelperId::from_raw(5), Some(HelperId::MapLookupElem));
        assert_eq!(HelperId::from_raw(6), Some(HelperId::MapUpdateElem));
        assert_eq!(HelperId::from_raw(7), Some(HelperId::MapDeleteElem));
        assert_eq!(HelperId::from_raw(8), Some(HelperId::RingbufOutput));
        assert_eq!(HelperId::from_raw(9), Some(HelperId::TimeseriesPush));
        assert_eq!(
            HelperId::from_raw(13),
            Some(HelperId::GetInterruptLatencyNs)
        );
        assert_eq!(HelperId::from_raw(14), Some(HelperId::ProbeRead));
        assert_eq!(HelperId::from_raw(15), Some(HelperId::GetBootTimeMs));
        assert_eq!(HelperId::from_raw(16), Some(HelperId::GetKernelHeapKb));
        assert_eq!(HelperId::from_raw(17), Some(HelperId::GetKernelImageMb));
        assert_eq!(HelperId::from_raw(1003), Some(HelperId::GpioSet));
        assert_eq!(HelperId::from_raw(1004), Some(HelperId::GpioGet));
        assert_eq!(HelperId::from_raw(1005), Some(HelperId::PwmWrite));
    }

    #[test]
    fn helper_signature_ktime() {
        let sig = get_helper_signature(HelperId::KtimeGetNs);
        assert_eq!(sig.args.len(), 0);
        assert_eq!(sig.ret, ReturnType::Integer);
    }

    #[test]
    fn helper_signature_map_lookup() {
        let sig = get_helper_signature(HelperId::MapLookupElem);
        assert_eq!(sig.args.len(), 2);
        assert_eq!(sig.args[0], ArgType::Scalar);
        assert_eq!(sig.args[1], ArgType::PtrToMapKey);
        assert_eq!(sig.ret, ReturnType::PtrToMapValueOrNull);
    }

    #[test]
    fn validate_ktime_get_ns() {
        let args = [RegType::NotInit; 5];
        let result = validate_helper_call(1, &args);
        assert!(matches!(result, HelperValidation::Valid(_)));
    }

    #[test]
    fn validate_map_lookup_valid() {
        let mut args = [RegType::NotInit; 5];
        args[0] = RegType::Scalar; // R1 = map ID
        args[1] = RegType::PtrToStack; // R2 = key on stack

        let result = validate_helper_call(5, &args); // 5 = map_lookup_elem (ABI)
        assert!(matches!(result, HelperValidation::Valid(_)));
    }

    #[test]
    fn validate_map_lookup_invalid_arg() {
        let mut args = [RegType::NotInit; 5];
        args[0] = RegType::PtrToStack; // Wrong! Should be map ID (Scalar)
        args[1] = RegType::PtrToStack;

        let result = validate_helper_call(5, &args); // 5 = map_lookup_elem (ABI)
        assert!(matches!(
            result,
            HelperValidation::ArgTypeMismatch { arg_idx: 0, .. }
        ));
    }

    #[test]
    fn validate_unknown_helper() {
        let args = [RegType::NotInit; 5];
        let result = validate_helper_call(9999, &args);
        assert!(matches!(result, HelperValidation::UnknownHelper(9999)));
    }

    #[test]
    fn arg_type_compatibility() {
        // Scalar accepts scalar
        assert!(ArgType::Scalar.is_compatible(RegType::Scalar));
        assert!(!ArgType::Scalar.is_compatible(RegType::PtrToStack));

        // PtrToMem accepts various pointer types
        assert!(ArgType::PtrToMem.is_compatible(RegType::PtrToStack));
        assert!(ArgType::PtrToMem.is_compatible(RegType::PtrToMapValue));
        assert!(!ArgType::PtrToMem.is_compatible(RegType::Scalar));

        // PtrToMemOrNull accepts null
        assert!(ArgType::PtrToMemOrNull.is_compatible(RegType::NullPtr));
        assert!(ArgType::PtrToMemOrNull.is_compatible(RegType::PtrToStack));
    }

    #[test]
    fn robotics_helpers_available() {
        // Robotics helpers should be defined
        assert!(HelperId::from_raw(1000).is_some());
        assert_eq!(HelperId::from_raw(9), Some(HelperId::TimeseriesPush));

        let sig = get_helper_signature(HelperId::MotorEmergencyStop);
        assert_eq!(sig.args.len(), 1);
        assert_eq!(sig.args[0], ArgType::Scalar);
    }
}
