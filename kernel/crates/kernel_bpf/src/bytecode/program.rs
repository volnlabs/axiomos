//! BPF Program Representation
//!
//! This module defines the `BpfProgram` type which represents a validated
//! BPF program ready for execution. Programs are parameterized by their
//! profile, which determines compile-time constraints.
//!
//! # Profile Constraints
//!
//! - Stack size is bounded by `P::MAX_STACK_SIZE`
//! - Instruction count is bounded by `P::MAX_INSN_COUNT`
//! - These constraints are enforced at compile time via const generics

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::insn::BpfInsn;
use crate::profile::{ActiveProfile, PhysicalProfile};
use crate::verifier::{VerificationToken, Verifier, VerifyConfig, VerifyError};

/// BPF program types.
///
/// Different program types have different entry points, context types,
/// and allowed helper functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum BpfProgType {
    /// Unspecified program type
    #[default]
    Unspec = 0,
    /// Socket filter programs
    SocketFilter = 1,
    /// Kernel probe programs
    Kprobe = 2,
    /// Scheduler classifier programs
    SchedCls = 3,
    /// Scheduler action programs
    SchedAct = 4,
    /// Tracepoint programs
    Tracepoint = 5,
    /// XDP (eXpress Data Path) programs
    Xdp = 6,
    /// Perf event programs
    PerfEvent = 7,
    /// Cgroup socket programs
    CgroupSkb = 8,
    /// Cgroup socket operations
    CgroupSock = 9,
    /// Lightweight tunnel programs
    LwtIn = 10,
    /// Lightweight tunnel output programs
    LwtOut = 11,
    /// Lightweight tunnel transmit programs
    LwtXmit = 12,
    /// Socket operations programs
    SockOps = 13,
    /// SK_SKB programs
    SkSkb = 14,

    // Profile-specific program types
    /// Real-time programs (embedded only)
    #[cfg(feature = "embedded-profile")]
    RealTime = 100,

    /// Deadline-critical programs (embedded only)
    #[cfg(feature = "embedded-profile")]
    DeadlineCritical = 101,

    /// Cgroup device programs (cloud only)
    #[cfg(feature = "cloud-profile")]
    CgroupDevice = 200,

    /// Socket lookup programs (cloud only)
    #[cfg(feature = "cloud-profile")]
    SkLookup = 201,
}

impl BpfProgType {
    /// Check if this program type requires real-time guarantees.
    #[inline]
    pub const fn requires_realtime(&self) -> bool {
        #[cfg(feature = "embedded-profile")]
        {
            matches!(self, Self::RealTime | Self::DeadlineCritical)
        }
        #[cfg(not(feature = "embedded-profile"))]
        {
            false
        }
    }

    /// Check if this program type is allowed for the current profile.
    #[inline]
    pub fn is_allowed_for_profile<P: PhysicalProfile>(&self) -> bool {
        // All standard types are allowed in both profiles
        match self {
            Self::Unspec
            | Self::SocketFilter
            | Self::Kprobe
            | Self::SchedCls
            | Self::SchedAct
            | Self::Tracepoint
            | Self::Xdp
            | Self::PerfEvent
            | Self::CgroupSkb
            | Self::CgroupSock
            | Self::LwtIn
            | Self::LwtOut
            | Self::LwtXmit
            | Self::SockOps
            | Self::SkSkb => true,

            #[cfg(feature = "embedded-profile")]
            Self::RealTime | Self::DeadlineCritical => true,

            #[cfg(feature = "cloud-profile")]
            Self::CgroupDevice | Self::SkLookup => true,
        }
    }
}

/// Unverified BPF bytecode.
///
/// A raw program can be assembled by safe code, but execution engines do not
/// accept it. Consume it with [`verify`](Self::verify) or
/// [`verify_with_config`](Self::verify_with_config) to obtain a
/// [`VerifiedProgram`].
#[derive(Debug, Clone)]
pub struct RawProgram<P: PhysicalProfile = ActiveProfile> {
    prog_type: BpfProgType,
    insns: Vec<BpfInsn>,
    name: Option<&'static str>,
    _profile: PhantomData<P>,
}

impl<P: PhysicalProfile> RawProgram<P> {
    /// Create unchecked bytecode. This value cannot be executed directly.
    pub fn new(prog_type: BpfProgType, insns: Vec<BpfInsn>) -> Self {
        Self {
            prog_type,
            insns,
            name: None,
            _profile: PhantomData,
        }
    }

    /// Add a diagnostic name without changing the bytecode.
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// Return the unchecked instruction stream.
    pub fn instructions(&self) -> &[BpfInsn] {
        &self.insns
    }

    /// Return the declared program type.
    pub fn prog_type(&self) -> BpfProgType {
        self.prog_type
    }

    /// Verify with conservative defaults and consume the raw program.
    pub fn verify(self) -> Result<VerifiedProgram<P>, VerifyError> {
        self.verify_with_config(VerifyConfig::default())
    }

    /// Verify with explicit context and map bounds and consume the raw program.
    pub fn verify_with_config(
        self,
        config: VerifyConfig<'_>,
    ) -> Result<VerifiedProgram<P>, VerifyError> {
        let mut program = Verifier::<P>::verify_with_config(self.prog_type, &self.insns, config)?;
        if let Some(name) = self.name {
            program = program.with_name(name);
        }
        Ok(program)
    }
}

/// Validated BPF program ready for execution.
///
/// A `BpfProgram` represents a BPF program that has passed verification
/// and is ready to be executed. The program is parameterized by its
/// profile type, which determines compile-time constraints.
///
/// # Type Parameter
///
/// - `P`: The physical profile this program was validated against.
///   Defaults to `ActiveProfile` (the build-time selected profile).
///
/// # Compile-Time Constraints
///
/// The profile enforces these compile-time constraints:
/// - Maximum stack size: `P::MAX_STACK_SIZE`
/// - Maximum instruction count: `P::MAX_INSN_COUNT`
///
/// # Example
///
/// ```rust,ignore
/// use kernel_bpf::bytecode::BpfProgram;
/// use kernel_bpf::profile::ActiveProfile;
///
/// // Create a program for the active profile
/// let raw = RawProgram::<ActiveProfile>::new(BpfProgType::SocketFilter, instructions);
/// let program: VerifiedProgram<ActiveProfile> = raw.verify()?;
/// ```
///
/// Safe callers cannot manufacture this type without running the verifier:
///
/// ```compile_fail
/// use kernel_bpf::bytecode::{BpfInsn, BpfProgType, VerifiedProgram};
/// use kernel_bpf::profile::ActiveProfile;
///
/// let _ = VerifiedProgram::<ActiveProfile>::from_verified_parts(
///     BpfProgType::SocketFilter,
///     Vec::from([BpfInsn::exit()]),
///     0,
/// );
/// ```
pub struct VerifiedProgram<P: PhysicalProfile = ActiveProfile> {
    /// Program type
    prog_type: BpfProgType,
    /// Verified instructions
    insns: Vec<BpfInsn>,
    /// Computed stack size required
    stack_size: usize,
    /// Program name for debugging
    name: Option<&'static str>,
    /// Marker for profile type
    _profile: PhantomData<P>,
}

/// Compatibility name for the verified program artifact.
pub type BpfProgram<P = ActiveProfile> = VerifiedProgram<P>;

impl<P: PhysicalProfile> Clone for VerifiedProgram<P> {
    fn clone(&self) -> Self {
        Self {
            prog_type: self.prog_type,
            insns: self.insns.clone(),
            stack_size: self.stack_size,
            name: self.name,
            _profile: PhantomData,
        }
    }
}

impl<P: PhysicalProfile> VerifiedProgram<P> {
    /// Maximum stack size for this profile.
    pub const MAX_STACK_SIZE: usize = P::MAX_STACK_SIZE;

    /// Maximum instruction count for this profile.
    pub const MAX_INSN_COUNT: usize = P::MAX_INSN_COUNT;

    /// Build a verified program after the verifier has completed every phase.
    ///
    /// # Arguments
    ///
    /// * `prog_type` - The program type
    /// * `insns` - The verified instruction stream
    /// * `stack_size` - The computed stack size required
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack size exceeds profile limit
    /// - Instruction count exceeds profile limit
    /// - Program type is not allowed for this profile
    pub(crate) fn from_verified_parts(
        prog_type: BpfProgType,
        insns: Vec<BpfInsn>,
        stack_size: usize,
        _token: VerificationToken,
    ) -> Result<Self, ProgramError> {
        // Check profile constraints
        if stack_size > Self::MAX_STACK_SIZE {
            return Err(ProgramError::StackSizeExceeded {
                required: stack_size,
                limit: Self::MAX_STACK_SIZE,
            });
        }

        if insns.len() > Self::MAX_INSN_COUNT {
            return Err(ProgramError::InsnCountExceeded {
                count: insns.len(),
                limit: Self::MAX_INSN_COUNT,
            });
        }

        if !prog_type.is_allowed_for_profile::<P>() {
            return Err(ProgramError::ProgramTypeNotAllowed);
        }

        Ok(Self {
            prog_type,
            insns,
            stack_size,
            name: None,
            _profile: PhantomData,
        })
    }

    /// Create a program with a name.
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// Get the program type.
    #[inline]
    pub fn prog_type(&self) -> BpfProgType {
        self.prog_type
    }

    /// Get the instruction stream.
    #[inline]
    pub fn instructions(&self) -> &[BpfInsn] {
        &self.insns
    }

    /// Get the number of instructions.
    #[inline]
    pub fn insn_count(&self) -> usize {
        self.insns.len()
    }

    /// Get the required stack size.
    #[inline]
    pub fn stack_size(&self) -> usize {
        self.stack_size
    }

    /// Get the program name.
    #[inline]
    pub fn name(&self) -> Option<&'static str> {
        self.name
    }

    /// Get the profile name.
    #[inline]
    pub fn profile_name(&self) -> &'static str {
        P::NAME
    }

    /// Check if JIT compilation is allowed for this program's profile.
    #[inline]
    pub const fn jit_allowed(&self) -> bool {
        P::JIT_ALLOWED
    }
}

impl<P: PhysicalProfile> fmt::Debug for VerifiedProgram<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfProgram")
            .field("prog_type", &self.prog_type)
            .field("insn_count", &self.insns.len())
            .field("stack_size", &self.stack_size)
            .field("name", &self.name)
            .field("profile", &P::NAME)
            .finish()
    }
}

/// Errors that can occur when creating or validating a BPF program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    /// Stack size exceeds profile limit.
    StackSizeExceeded {
        /// Required stack size
        required: usize,
        /// Profile limit
        limit: usize,
    },

    /// Instruction count exceeds profile limit.
    InsnCountExceeded {
        /// Actual instruction count
        count: usize,
        /// Profile limit
        limit: usize,
    },

    /// Program type is not allowed for this profile.
    ProgramTypeNotAllowed,

    /// Empty program (no instructions).
    EmptyProgram,

    /// Program does not end with exit instruction.
    NoExitInstruction,

    /// Invalid instruction in program.
    InvalidInstruction {
        /// Index of invalid instruction
        index: usize,
    },

    /// Full static verification rejected the program.
    VerificationFailed(VerifyError),
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackSizeExceeded { required, limit } => {
                write!(f, "stack size {} exceeds profile limit {}", required, limit)
            }
            Self::InsnCountExceeded { count, limit } => {
                write!(
                    f,
                    "instruction count {} exceeds profile limit {}",
                    count, limit
                )
            }
            Self::ProgramTypeNotAllowed => {
                write!(f, "program type not allowed for this profile")
            }
            Self::EmptyProgram => {
                write!(f, "program has no instructions")
            }
            Self::NoExitInstruction => {
                write!(f, "program does not end with exit instruction")
            }
            Self::InvalidInstruction { index } => {
                write!(f, "invalid instruction at index {}", index)
            }
            Self::VerificationFailed(error) => error.fmt(f),
        }
    }
}

impl From<VerifyError> for ProgramError {
    fn from(error: VerifyError) -> Self {
        match error {
            VerifyError::EmptyProgram => Self::EmptyProgram,
            VerifyError::NoExit => Self::NoExitInstruction,
            VerifyError::StackExceeded { used, limit } => Self::StackSizeExceeded {
                required: used,
                limit,
            },
            VerifyError::InsnCountExceeded { count, limit } => {
                Self::InsnCountExceeded { count, limit }
            }
            VerifyError::InvalidOpcode { insn_idx, .. }
            | VerifyError::InvalidRegister { insn_idx, .. } => {
                Self::InvalidInstruction { index: insn_idx }
            }
            other => Self::VerificationFailed(other),
        }
    }
}

/// Builder for constructing BPF programs.
///
/// This is useful for creating test programs or programmatically
/// generating BPF bytecode.
pub struct ProgramBuilder<P: PhysicalProfile = ActiveProfile> {
    prog_type: BpfProgType,
    insns: Vec<BpfInsn>,
    name: Option<&'static str>,
    _profile: PhantomData<P>,
}

impl<P: PhysicalProfile> ProgramBuilder<P> {
    /// Create a new program builder.
    pub fn new(prog_type: BpfProgType) -> Self {
        Self {
            prog_type,
            insns: Vec::new(),
            name: None,
            _profile: PhantomData,
        }
    }

    /// Set the program name.
    pub fn name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// Add an instruction.
    pub fn insn(mut self, insn: BpfInsn) -> Self {
        self.insns.push(insn);
        self
    }

    /// Add multiple instructions.
    pub fn insns(mut self, insns: impl IntoIterator<Item = BpfInsn>) -> Self {
        self.insns.extend(insns);
        self
    }

    /// Add an exit instruction.
    pub fn exit(self) -> Self {
        self.insn(BpfInsn::exit())
    }

    /// Build the program.
    ///
    /// # Errors
    ///
    /// Returns an error if the program violates profile constraints.
    pub fn build(self) -> Result<BpfProgram<P>, ProgramError> {
        self.build_raw().verify().map_err(ProgramError::from)
    }

    /// Build unchecked bytecode for verification with caller-supplied bounds.
    pub fn build_raw(self) -> RawProgram<P> {
        let mut program = RawProgram::new(self.prog_type, self.insns);
        if let Some(name) = self.name {
            program = program.with_name(name);
        }
        program
    }
}

impl<P: PhysicalProfile> Default for ProgramBuilder<P> {
    fn default() -> Self {
        Self::new(BpfProgType::Unspec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_constants() {
        // Verify profile constants are accessible
        let _max_stack: usize = BpfProgram::<ActiveProfile>::MAX_STACK_SIZE;
        let _max_insns: usize = BpfProgram::<ActiveProfile>::MAX_INSN_COUNT;
    }

    #[test]
    fn simple_program() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .name("test")
            .insn(BpfInsn::mov64_imm(0, 0))
            .exit()
            .build()
            .expect("valid program");

        assert_eq!(program.prog_type(), BpfProgType::SocketFilter);
        assert_eq!(program.insn_count(), 2);
        assert_eq!(program.name(), Some("test"));
    }

    #[test]
    fn empty_program_rejected() {
        let result = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter).build();

        assert!(matches!(result, Err(ProgramError::EmptyProgram)));
    }

    #[cfg(feature = "cloud-profile")]
    #[test]
    fn cloud_profile_limits() {
        use crate::profile::CloudProfile;

        assert_eq!(BpfProgram::<CloudProfile>::MAX_STACK_SIZE, 512 * 1024);
        assert_eq!(BpfProgram::<CloudProfile>::MAX_INSN_COUNT, 1_000_000);
    }

    #[cfg(feature = "embedded-profile")]
    #[test]
    fn embedded_profile_limits() {
        use crate::profile::EmbeddedProfile;

        assert_eq!(BpfProgram::<EmbeddedProfile>::MAX_STACK_SIZE, 8 * 1024);
        assert_eq!(BpfProgram::<EmbeddedProfile>::MAX_INSN_COUNT, 100_000);
    }
}
