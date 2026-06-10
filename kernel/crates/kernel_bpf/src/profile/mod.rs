//! Physical Reality Profiles
//!
//! Build-time selection that defines:
//! - What the kernel may assume (power, memory, latency)
//! - What the kernel must guarantee
//! - What the kernel must forbid
//!
//! # Architecture
//!
//! Profiles use sealed traits to prevent external implementations, ensuring that
//! all profile-related behavior is controlled at compile time through feature flags.
//!
//! # Compile-Time Erasure
//!
//! Profile-inappropriate code paths are completely removed at compile time through:
//! - Feature-gated modules
//! - Associated type bounds
//! - Const generic parameters
//!
//! # Example
//!
//! ```rust,ignore
//! use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
//!
//! // Stack size is determined at compile time by the active profile
//! const STACK_SIZE: usize = ActiveProfile::MAX_STACK_SIZE;
//!
//! // JIT availability is a compile-time constant
//! if ActiveProfile::JIT_ALLOWED {
//!     // This code is erased in embedded profile
//! }
//! ```

mod failure;
mod memory;
mod scheduler;

pub use failure::{FailureSemantic, RecoveryRequired, RestartAcceptable};
pub use memory::{ElasticMemory, MemoryStrategy, StaticMemory};
pub use scheduler::{DeadlineAware, SchedulerPolicy, ThroughputOptimized};

/// Sealed trait module to prevent external implementations of profile traits.
mod sealed {
    pub trait Sealed {}
}

/// Marker trait for physical reality profiles.
///
/// This trait defines the contract between the kernel and the physical reality
/// it operates in. Each profile specifies:
///
/// - Resource assumptions (memory, power, latency)
/// - Guarantees the kernel must provide
/// - Operations that are forbidden
///
/// # Sealed Trait
///
/// This trait is sealed and cannot be implemented outside this crate.
/// Only `CloudProfile` and `EmbeddedProfile` are valid implementations.
///
/// # Associated Types
///
/// Each profile has associated types that encode its capabilities:
/// - `MemoryStrategy`: How memory is allocated (elastic vs static)
/// - `SchedulerPolicy`: How programs are scheduled (throughput vs deadline)
/// - `FailureSemantic`: How failures are handled (restart vs recovery)
///
/// # Associated Constants
///
/// Constants define hard limits enforced at compile time:
/// - `MAX_STACK_SIZE`: Maximum BPF stack in bytes
/// - `MAX_INSN_COUNT`: Maximum instructions (for WCET in embedded)
/// - `JIT_ALLOWED`: Whether JIT compilation is permitted
/// - `RESTART_ACCEPTABLE`: Whether restart is a valid failure recovery
pub trait PhysicalProfile: sealed::Sealed + 'static {
    /// Memory allocation strategy for this profile.
    type MemoryStrategy: MemoryStrategy;

    /// Scheduler policy for this profile.
    type SchedulerPolicy: SchedulerPolicy;

    /// Failure handling semantics for this profile.
    type FailureSemantic: FailureSemantic;

    /// Maximum BPF stack size in bytes.
    ///
    /// - Cloud: 512KB (elastic, can grow)
    /// - Embedded: 8KB (static, fixed at init)
    const MAX_STACK_SIZE: usize;

    /// Maximum instruction count for BPF programs.
    ///
    /// This bounds worst-case execution time in embedded profile.
    /// - Cloud: 1,000,000 (soft limit)
    /// - Embedded: 100,000 (hard limit for WCET)
    const MAX_INSN_COUNT: usize;

    /// Whether JIT compilation is allowed.
    ///
    /// - Cloud: true (JIT is default execution mode)
    /// - Embedded: false (interpreter or AOT only)
    const JIT_ALLOWED: bool;

    /// Whether restart is an acceptable failure recovery mechanism.
    ///
    /// - Cloud: true (restart is normal recovery)
    /// - Embedded: false (restart may be catastrophic, recovery required)
    const RESTART_ACCEPTABLE: bool;

    /// Per-program WCET budget in cycle units (#43).
    ///
    /// A program whose static worst-case execution cost
    /// (`VerifyStats::wcet_cycles`, the longest path through the loop-free
    /// CFG priced by `verifier::cost`) exceeds this budget is rejected at
    /// verification with `WcetExceeded`. Units are the cost model's relative
    /// cycle units, pending A76 calibration — retune this alongside the
    /// `COST_*` constants once measured cycles/op exist.
    ///
    /// - Cloud: effectively unlimited (timing is not a cloud contract)
    /// - Embedded: 100,000 units ≈ 100k cheap-ALU instructions, or ~6k map
    ///   lookups — generous for real robot extensions (≪10k instructions)
    ///   while still bounding adversarial helper-heavy programs.
    const WCET_CYCLE_BUDGET: u64;

    /// Profile name for diagnostics and logging.
    const NAME: &'static str;
}

/// Cloud profile: elastic resources, soft bounds, restart acceptable.
///
/// # Assumptions
///
/// - Power is effectively infinite (datacenter)
/// - Memory is elastic (can grow as needed)
/// - Latency bounds are soft (best-effort)
/// - Restart is an acceptable failure recovery
///
/// # Guarantees
///
/// - High throughput via JIT compilation
/// - Fair scheduling across programs
/// - Dynamic resource allocation
///
/// # Build-Time Selection
///
/// ```bash
/// cargo build --features cloud-profile
/// ```
pub struct CloudProfile;

impl sealed::Sealed for CloudProfile {}

impl PhysicalProfile for CloudProfile {
    type MemoryStrategy = ElasticMemory;
    type SchedulerPolicy = ThroughputOptimized;
    type FailureSemantic = RestartAcceptable;

    /// 512KB stack for cloud workloads
    const MAX_STACK_SIZE: usize = 512 * 1024;

    /// 1 million instructions (soft limit)
    const MAX_INSN_COUNT: usize = 1_000_000;

    /// JIT enabled by default
    const JIT_ALLOWED: bool = true;

    /// Restart is normal recovery
    const RESTART_ACCEPTABLE: bool = true;

    /// Timing is not a cloud contract; effectively unlimited.
    const WCET_CYCLE_BUDGET: u64 = u64::MAX;

    const NAME: &'static str = "cloud";
}

/// Embedded profile: static resources, hard bounds, recovery required.
///
/// # Assumptions
///
/// - Power is finite or intermittent
/// - Memory is statically bounded
/// - Latency bounds are hard (real-time deadlines)
/// - Restart may be impossible or catastrophic
///
/// # Guarantees
///
/// - Predictable execution time (WCET bounded)
/// - Deadline-aware scheduling
/// - Energy-aware execution
/// - Recovery partition for failures
///
/// # Build-Time Selection
///
/// ```bash
/// cargo build --features embedded-profile
/// ```
pub struct EmbeddedProfile;

impl sealed::Sealed for EmbeddedProfile {}

impl PhysicalProfile for EmbeddedProfile {
    type MemoryStrategy = StaticMemory;
    type SchedulerPolicy = DeadlineAware;
    type FailureSemantic = RecoveryRequired;

    /// 8KB stack for embedded constraints
    const MAX_STACK_SIZE: usize = 8 * 1024;

    /// 100K instructions (hard limit for WCET)
    const MAX_INSN_COUNT: usize = 100_000;

    /// No JIT - interpreter or AOT only
    const JIT_ALLOWED: bool = false;

    /// Restart is forbidden - must use recovery partition
    const RESTART_ACCEPTABLE: bool = false;

    /// Placeholder budget in relative cycle units, pending A76 calibration.
    const WCET_CYCLE_BUDGET: u64 = 100_000;

    const NAME: &'static str = "embedded";
}

// Type alias for the active profile based on feature flags.
// This allows code to reference `ActiveProfile` without knowing which profile is selected.

/// The currently active profile based on build-time feature selection.
///
/// This type alias resolves to either `CloudProfile` or `EmbeddedProfile`
/// depending on which feature flag is enabled.
///
/// # Usage
///
/// ```rust,ignore
/// use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};
///
/// // Access profile constants
/// let max_stack = ActiveProfile::MAX_STACK_SIZE;
/// let can_jit = ActiveProfile::JIT_ALLOWED;
/// ```
#[cfg(feature = "cloud-profile")]
pub type ActiveProfile = CloudProfile;

/// The currently active profile based on build-time feature selection.
#[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
pub type ActiveProfile = EmbeddedProfile;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_constants_are_consistent() {
        // Verify that the active profile has sensible constants
        assert!(ActiveProfile::MAX_STACK_SIZE > 0);
        assert!(ActiveProfile::MAX_INSN_COUNT > 0);

        // Profile name should be non-empty
        assert!(!ActiveProfile::NAME.is_empty());
    }

    #[cfg(feature = "cloud-profile")]
    #[test]
    fn cloud_profile_allows_jit() {
        assert!(CloudProfile::JIT_ALLOWED);
        assert!(CloudProfile::RESTART_ACCEPTABLE);
    }

    #[cfg(feature = "embedded-profile")]
    #[test]
    fn embedded_profile_forbids_jit() {
        assert!(!EmbeddedProfile::JIT_ALLOWED);
        assert!(!EmbeddedProfile::RESTART_ACCEPTABLE);
    }
}
