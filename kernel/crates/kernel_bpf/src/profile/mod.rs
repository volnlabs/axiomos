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
    /// - Embedded: one control-loop period's worth of cycle units
    ///   (`RT_PERIOD_NS / CYCLE_UNIT_NS`) — a single hook invocation that cannot
    ///   fit one period is unschedulable at any frequency, so it is rejected at
    ///   load regardless of admission.
    const WCET_CYCLE_BUDGET: u64;

    /// Calibrated cost of one WCET cycle unit, in nanoseconds, on this profile's
    /// target. The Pi5 A76 JIT measured ~5.74 ns/unit (`docs/benchmarks.md §12`,
    /// straight-line baseline); rounded up to 6 for a conservative bound. Used
    /// to convert a program's `wcet_cycles` into wall-clock time for the
    /// utilization admission test.
    ///
    /// - Cloud: 1 (timing is not a contract; the value never bites because the
    ///   utilization budget is unbounded)
    /// - Embedded: 6 ns/unit
    const CYCLE_UNIT_NS: u64;

    /// The control-loop period this profile schedules hooks against, in
    /// nanoseconds. Sets the per-program WCET budget (one invocation must fit a
    /// period) and the default hook fire frequency for admission.
    ///
    /// - Cloud: effectively unbounded
    /// - Embedded: 1_000_000 ns (a 1 kHz control loop)
    const RT_PERIOD_NS: u64;

    /// CPU-time budget for *all* admitted BPF hooks, in nanoseconds of execution
    /// per wall-clock second — the EDF utilization bound `U` expressed as
    /// `U × 1e9`. The admission ledger keeps `Σ WCETᵢ·freqᵢ` (in ns/s) under it.
    ///
    /// - Cloud: unbounded (admission never rejects)
    /// - Embedded: 500_000_000 (U = 0.5: at most half a core spent in BPF)
    const UTILIZATION_BUDGET_NS_PER_S: u64;

    /// Profile name for diagnostics and logging.
    const NAME: &'static str;

    /// Absolute PWM duty-cycle ceiling (percent) the actuation monitor enforces.
    /// - Cloud: `u32::MAX` (clamp is a no-op; timing/output are not cloud contracts)
    /// - Embedded: 90 (never command full power)
    const ACT_DUTY_MAX: u32;

    /// Maximum change in PWM duty per `ACT_RATE_WINDOW_NS` (slew-rate limit).
    /// - Cloud: `u32::MAX` (no slew limit)
    /// - Embedded: 20 (bounded acceleration)
    const ACT_DUTY_MAX_STEP: u32;

    /// Slew-rate window in nanoseconds. 0 disables slew limiting.
    /// - Cloud: 0 (disabled)
    /// - Embedded: 1_000_000 (one 1 kHz control period)
    const ACT_RATE_WINDOW_NS: u64;
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

    /// Nominal; never bites (utilization budget is unbounded).
    const CYCLE_UNIT_NS: u64 = 1;

    /// No control-loop deadline on the cloud profile.
    const RT_PERIOD_NS: u64 = u64::MAX;

    /// Unbounded: admission never rejects on the cloud profile.
    const UTILIZATION_BUDGET_NS_PER_S: u64 = u64::MAX;

    const NAME: &'static str = "cloud";
    const ACT_DUTY_MAX: u32 = u32::MAX;
    const ACT_DUTY_MAX_STEP: u32 = u32::MAX;
    const ACT_RATE_WINDOW_NS: u64 = 0;
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

    /// One control-loop period's worth of cycle units
    /// (`RT_PERIOD_NS / CYCLE_UNIT_NS` = 1_000_000 / 6 ≈ 166_666): a single hook
    /// invocation that cannot fit one period is unschedulable at any frequency.
    const WCET_CYCLE_BUDGET: u64 = Self::RT_PERIOD_NS / Self::CYCLE_UNIT_NS;

    /// Pi5 A76 JIT: ~5.74 ns/unit measured, rounded up to 6 (docs/benchmarks.md §12).
    const CYCLE_UNIT_NS: u64 = 6;

    /// 1 kHz control loop.
    const RT_PERIOD_NS: u64 = 1_000_000;

    /// U = 0.5: at most half a core spent across all admitted BPF hooks.
    const UTILIZATION_BUDGET_NS_PER_S: u64 = 500_000_000;

    const NAME: &'static str = "embedded";
    const ACT_DUTY_MAX: u32 = 90;
    const ACT_DUTY_MAX_STEP: u32 = 20;
    const ACT_RATE_WINDOW_NS: u64 = 1_000_000;
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

    #[test]
    fn actuation_consts_embedded() {
        assert_eq!(EmbeddedProfile::ACT_DUTY_MAX, 90);
        assert_eq!(EmbeddedProfile::ACT_DUTY_MAX_STEP, 20);
        assert_eq!(EmbeddedProfile::ACT_RATE_WINDOW_NS, 1_000_000);
    }

    #[test]
    fn actuation_consts_cloud_are_noops() {
        assert_eq!(CloudProfile::ACT_DUTY_MAX, u32::MAX);
        assert_eq!(CloudProfile::ACT_DUTY_MAX_STEP, u32::MAX);
        assert_eq!(CloudProfile::ACT_RATE_WINDOW_NS, 0);
    }
}
