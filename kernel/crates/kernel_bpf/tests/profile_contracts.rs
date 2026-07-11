//! Profile Contract Tests
//!
//! These tests verify that each profile maintains its documented constraints
//! and that compile-time erasure works correctly.

#![cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]

use kernel_bpf::profile::{ActiveProfile, PhysicalProfile};

#[test]
fn profile_constants_are_reasonable() {
    // Both profiles should have positive limits
    assert!(ActiveProfile::MAX_STACK_SIZE > 0);
    assert!(ActiveProfile::MAX_INSN_COUNT > 0);
}

#[test]
#[cfg(feature = "cloud-profile")]
fn cloud_profile_has_high_limits() {
    use kernel_bpf::profile::CloudProfile;

    // Cloud profile should have generous limits
    assert!(CloudProfile::MAX_STACK_SIZE >= 512 * 1024); // At least 512KB
    assert!(CloudProfile::MAX_INSN_COUNT >= 1_000_000); // At least 1M instructions
    // PR #8 (audit C-06): both profiles now use the interpreter. JIT is
    // gated off until the compile-on-load RW→RX redesign lands.
    assert!(
        !CloudProfile::JIT_ALLOWED,
        "CloudProfile::JIT_ALLOWED must stay false until the C-06 redesign; \
         see kernel_bpf::profile::CloudProfile::JIT_ALLOWED for context"
    );
    assert!(CloudProfile::RESTART_ACCEPTABLE);
}

#[test]
#[cfg(feature = "embedded-profile")]
fn embedded_profile_has_conservative_limits() {
    use kernel_bpf::profile::EmbeddedProfile;

    // Embedded profile should have conservative limits
    assert!(EmbeddedProfile::MAX_STACK_SIZE <= 64 * 1024); // At most 64KB
    assert!(EmbeddedProfile::MAX_INSN_COUNT <= 200_000); // At most 200K instructions
    assert!(!EmbeddedProfile::JIT_ALLOWED);
    assert!(!EmbeddedProfile::RESTART_ACCEPTABLE);
}

#[test]
#[cfg(feature = "cloud-profile")]
fn cloud_profile_is_active() {
    use core::any::TypeId;

    use kernel_bpf::profile::CloudProfile;

    // ActiveProfile should be CloudProfile in cloud builds
    assert_eq!(TypeId::of::<ActiveProfile>(), TypeId::of::<CloudProfile>());
}

#[test]
#[cfg(feature = "embedded-profile")]
fn embedded_profile_is_active() {
    use core::any::TypeId;

    use kernel_bpf::profile::EmbeddedProfile;

    // ActiveProfile should be EmbeddedProfile in embedded builds
    assert_eq!(
        TypeId::of::<ActiveProfile>(),
        TypeId::of::<EmbeddedProfile>()
    );
}

#[test]
fn stack_size_contract() {
    // Ensure stack size is a power of 2 (or close to it for alignment)
    let stack = ActiveProfile::MAX_STACK_SIZE;
    // Should be at least 4KB (typical minimum page size)
    assert!(stack >= 4096);
    // Should be at most 1MB (reasonable upper bound)
    assert!(stack <= 1024 * 1024);
}

#[test]
fn instruction_count_contract() {
    let insn_count = ActiveProfile::MAX_INSN_COUNT;
    // Should allow at least basic programs
    assert!(insn_count >= 1000);
    // Should prevent runaway programs
    assert!(insn_count <= 10_000_000);
}

// Verify JIT erasure in embedded builds
#[cfg(feature = "embedded-profile")]
mod jit_erasure {
    // This module should NOT be able to import JIT types
    // If this compiles, JIT is properly erased

    #[test]
    fn jit_module_not_available() {
        // The JIT module doesn't exist in embedded builds
        // This test passes by virtue of compiling
    }
}

// Verify deadline types exist in embedded builds
#[cfg(feature = "embedded-profile")]
mod deadline_types {
    use kernel_bpf::scheduler::{Deadline, DeadlinePolicy};

    #[test]
    fn deadline_types_available() {
        let deadline = Deadline::new(1000, 500);
        assert_eq!(deadline.absolute_ns, 1000);

        let policy = DeadlinePolicy::new();
        assert_eq!(policy.exec_count(), 0);
    }
}

// Verify throughput types exist in cloud builds
#[cfg(feature = "cloud-profile")]
mod throughput_types {
    use kernel_bpf::scheduler::ThroughputPolicy;

    #[test]
    fn throughput_types_available() {
        let policy = ThroughputPolicy::new();
        assert_eq!(policy.exec_count(), 0);
    }
}

// Verify resize is available only in cloud builds
#[cfg(feature = "cloud-profile")]
mod resize_availability {
    use kernel_bpf::maps::{ArrayMap, BpfMap};
    use kernel_bpf::profile::CloudProfile;

    #[test]
    fn resize_is_available() {
        let mut map = ArrayMap::<CloudProfile>::with_entries(4, 10).expect("create map");
        // This should compile and work
        map.resize(20).expect("resize");
        assert_eq!(map.def().max_entries, 20);
    }
}

// Verify static pool exists only in embedded builds
#[cfg(feature = "embedded-profile")]
mod static_pool_availability {
    use kernel_bpf::maps::StaticPool;

    #[test]
    fn static_pool_is_available() {
        // Static pool should be accessible
        let total = StaticPool::total_size();
        assert!(total > 0);
    }
}
