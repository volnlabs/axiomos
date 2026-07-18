use core::ops::{BitOr, BitOrAssign};

/// Process capabilities that authorize BPF control-plane operations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfCapabilities(u32);

impl BpfCapabilities {
    pub const NONE: Self = Self(0);
    pub const PROGRAM_LOAD: Self = Self(kernel_abi::BPF_CAP_PROGRAM_LOAD);
    pub const MAP_CREATE: Self = Self(kernel_abi::BPF_CAP_MAP_CREATE);
    pub const MAP_READ: Self = Self(kernel_abi::BPF_CAP_MAP_READ);
    pub const MAP_WRITE: Self = Self(kernel_abi::BPF_CAP_MAP_WRITE);
    pub const ATTACH_TRACE: Self = Self(kernel_abi::BPF_CAP_ATTACH_TRACE);
    pub const ATTACH_SCHEDULER: Self = Self(kernel_abi::BPF_CAP_ATTACH_SCHEDULER);
    pub const ATTACH_DEVICE: Self = Self(kernel_abi::BPF_CAP_ATTACH_DEVICE);
    pub const OBJECT_PIN: Self = Self(kernel_abi::BPF_CAP_OBJECT_PIN);
    pub const ACTUATE: Self = Self(kernel_abi::BPF_CAP_ACTUATE);
    pub const PRIVILEGED_VERIFY: Self = Self(kernel_abi::BPF_CAP_PRIVILEGED_VERIFY);
    pub const OBJECT_ADMIN: Self = Self(kernel_abi::BPF_CAP_OBJECT_ADMIN);

    pub const MAP_ACCESS: Self = Self(Self::MAP_READ.0 | Self::MAP_WRITE.0);
    pub const PROGRAM_ATTACH: Self =
        Self(Self::ATTACH_TRACE.0 | Self::ATTACH_SCHEDULER.0 | Self::ATTACH_DEVICE.0);

    /// Authority assigned to the first userspace process. Init can run the
    /// lifecycle probes and delegate the shipped scheduler demos, but it has no
    /// device attach or actuation authority.
    pub const USERSPACE_INIT: Self = Self(
        Self::PROGRAM_LOAD.0
            | Self::MAP_CREATE.0
            | Self::MAP_READ.0
            | Self::MAP_WRITE.0
            | Self::ATTACH_SCHEDULER.0
            | Self::OBJECT_PIN.0
            | Self::PRIVILEGED_VERIFY.0
            | Self::OBJECT_ADMIN.0,
    );

    pub const ALL: Self = Self(
        Self::PROGRAM_LOAD.0
            | Self::MAP_CREATE.0
            | Self::MAP_READ.0
            | Self::MAP_WRITE.0
            | Self::ATTACH_TRACE.0
            | Self::ATTACH_SCHEDULER.0
            | Self::ATTACH_DEVICE.0
            | Self::OBJECT_PIN.0
            | Self::ACTUATE.0
            | Self::PRIVILEGED_VERIFY.0
            | Self::OBJECT_ADMIN.0,
    );

    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub const fn intersection(self, allowed: Self) -> Self {
        Self(self.0 & allowed.0)
    }

    #[must_use]
    pub const fn without(self, removed: Self) -> Self {
        Self(self.0 & !removed.0)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for BpfCapabilities {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for BpfCapabilities {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Security-relevant process identity propagated across fork and exec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credentials {
    bpf_capabilities: BpfCapabilities,
}

impl Credentials {
    pub(crate) const fn kernel() -> Self {
        Self {
            bpf_capabilities: BpfCapabilities::ALL,
        }
    }

    pub(crate) const fn inherit(parent: Self) -> Self {
        parent
    }

    #[must_use]
    pub const fn bpf_capabilities(self) -> BpfCapabilities {
        self.bpf_capabilities
    }

    #[must_use]
    pub const fn has_bpf_capabilities(self, required: BpfCapabilities) -> bool {
        self.bpf_capabilities.contains(required)
    }

    /// Retain only the supplied capabilities. Removed capabilities cannot be regained.
    pub fn restrict_bpf_capabilities(&mut self, allowed: BpfCapabilities) -> BpfCapabilities {
        self.bpf_capabilities = self.bpf_capabilities.intersection(allowed);
        self.bpf_capabilities
    }

    /// Permanently remove the supplied capabilities.
    pub fn drop_bpf_capabilities(&mut self, removed: BpfCapabilities) -> BpfCapabilities {
        self.bpf_capabilities = self.bpf_capabilities.without(removed);
        self.bpf_capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_credentials_have_every_bpf_capability() {
        let credentials = Credentials::kernel();

        assert_eq!(credentials.bpf_capabilities(), BpfCapabilities::ALL);
        assert!(credentials.has_bpf_capabilities(BpfCapabilities::ACTUATE));
        assert!(credentials.has_bpf_capabilities(BpfCapabilities::PRIVILEGED_VERIFY));
    }

    #[test]
    fn userspace_init_authority_excludes_device_and_actuation_rights() {
        assert!(BpfCapabilities::ALL.contains(BpfCapabilities::USERSPACE_INIT));
        assert!(!BpfCapabilities::USERSPACE_INIT.intersects(
            BpfCapabilities::ATTACH_DEVICE
                | BpfCapabilities::ATTACH_TRACE
                | BpfCapabilities::ACTUATE
        ));
    }

    #[test]
    fn inheritance_copies_the_exact_restricted_snapshot() {
        let mut parent = Credentials::kernel();
        parent.drop_bpf_capabilities(BpfCapabilities::ACTUATE | BpfCapabilities::PRIVILEGED_VERIFY);

        let child = Credentials::inherit(parent);
        assert_eq!(child, parent);

        parent.drop_bpf_capabilities(BpfCapabilities::PROGRAM_ATTACH);
        assert!(child.has_bpf_capabilities(BpfCapabilities::PROGRAM_ATTACH));
        assert!(!parent.has_bpf_capabilities(BpfCapabilities::PROGRAM_ATTACH));
    }

    #[test]
    fn restriction_cannot_regain_a_removed_capability() {
        let mut credentials = Credentials::kernel();
        credentials.drop_bpf_capabilities(BpfCapabilities::PROGRAM_LOAD);

        credentials.restrict_bpf_capabilities(BpfCapabilities::ALL);

        assert!(!credentials.has_bpf_capabilities(BpfCapabilities::PROGRAM_LOAD));
        assert!(credentials.has_bpf_capabilities(BpfCapabilities::MAP_CREATE));
    }

    #[test]
    fn restriction_can_only_reduce_the_current_set() {
        let mut credentials = Credentials::kernel();
        let retained = BpfCapabilities::MAP_READ | BpfCapabilities::OBJECT_PIN;

        assert_eq!(credentials.restrict_bpf_capabilities(retained), retained);
        assert_eq!(
            credentials.restrict_bpf_capabilities(BpfCapabilities::ALL),
            retained
        );
        assert!(!credentials.bpf_capabilities().is_empty());
    }

    #[test]
    fn abi_masks_round_trip_and_unknown_bits_are_rejected() {
        assert_eq!(BpfCapabilities::ALL.bits(), kernel_abi::BPF_CAP_ALL);
        assert_eq!(
            BpfCapabilities::from_bits(kernel_abi::BPF_CAP_MAP_READ),
            Some(BpfCapabilities::MAP_READ)
        );
        assert_eq!(BpfCapabilities::from_bits(1 << 31), None);
    }
}
