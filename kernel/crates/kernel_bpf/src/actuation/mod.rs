//! ARM-A — the Actuation Reference Monitor (pure decision core).
//!
//! Untrusted, hot-loaded BPF logic proposes actuations; this monitor decides
//! whether each one may reach hardware, clamping magnitude and slew into a
//! per-profile safety envelope. The decision logic is pure (no MMIO) so the
//! "0 escapes" safety invariant is proven by host tests; the kernel binary
//! crate maps a `Decision` onto RP1 MMIO (see `kernel/src/actuation.rs`).

use crate::profile::PhysicalProfile;

/// What kind of actuator a request targets. Determines the safe state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActuationKind {
    /// PWM duty cycle, percent 0..=100.
    PwmDuty,
    /// GPIO output level, 0 or 1.
    GpioLevel,
}

/// Identifies a physical output channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId {
    pub kind: ActuationKind,
    /// PWM: controller id (0|1). GPIO: 0.
    pub chip: u8,
    /// PWM: channel (1|2). GPIO: pin (0..=27).
    pub channel: u8,
}

/// A requested actuation, before the monitor decides.
#[derive(Debug, Clone, Copy)]
pub struct ActuationRequest {
    pub ch: ChannelId,
    pub value: u32,
}

/// The safety envelope for a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub min: u32,
    pub max: u32,
    /// Max change in output per `window_ns`. 0 disables slew limiting.
    pub max_step: u32,
    /// Rate-limit window in nanoseconds. 0 disables slew limiting.
    pub window_ns: u64,
}

impl Envelope {
    /// Build the Spec-1 envelope for a channel kind. `PwmDuty` reads the profile
    /// constants; `GpioLevel` is the fixed `{0,1,1,0}` envelope (slew is not
    /// meaningful on a binary line).
    pub fn from_profile<P: PhysicalProfile>(kind: ActuationKind) -> Self {
        match kind {
            ActuationKind::PwmDuty => Envelope {
                min: 0,
                max: P::ACT_DUTY_MAX,
                max_step: P::ACT_DUTY_MAX_STEP,
                window_ns: P::ACT_RATE_WINDOW_NS,
            },
            ActuationKind::GpioLevel => Envelope {
                min: 0,
                max: 1,
                max_step: 1,
                window_ns: 0,
            },
        }
    }
}

/// Why a request was structurally refused (distinct from a policy-safe outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// No envelope exists for this channel (deny-by-default).
    UnknownChannel,
}

/// The monitor's decision — four distinguishable outcomes so audit logs,
/// authority decisions, and incident replay (Spec 2) can tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Inside the envelope; apply `value` unchanged.
    Allow(u32),
    /// Clamped (magnitude and/or slew); apply the bounded value.
    Clamp(u32),
    /// Policy forced the channel to its safe value (safe-hold / e-stop / veto).
    Safe(u32),
    /// Structurally invalid; the caller drives the universal safe (0).
    Reject(RejectReason),
}

impl Decision {
    /// Map a decision to `(mmio_value_to_write, return_code_for_caller)`.
    /// `Reject` writes the universal safe value 0 (an unknown channel must not be
    /// wired to a live actuator). `Safe` returns -1 to signal policy intervention.
    pub fn apply(self) -> (u32, i64) {
        match self {
            Decision::Allow(v) | Decision::Clamp(v) => (v, 0),
            Decision::Safe(v) => (v, -1),
            Decision::Reject(_) => (0, -1),
        }
    }
}

/// Per-channel mutable state. Modeled explicitly: slew-rate limiting,
/// auditability, and Spec 2 extensions all depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelState {
    pub last_output: u32,
    pub last_update_ns: u64,
    /// When set, every request resolves to `Safe(min)`.
    pub safe_hold: bool,
}

impl ChannelState {
    pub(crate) const DEFAULT: ChannelState = ChannelState {
        last_output: 0,
        last_update_ns: 0,
        safe_hold: false,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{CloudProfile, EmbeddedProfile};

    #[test]
    fn pwm_envelope_from_embedded_profile() {
        let e = Envelope::from_profile::<EmbeddedProfile>(ActuationKind::PwmDuty);
        assert_eq!(e, Envelope { min: 0, max: 90, max_step: 20, window_ns: 1_000_000 });
    }

    #[test]
    fn gpio_envelope_is_fixed() {
        let e = Envelope::from_profile::<CloudProfile>(ActuationKind::GpioLevel);
        assert_eq!(e, Envelope { min: 0, max: 1, max_step: 1, window_ns: 0 });
    }

    #[test]
    fn decision_apply_mapping() {
        assert_eq!(Decision::Allow(42).apply(), (42, 0));
        assert_eq!(Decision::Clamp(90).apply(), (90, 0));
        assert_eq!(Decision::Safe(0).apply(), (0, -1));
        assert_eq!(Decision::Reject(RejectReason::UnknownChannel).apply(), (0, -1));
    }
}
