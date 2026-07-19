//! Caller privilege tier for BPF program loads (#88).
//!
//! Linux applies stricter verification to unprivileged BPF (a larger attack
//! surface). axiomos keys the same tiering on *who loaded the program*. The tier
//! is carried in [`super::VerifyConfig`] and consulted by privilege-gated rules.

/// Privilege tier of the caller that loaded a BPF program.
///
/// Stricter tiers are *lower*: [`Ord`] is `Unprivileged < Privileged < Trusted`,
/// so a rule requiring tier `T` accepts any `caller >= T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LoadCaller {
    /// Anyone else, including future over-network loads (#67): strictest rules.
    Unprivileged,
    /// Privileged in-kernel / init caller: standard rules. Default — every
    /// current load comes from the privileged init context and must not regress
    /// while no credential system exists.
    #[default]
    Privileged,
    /// Boot-time / signature-authenticated programs (#20): most permissive.
    Trusted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering_is_unpriv_lt_priv_lt_trusted() {
        assert!(LoadCaller::Unprivileged < LoadCaller::Privileged);
        assert!(LoadCaller::Privileged < LoadCaller::Trusted);
    }

    #[test]
    fn default_is_privileged() {
        assert_eq!(LoadCaller::default(), LoadCaller::Privileged);
    }
}
