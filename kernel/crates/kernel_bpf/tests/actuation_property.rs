//! Property test for ARM-A: the core safety invariant. Over randomly generated
//! requests against random monotonic time, the applied output is ALWAYS within
//! the channel envelope and never slews faster than `max_step` within a window.
//! This is the direct evidence for the "0 escapes" claim.

#![cfg(any(feature = "cloud-profile", feature = "embedded-profile"))]

use kernel_bpf::actuation::{ActuationKind, ActuationRequest, ChannelId, Decision, Envelope, Monitor};
use kernel_bpf::profile::{ActiveProfile, EmbeddedProfile};
use proptest::prelude::*;

/// The output a decision applies to hardware (None for Reject, which writes the
/// universal safe 0 — handled separately; this test only feeds known channels).
fn applied(d: Decision) -> u32 {
    match d {
        Decision::Allow(v) | Decision::Clamp(v) | Decision::Safe(v) => v,
        Decision::Reject(_) => unreachable!("known channel must not be rejected"),
    }
}

proptest! {
    #[test]
    fn pwm_output_always_within_envelope_and_slew(
        // a known PWM channel
        chip in 0u8..2,
        channel in 1u8..=2,
        // a sequence of (requested_value, time_delta_ns)
        steps in proptest::collection::vec((0u32..200, 0u64..3_000_000), 1..64),
    ) {
        let env = Envelope::from_profile::<EmbeddedProfile>(ActuationKind::PwmDuty);
        let mut m = Monitor::<ActiveProfile>::new();
        let ch = ChannelId { kind: ActuationKind::PwmDuty, chip, channel };

        let mut now: u64 = 0;
        let mut prev = 0u32; // matches ChannelState default last_output
        for (value, dt) in steps {
            now = now.saturating_add(dt);
            let out = applied(m.decide(ActuationRequest { ch, value }, now));

            // Invariant 1: output always within [min, max].
            prop_assert!(out >= env.min && out <= env.max, "out {} outside [{},{}]", out, env.min, env.max);

            // Invariant 2: when the previous update is within the window, the
            // step is bounded by max_step.
            if env.window_ns > 0 && dt < env.window_ns {
                let delta = out.abs_diff(prev);
                prop_assert!(delta <= env.max_step, "slew {} > max_step {}", delta, env.max_step);
            }
            prev = out;
        }
    }
}
