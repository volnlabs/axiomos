//! Property test for ARM-A: the core safety invariant. Over randomly generated
//! requests against random monotonic time, the applied output is ALWAYS within
//! the channel envelope and never slews faster than `max_step` within a window.
//! This is the direct evidence for the "0 escapes" claim.

// Skipped under Miri: proptest (256 cases × many `decide` calls) is far too slow
// under Miri's interpreter and needs entropy Miri's isolation blocks. The host
// `cargo test` run provides the 0-escapes coverage; Miri checks the other tests.
#![cfg(all(
    not(miri),
    any(feature = "cloud-profile", feature = "embedded-profile")
))]

use kernel_bpf::actuation::{
    ActuationKind, ActuationRequest, AuditSource, Authority, ChannelId, Decision, Envelope,
    EstopAction, EstopCommandResult, Monitor, ReleaseResult,
};
use kernel_bpf::profile::EmbeddedProfile;
use proptest::prelude::*;

/// The output a decision applies to hardware (None for Reject, which writes the
/// universal safe 0 — handled separately; this test only feeds known channels).
fn applied(d: Decision) -> u32 {
    match d {
        Decision::Allow(v) | Decision::Clamp(v) | Decision::Safe(v) => v,
        Decision::Reject(_) => 0,
    }
}

fn authority(raw: u8) -> Authority {
    match raw % 4 {
        0 => Authority::Learned,
        1 => Authority::Mission,
        2 => Authority::Operator,
        _ => Authority::Safety,
    }
}

fn source(raw: u8) -> AuditSource {
    match raw % 6 {
        0 => AuditSource::Operator,
        1 => AuditSource::Watchdog,
        2 => AuditSource::GpioHook,
        3 => AuditSource::LearnedBehavior,
        4 => AuditSource::Mission,
        _ => AuditSource::SyscallPwm,
    }
}

fn pwm(chip: u8, channel: u8, value: u32) -> ActuationRequest {
    ActuationRequest {
        ch: ChannelId {
            kind: ActuationKind::PwmDuty,
            chip,
            channel,
        },
        value,
    }
}

fn assert_known_pwm_safe(known: &[[bool; 2]; 2], hw: &[[u32; 2]; 2]) {
    for chip in 0..2 {
        for channel in 0..2 {
            if known[chip][channel] {
                assert_eq!(hw[chip][channel], 0);
            }
        }
    }
}

#[test]
fn invalid_and_latched_request_sweep_has_zero_unsafe_escapes() {
    let mut m = Monitor::<EmbeddedProfile>::new();

    for i in 0..1000 {
        let req = pwm(2, (i % 4) as u8, 200);
        let decision = m.decide(
            req,
            Authority::Learned,
            AuditSource::LearnedBehavior,
            i as u64,
        );
        assert_eq!(applied(decision), 0);
    }

    let ch = pwm(0, 1, 80).ch;
    assert_ne!(
        applied(m.decide(
            pwm(0, 1, 80),
            Authority::Learned,
            AuditSource::LearnedBehavior,
            2_000
        )),
        0
    );
    let safe = m.watchdog_estop_trigger(3_000);
    assert!(safe.contains(ch, 0));
    assert!(m.is_latched());

    for i in 0..1000 {
        let decision = m.decide(
            pwm(0, 1, 1 + (i % 200) as u32),
            authority((i % 4) as u8),
            source((i % 6) as u8),
            4_000 + i as u64,
        );
        assert_eq!(applied(decision), 0);
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
        // Pin both the envelope and the monitor to EmbeddedProfile so the test
        // exercises real clamping under either CI profile (the cloud profile
        // disables clamping, so its envelope is unbounded and proves nothing).
        let env = Envelope::from_profile::<EmbeddedProfile>(ActuationKind::PwmDuty);
        let mut m = Monitor::<EmbeddedProfile>::new();
        let ch = ChannelId { kind: ActuationKind::PwmDuty, chip, channel };

        let mut now: u64 = 0;
        let mut prev = 0u32; // matches ChannelState default last_output
        for (value, dt) in steps {
            now = now.saturating_add(dt);
            let out = applied(m.decide(
                ActuationRequest { ch, value },
                Authority::Learned,
                AuditSource::LearnedBehavior,
                now,
            ));

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

    #[test]
    fn governance_random_sequences_keep_latched_outputs_safe(
        steps in proptest::collection::vec(
            (
                0u8..6,          // op kind
                0u8..3,          // chip; 2 is invalid
                0u8..4,          // channel; 0 and 3 are invalid for PWM
                0u32..200,       // requested value
                0u8..4,          // authority
                0u8..6,          // source
                0u64..3_000_000, // time delta
            ),
            1..128
        ),
    ) {
        let mut m = Monitor::<EmbeddedProfile>::new();
        let mut now = 10_000_000u64;
        let mut known = [[false; 2]; 2];
        let mut hw = [[0u32; 2]; 2];

        for (op, chip, channel, value, authority_raw, source_raw, dt) in steps {
            now = now.saturating_add(dt);
            let auth = authority(authority_raw);
            let src = source(source_raw);

            match op {
                0 | 1 => {
                    let req = pwm(chip, channel, value);
                    let decision = m.decide(req, auth, src, now);
                    if chip < 2 && (1..=2).contains(&channel) {
                        let chip_idx = chip as usize;
                        let channel_idx = (channel - 1) as usize;
                        known[chip_idx][channel_idx] = true;
                        hw[chip_idx][channel_idx] = applied(decision);
                    } else {
                        prop_assert_eq!(applied(decision), 0);
                    }
                }
                2 => {
                    let safe = match m.operator_estop(EstopAction::Trigger, now) {
                        EstopCommandResult::Triggered(safe) => safe,
                        other => panic!("operator trigger returned {other:?}"),
                    };
                    for chip_idx in 0..2 {
                        for channel_idx in 0..2 {
                            if known[chip_idx][channel_idx] {
                                let ch = ChannelId {
                                    kind: ActuationKind::PwmDuty,
                                    chip: chip_idx as u8,
                                    channel: (channel_idx + 1) as u8,
                                };
                                prop_assert!(safe.contains(ch, 0));
                            }
                        }
                    }
                    for drive in safe.iter() {
                        if drive.channel.kind == ActuationKind::PwmDuty {
                            hw[drive.channel.chip as usize][(drive.channel.channel - 1) as usize] =
                                drive.safe_value;
                        }
                    }
                    prop_assert!(m.is_latched());
                }
                3 => {
                    let safe = m.watchdog_estop_trigger(now);
                    for chip_idx in 0..2 {
                        for channel_idx in 0..2 {
                            if known[chip_idx][channel_idx] {
                                let ch = ChannelId {
                                    kind: ActuationKind::PwmDuty,
                                    chip: chip_idx as u8,
                                    channel: (channel_idx + 1) as u8,
                                };
                                prop_assert!(safe.contains(ch, 0));
                            }
                        }
                    }
                    for drive in safe.iter() {
                        if drive.channel.kind == ActuationKind::PwmDuty {
                            hw[drive.channel.chip as usize][(drive.channel.channel - 1) as usize] =
                                drive.safe_value;
                        }
                    }
                    prop_assert!(m.is_latched());
                }
                4 => {
                    let before = m.is_latched();
                    let result = m.estop_release(auth, src, now);
                    if auth == Authority::Operator {
                        prop_assert_eq!(result, ReleaseResult::Released);
                        prop_assert!(!m.is_latched());
                    } else {
                        prop_assert_eq!(result, ReleaseResult::Denied);
                        prop_assert_eq!(m.is_latched(), before);
                    }
                }
                _ => {
                    let before = m.is_latched();
                    prop_assert_eq!(m.is_latched(), before);
                }
            }

            if m.is_latched() {
                assert_known_pwm_safe(&known, &hw);
            }
        }
    }
}
