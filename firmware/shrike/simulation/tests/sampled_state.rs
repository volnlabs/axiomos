//! Sampled-state host checks. Physical edge-loss claims remain HIL-only.

use std::collections::VecDeque;

use shrike_control::{run, Config, EstopLine, RunTermination, StopReason};
use shrike_link::{encode, Msg, MAX_FRAME};
use shrike_rp2040_host_sim::mocks::{
    MockByteIo, MockClock, MockEstop, MockMotorPair, MockUltrasonic, MotorPairCall,
};

fn default_config() -> Config {
    Config {
        require_session: false,
        link_timeout_us: 100_000,
        ping_period_us: 50_000,
        peer_heartbeat_period_us: 20_000,
    }
}

#[test]
fn ultrasonic_echo_sampled_state_sequence_drains_all_echoes() {
    let mut io = MockByteIo::new(vec![]);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();

    let summary = run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        default_config(),
        Some(100),
    )
    .unwrap();

    assert!(summary.bytes_written > 0);
    assert_eq!(summary.iterations, 100);
}

struct SequencedEstop(VecDeque<bool>);

impl EstopLine for SequencedEstop {
    fn asserted(&mut self) -> bool {
        self.0.pop_front().unwrap_or(false)
    }
}

#[test]
fn hardware_estop_sampled_immediately_before_apply_suppresses_command() {
    let mut frame = [0; MAX_FRAME];
    let len = encode(
        &Msg::MotorSetpoint {
            seq: 1,
            left: 400,
            right: -400,
        },
        &mut frame,
    )
    .unwrap();
    let mut io = MockByteIo::new(frame[..len].to_vec());
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = SequencedEstop([false, false, true].into());
    let mut motors = MockMotorPair::new();

    let summary = run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        default_config(),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::HardwareEstop)
    );
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
}

#[test]
fn hardware_estop_sampled_after_barrier_apply_suppresses_safe_ack() {
    let session = 7;
    let mut input = Vec::new();
    for message in [
        Msg::SessionOffer { session },
        Msg::SafeBarrier {
            session,
            correlation: 11,
            sequence: 1,
        },
    ] {
        let mut frame = [0; MAX_FRAME];
        let len = encode(&message, &mut frame).unwrap();
        input.extend_from_slice(&frame[..len]);
    }
    let mut io = MockByteIo::new(input);
    let mut motors = MockMotorPair::new();
    // Offer: iteration/decode/pre/post all clear. Barrier becomes asserted
    // only in the post-apply sample, before SafeAck can be queued.
    let mut estop = SequencedEstop([false, false, false, false, false, false, true].into());
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut estop,
        &mut motors,
        Config {
            require_session: true,
            link_timeout_us: 100,
            ping_period_us: u64::MAX,
            peer_heartbeat_period_us: 0,
        },
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::HardwareEstop)
    );
    assert_eq!(summary.safe_barriers_accepted, 0);
    // SessionReady is queued but never serviced before the terminal barrier;
    // SafeAck is never queued.
    assert!(io.output.is_empty());
    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 0,
                left: 0,
                right: 0,
            },
            MotorPairCall::Apply {
                seq: 1,
                left: 0,
                right: 0,
            },
            MotorPairCall::Inhibit,
        ]
    );
}
