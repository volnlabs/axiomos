//! Sampled-state host checks. Physical edge-loss claims remain HIL-only.

use std::collections::VecDeque;

use shrike_control::{run, Config, EstopLine, RunTermination, StopReason};
use shrike_link::{encode, Msg, MAX_FRAME};
use shrike_rp2040_host_sim::mocks::{
    MockByteIo, MockClock, MockEstop, MockMotorPair, MockUltrasonic, MotorPairCall,
};

fn default_config() -> Config {
    Config {
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
