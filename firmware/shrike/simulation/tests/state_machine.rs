//! Host-simulation checks for bounded control-loop state transitions.

use shrike_control::{run, Config, RunTermination, StopReason};
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
fn bounded_cold_idle_does_not_touch_motion_before_safe_exit() {
    let mut io = MockByteIo::new(vec![]);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
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

    assert_eq!(summary.termination, RunTermination::IterationLimit);
    assert_eq!(summary.iterations, 100);
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
}

#[test]
fn hardware_estop_is_terminal_and_inhibits_once() {
    let mut io = MockByteIo::new(vec![]);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(true);
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

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::HardwareEstop)
    );
    assert_eq!(summary.iterations, 1);
    assert_eq!(summary.estop_asserts, 1);
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
}

#[test]
fn ultrasonic_trigger_uses_the_configured_period() {
    let mut io = MockByteIo::new(vec![]);
    let clock = MockClock::new(50_000);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();

    run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        default_config(),
        Some(1),
    )
    .unwrap();

    assert_eq!(ultra.triggers, 1);
}
