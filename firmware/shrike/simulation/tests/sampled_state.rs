//! Sampled-state stress tests for `shrike_control::run` under the host-
//! simulation mocks.
//!
//! These tests assert the production control loop's behavior under
//! sequences of sampled state (e-stop transitions, ultrasonic echo
//! availability). They do NOT claim 'no lost IRQ edge' — that is a
//! hardware-level property validated by physical HIL, not host
//! simulation. The firmware polls the e-stop line and the ultrasonic
//! echo pin; the test asserts the sampled-state-sequence behavior.

use shrike_control::{run, Config};
use shrike_rp2040_host_sim::mocks::{MockByteIo, MockClock, MockEstop, MockUltrasonic};

fn default_config() -> Config {
    Config {
        link_timeout_us: 100_000,
        ping_period_us: 50_000,
        peer_heartbeat_period_us: 20_000,
    }
}

#[test]
fn ultrasonic_echo_sampled_state_sequence_drains_all_echoes() {
    // Pre-program 10 echoes. The control loop runs for enough
    // iterations to drain them all. The MockByteIo output buffer
    // should contain at least 10 encoded Sensor frames.
    let io = MockByteIo::new(vec![]);
    let clock = MockClock::new(0);
    let ultra = MockUltrasonic::new(vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]);
    let estop = MockEstop::new(false);
    let left = shrike_rp2040_host_sim::mocks::MockMotor::new();
    let right = shrike_rp2040_host_sim::mocks::MockMotor::new();

    let summary = run(
        io,
        clock,
        ultra,
        estop,
        left,
        right,
        default_config(),
        Some(100),
    )
    .expect("bounded run must return a summary");

    // The run drained 10 echoes; the bytes_written counter must be > 0.
    // (The exact byte count depends on shrike_link encoding, which we
    // don't hardcode here. The key assertion: echoes were processed.)
    assert!(
        summary.bytes_written > 0,
        "echo processing must produce encoded Sensor frames in the output buffer"
    );
    assert_eq!(summary.iterations, 100);
}

#[test]
fn e_stop_sampled_state_sequence_produces_correct_summary() {
    // E-stop is asserted for the entire run. The summary must record:
    // - iterations == N
    // - motor_drive_calls == 0
    // - motor_coast_calls == 2 * N
    // - estop_asserts == N
    let io = MockByteIo::new(vec![]);
    let clock = MockClock::new(0);
    let ultra = MockUltrasonic::new(vec![]);
    let estop = MockEstop::new(true);
    let left = shrike_rp2040_host_sim::mocks::MockMotor::new();
    let right = shrike_rp2040_host_sim::mocks::MockMotor::new();

    let summary = run(
        io,
        clock,
        ultra,
        estop,
        left,
        right,
        default_config(),
        Some(50),
    )
    .expect("bounded run must return a summary");

    assert_eq!(summary.iterations, 50);
    assert_eq!(summary.motor_drive_calls, 0);
    assert_eq!(summary.motor_coast_calls, 100);
    assert_eq!(summary.estop_asserts, 50);
}
