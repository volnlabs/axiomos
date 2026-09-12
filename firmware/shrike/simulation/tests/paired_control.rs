use std::cell::Cell;

use shrike_control::fpga::{
    BitstreamManifest, FpgaLifecycle, FpgaPlatform, FPGA_STORAGE_START, STATUS_COMMAND_VALID,
    STATUS_READY,
};
use shrike_control::{run, Config, FaultReason, MicrosClock, RunTermination, StopReason};
use shrike_link::{encode, Msg, MAX_FRAME};
use shrike_rp2040_host_sim::mocks::{
    MockByteIo, MockClock, MockEstop, MockMotorPair, MockUltrasonic, MotorPairCall,
};

fn config(timeout: u64) -> Config {
    Config {
        link_timeout_us: timeout,
        ping_period_us: u64::MAX,
        peer_heartbeat_period_us: 0,
    }
}

fn frames(messages: &[Msg]) -> Vec<u8> {
    let mut input = Vec::new();
    for msg in messages {
        let mut frame = [0; MAX_FRAME];
        let len = encode(msg, &mut frame).unwrap();
        input.extend_from_slice(&frame[..len]);
    }
    input
}

#[test]
fn same_batch_zero_then_reverse_is_applied_in_decode_order() {
    let input = frames(&[
        Msg::MotorSetpoint {
            seq: 1,
            left: 0,
            right: 0,
        },
        Msg::MotorSetpoint {
            seq: 2,
            left: -400,
            right: 400,
        },
    ]);

    let mut io = MockByteIo::new(input);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();
    run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 1,
                left: 0,
                right: 0,
            },
            MotorPairCall::Apply {
                seq: 2,
                left: -400,
                right: 400,
            },
            MotorPairCall::Inhibit,
        ]
    );
}

#[test]
fn duplicate_and_stale_setpoints_are_never_resubmitted() {
    let input = frames(&[
        Msg::MotorSetpoint {
            seq: 5,
            left: 10,
            right: 20,
        },
        Msg::MotorSetpoint {
            seq: 5,
            left: 30,
            right: 40,
        },
        Msg::MotorSetpoint {
            seq: 4,
            left: 50,
            right: 60,
        },
    ]);
    let mut io = MockByteIo::new(input);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();

    run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 5,
                left: 10,
                right: 20,
            },
            MotorPairCall::Inhibit,
        ]
    );
}

struct SequenceClock {
    samples: Vec<u64>,
    next: Cell<usize>,
}

impl SequenceClock {
    fn new(samples: Vec<u64>) -> Self {
        Self {
            samples,
            next: Cell::new(0),
        }
    }
}

impl MicrosClock for SequenceClock {
    fn now_us(&self) -> u64 {
        let next = self.next.get();
        self.next.set(next + 1);
        self.samples
            .get(next)
            .or_else(|| self.samples.last())
            .copied()
            .unwrap_or(0)
    }
}

#[test]
fn heartbeat_at_timeout_does_not_keep_the_last_motor_command_alive() {
    let input = frames(&[
        Msg::MotorSetpoint {
            seq: 1,
            left: 100,
            right: 100,
        },
        Msg::HeartbeatToShrike { seq: 1 },
    ]);
    let mut io = MockByteIo::new(input);
    let clock = SequenceClock::new(vec![0, 0, 0, 0, 100]);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();

    let summary = run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::WatchdogExpired)
    );
    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 1,
                left: 100,
                right: 100,
            },
            MotorPairCall::Inhibit,
        ]
    );
}

#[test]
fn command_expiring_during_pre_apply_checks_is_never_submitted() {
    let input = frames(&[Msg::MotorSetpoint {
        seq: 1,
        left: 100,
        right: 100,
    }]);
    let mut io = MockByteIo::new(input);
    let clock = SequenceClock::new(vec![0, 0, 100]);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();

    let summary = run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::WatchdogExpired)
    );
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
}

#[test]
fn software_stop_midbatch_suppresses_later_motion() {
    let input = frames(&[
        Msg::MotorSetpoint {
            seq: 1,
            left: 100,
            right: 100,
        },
        Msg::Estop { assert: true },
        Msg::MotorSetpoint {
            seq: 2,
            left: 700,
            right: 700,
        },
    ]);
    let mut io = MockByteIo::new(input);
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
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::SoftwareEstop)
    );
    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 1,
                left: 100,
                right: 100,
            },
            MotorPairCall::Inhibit,
        ]
    );
}

#[test]
fn failed_sink_blocks_following_commands() {
    let input = frames(&[
        Msg::MotorSetpoint {
            seq: 1,
            left: 100,
            right: 100,
        },
        Msg::MotorSetpoint {
            seq: 2,
            left: 200,
            right: 200,
        },
    ]);
    let mut io = MockByteIo::new(input);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = MockMotorPair::new();
    motors.fail_apply_at = Some(0);

    let summary = run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Fault(FaultReason::MotorSink)
    );
    assert_eq!(summary.motor_pairs_accepted, 0);
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
}

struct AckingFpga {
    last_seq: u8,
    transfers: usize,
    forced_safe: usize,
}

impl FpgaPlatform for AckingFpga {
    type Error = ();

    fn force_safe(&mut self) {
        self.forced_safe += 1;
    }

    fn now_us(&mut self) -> u64 {
        0
    }

    fn bitstream_sha256(&mut self, _: u32, _: u32) -> Result<[u8; 32], Self::Error> {
        Ok([1; 32])
    }

    fn begin_configuration(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn stream_bitstream(&mut self, _: u32, _: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    fn ready_status(&mut self) -> Result<u8, Self::Error> {
        Ok(STATUS_READY)
    }

    fn handoff_to_runtime(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn runtime_transfer(&mut self, frame: &[u8; 12]) -> Result<u8, Self::Error> {
        self.last_seq = frame[4];
        self.transfers += 1;
        Ok(0)
    }

    fn read_runtime_status(&mut self) -> Result<[u8; 2], Self::Error> {
        Ok([STATUS_READY | STATUS_COMMAND_VALID, self.last_seq])
    }
}

#[test]
fn fpga_lifecycle_sink_requires_and_accepts_the_real_runtime_ack() {
    let input = frames(&[Msg::MotorSetpoint {
        seq: 7,
        left: 400,
        right: -400,
    }]);
    let mut io = MockByteIo::new(input);
    let clock = MockClock::new(0);
    let mut ultra = MockUltrasonic::new(vec![]);
    let mut estop = MockEstop::new(false);
    let mut motors = FpgaLifecycle::new(AckingFpga {
        last_seq: 0,
        transfers: 0,
        forced_safe: 0,
    });
    motors
        .configure(
            BitstreamManifest {
                offset: FPGA_STORAGE_START,
                length: 1,
                sha256: [1; 32],
            },
            1,
        )
        .unwrap();

    let summary = run(
        &mut io,
        &clock,
        &mut ultra,
        &mut estop,
        &mut motors,
        config(100),
        Some(1),
    )
    .unwrap();

    assert_eq!(summary.termination, RunTermination::IterationLimit);
    assert_eq!(summary.motor_pairs_accepted, 1);
    assert_eq!(motors.platform().transfers, 1);
    assert!(!motors.runtime_ready());
}

struct BackpressuredIo {
    budget: usize,
    per_iteration: usize,
    fail_after: Option<usize>,
    wire: Vec<u8>,
}
impl shrike_control::ByteIo for BackpressuredIo {
    type Error = ();
    fn read(&mut self) -> Option<u8> {
        self.budget = self.per_iteration;
        None
    }
    fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if self.fail_after.is_some_and(|n| self.wire.len() >= n) {
            return Err(());
        }
        let n = bytes.len().min(self.budget);
        self.wire.extend_from_slice(&bytes[..n]);
        self.budget -= n;
        Ok(n)
    }
    fn reset(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

#[test]
fn loop_keeps_partial_sensor_frame_until_uart_accepts_all_bytes() {
    let mut io = BackpressuredIo {
        budget: 0,
        per_iteration: 3,
        fail_after: None,
        wire: vec![],
    };
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![126]),
        &mut MockEstop::new(false),
        &mut motors,
        config(100),
        Some(4),
    )
    .unwrap();
    let mut decoder = shrike_link::Decoder::new();
    let messages: Vec<_> = io.wire.iter().filter_map(|&b| decoder.push(b)).collect();
    assert_eq!(
        messages,
        [Ok(Msg::Sensor {
            ultrasonic_echo_us: 126,
            estop_line: false,
            flags: 0
        })]
    );
    assert_eq!(summary.bytes_written as usize, io.wire.len());
}

#[test]
fn telemetry_capacity_and_stop_discards_have_explicit_loss_counts() {
    let mut io = BackpressuredIo {
        budget: 0,
        per_iteration: 0,
        fail_after: None,
        wire: vec![],
    };
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![1, 2, 3, 4, 5]),
        &mut MockEstop::new(false),
        &mut MockMotorPair::new(),
        config(100),
        Some(5),
    )
    .unwrap();
    assert_eq!(summary.telemetry_frames_dropped, 5);
    assert_eq!(summary.bytes_written, 0);
}

#[test]
fn failed_uart_write_reports_accepted_prefix_and_discards_partial_frame() {
    let mut io = BackpressuredIo {
        budget: 0,
        per_iteration: usize::MAX,
        fail_after: Some(3),
        wire: vec![],
    };
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![1, 2]),
        &mut MockEstop::new(false),
        &mut motors,
        config(100),
        Some(5),
    )
    .unwrap();
    assert_eq!(summary.termination, RunTermination::Fault(FaultReason::Io));
    assert_eq!(summary.bytes_written, 3);
    assert_eq!(summary.telemetry_frames_dropped, 1);
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
    assert_eq!(io.wire.len(), 3);
}
