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
        expected_session: None,
        offer_deadline_us: 0,
        link_timeout_us: timeout,
        ping_period_us: u64::MAX,
        peer_heartbeat_period_us: 0,
    }
}

fn managed_config(timeout: u64, session: u32) -> Config {
    Config {
        expected_session: Some(core::num::NonZeroU32::new(session).unwrap()),
        offer_deadline_us: 1_000_000,
        link_timeout_us: timeout,
        ping_period_us: 1,
        peer_heartbeat_period_us: 1,
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

fn decoded(bytes: &[u8]) -> Vec<Msg> {
    let mut decoder = shrike_link::Decoder::new();
    bytes
        .iter()
        .filter_map(|&byte| decoder.push(byte))
        .map(Result::unwrap)
        .collect()
}

#[test]
fn frozen_clock_without_offer_exits_with_bounded_work_and_no_output() {
    use shrike_control::requalification::MAX_POLLS;
    use shrike_control::transport::TransportError;
    let mut io = MockByteIo::new(vec![]);
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, 7),
        // A test guard lets the old unbounded implementation fail promptly.
        // Production must return its own PollLimit before this guard fires.
        Some(MAX_POLLS + 2),
    )
    .unwrap();
    assert_eq!(
        summary.termination,
        RunTermination::Fault(FaultReason::Transport(TransportError::PollLimit))
    );
    assert!(io.reads <= MAX_POLLS as usize);
    assert!(io.output.is_empty());
    assert_eq!(io.resets, 1);
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
}

#[test]
fn session_offer_deadline_includes_decode_and_zero_sink_completion() {
    use shrike_control::transport::TransportError;
    for (times, applied, fault) in [
        (vec![100], 0, TransportError::TimedOut),
        (vec![0, 100], 0, TransportError::TimedOut),
        (vec![0, 0, 100], 0, TransportError::TimedOut),
        (vec![0, 0, 0, 100], 1, TransportError::TimedOut),
        (vec![5, 4], 0, TransportError::ClockRegression),
    ] {
        let mut io = MockByteIo::new(frames(&[Msg::SessionOffer { session: 7 }]));
        let mut motors = MockMotorPair::new();
        let mut cfg = managed_config(100, 7);
        cfg.offer_deadline_us = 100;
        let result = run(
            &mut io,
            &SequenceClock::new(times),
            &mut MockUltrasonic::new(vec![]),
            &mut MockEstop::new(false),
            &mut motors,
            cfg,
            Some(1),
        )
        .unwrap();
        assert_eq!(
            result.termination,
            RunTermination::Fault(FaultReason::Transport(fault))
        );
        assert_eq!(result.motor_pairs_accepted, applied);
        assert!(io.output.is_empty());
        assert_eq!(motors.calls.last(), Some(&MotorPairCall::Inhibit));
    }
}

#[test]
fn unrelated_session_offer_cannot_authorize_buffered_motion() {
    // This run belongs to the explicitly prepared session 7. Neither an old
    // offer nor a future offer may establish authority for the following pair.
    for session in [6, 8, u32::MAX] {
        let mut io = MockByteIo::new(frames(&[
            Msg::SessionOffer { session },
            Msg::MotorSetpoint {
                seq: 1,
                left: 600,
                right: 600,
            },
        ]));
        let mut motors = MockMotorPair::new();
        let summary = run(
            &mut io,
            &MockClock::new(0),
            &mut MockUltrasonic::new(vec![]),
            &mut MockEstop::new(false),
            &mut motors,
            managed_config(100, 7),
            Some(1),
        )
        .unwrap();
        assert_eq!(
            summary.termination,
            RunTermination::Fault(FaultReason::UnexpectedMessage)
        );
        assert_eq!(summary.motor_pairs_accepted, 0);
        assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
        assert!(io.output.is_empty());
        assert_eq!(io.resets, 1);
    }
}

#[test]
fn rx_error_discards_queued_safe_replies_and_partial_motion_and_preserves_reset_failure() {
    let safe = frames(&[
        Msg::SessionOffer { session: 7 },
        Msg::SafeBarrier {
            session: 7,
            correlation: 1,
            sequence: 1,
        },
    ]);
    for reset_fails in [false, true] {
        let mut input = safe.clone();
        input.extend(frames(&[Msg::MotorSetpoint {
            seq: 2,
            left: 200,
            right: 200,
        }]));
        let mut io = MockByteIo::new(input);
        io.fail_read_at = Some(safe.len() + 3);
        io.fail_reset = reset_fails;
        let mut motors = MockMotorPair::new();
        let summary = run(
            &mut io,
            &MockClock::new(0),
            &mut MockUltrasonic::new(vec![]),
            &mut MockEstop::new(false),
            &mut motors,
            managed_config(100, 7),
            Some(2),
        )
        .unwrap();
        assert_eq!(summary.termination, RunTermination::Fault(FaultReason::Io));
        assert_eq!(summary.iterations, 1);
        assert_eq!(summary.motor_pairs_accepted, 2);
        assert_eq!(summary.safe_barriers_accepted, 1);
        assert_eq!(summary.motor_inhibit_calls, 1);
        assert_eq!(summary.telemetry_frames_dropped, 2);
        assert_eq!(summary.bytes_written, 0);
        assert_eq!(summary.io_reset_failed, reset_fails);
        assert_eq!((io.reads, io.resets), (safe.len() + 4, 1));
        assert!(
            io.output.is_empty(),
            "neither pending acknowledgement may escape"
        );
        assert_eq!(
            motors.calls,
            [
                MotorPairCall::Apply {
                    seq: 0,
                    left: 0,
                    right: 0
                },
                MotorPairCall::Apply {
                    seq: 1,
                    left: 0,
                    right: 0
                },
                MotorPairCall::Inhibit,
            ]
        );
        if !reset_fails {
            assert_eq!(shrike_control::ByteIo::read(&mut io), Ok(None));
        }
    }
}

#[test]
fn managed_peer_is_silent_and_rejects_motion_before_session_offer() {
    let mut silent_io = MockByteIo::new(vec![]);
    let mut silent_ultra = MockUltrasonic::new(vec![77]);
    let silent = run(
        &mut silent_io,
        &MockClock::new(10),
        &mut silent_ultra,
        &mut MockEstop::new(false),
        &mut MockMotorPair::new(),
        managed_config(100, 7),
        Some(2),
    )
    .unwrap();
    assert_eq!(silent.termination, RunTermination::IterationLimit);
    assert_eq!(silent_io.output, []);
    assert_eq!(silent_ultra.triggers, 0);

    let mut io = MockByteIo::new(frames(&[Msg::MotorSetpoint {
        seq: 1,
        left: 100,
        right: 100,
    }]));
    let mut motors = MockMotorPair::new();
    let rejected = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, 7),
        Some(1),
    )
    .unwrap();
    assert_eq!(
        rejected.termination,
        RunTermination::Fault(FaultReason::UnexpectedMessage)
    );
    assert_eq!(motors.calls, [MotorPairCall::Inhibit]);
    assert_eq!(io.output, []);
}

#[test]
fn managed_offer_and_barrier_echo_exact_identity_and_block_stale_motion() {
    let offer = Msg::SessionOffer {
        session: 0x1020_3040,
    };
    let barrier = Msg::SafeBarrier {
        session: 0x1020_3040,
        correlation: 0x0102_0304_0506_0708,
        sequence: 20,
    };
    let stale = Msg::MotorSetpoint {
        seq: 19,
        left: 700,
        right: 700,
    };
    let mut io = MockByteIo::new(frames(&[offer, barrier, stale]));
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, 0x1020_3040),
        Some(1),
    )
    .unwrap();

    assert_eq!(summary.termination, RunTermination::IterationLimit);
    assert_eq!(summary.safe_barriers_accepted, 1);
    assert_eq!(
        decoded(&io.output),
        [
            Msg::SessionReady {
                session: 0x1020_3040
            },
            Msg::SafeAck {
                session: 0x1020_3040,
                correlation: 0x0102_0304_0506_0708,
                sequence: 20,
            }
        ]
    );
    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 0,
                left: 0,
                right: 0,
            },
            MotorPairCall::Apply {
                seq: 20,
                left: 0,
                right: 0,
            },
            MotorPairCall::Inhibit,
        ]
    );
}

#[test]
fn managed_session_consumes_zero_and_rejects_equal_first_barrier_without_ack() {
    let session = 12;
    let mut io = MockByteIo::new(frames(&[
        Msg::SessionOffer { session },
        Msg::SafeBarrier {
            session,
            correlation: 1,
            sequence: 0,
        },
    ]));
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, session),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Fault(FaultReason::UnexpectedMessage)
    );
    assert_eq!(summary.safe_barriers_accepted, 0);
    assert!(io.output.is_empty());
    assert_eq!(
        motors.calls,
        [
            MotorPairCall::Apply {
                seq: 0,
                left: 0,
                right: 0,
            },
            MotorPairCall::Inhibit,
        ]
    );
}

#[test]
fn managed_ack_capacity_failure_is_terminal_and_does_not_ack_third_barrier() {
    let session = 9;
    let input = frames(&[
        Msg::SessionOffer { session },
        Msg::SafeBarrier {
            session,
            correlation: 1,
            sequence: 1,
        },
        Msg::SafeBarrier {
            session,
            correlation: 2,
            sequence: 2,
        },
    ]);
    let mut io = MockByteIo::new(input);
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, session),
        Some(1),
    )
    .unwrap();
    assert_eq!(summary.termination, RunTermination::Fault(FaultReason::Io));
    assert_eq!(summary.safe_barriers_accepted, 1);
    assert!(io.output.is_empty());
    assert_eq!(motors.calls.last(), Some(&MotorPairCall::Inhibit));
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
    sequence_valid: bool,
    command_valid: bool,
    transfers: usize,
    forced_safe: usize,
    status_override: Option<(usize, [u8; 2])>,
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
        let sequence = frame[4];
        let distance = sequence.wrapping_sub(self.last_seq);
        self.command_valid = !self.sequence_valid || (distance != 0 && distance < 128);
        if self.command_valid {
            self.last_seq = sequence;
            self.sequence_valid = true;
        }
        self.transfers += 1;
        Ok(0)
    }

    fn read_runtime_status(&mut self) -> Result<[u8; 2], Self::Error> {
        Ok(self
            .status_override
            .filter(|(at, _)| *at == self.transfers)
            .map(|(_, status)| status)
            .unwrap_or([
                STATUS_READY
                    | if self.command_valid {
                        STATUS_COMMAND_VALID
                    } else {
                        0
                    },
                self.last_seq,
            ]))
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
        sequence_valid: false,
        command_valid: false,
        transfers: 0,
        forced_safe: 0,
        status_override: None,
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

#[test]
fn managed_fpga_posttransaction_mismatch_cannot_emit_acknowledgement() {
    for (at, wrong_sequence) in [(1, 1), (2, 0)] {
        let mut io = MockByteIo::new(frames(&[
            Msg::SessionOffer { session: 7 },
            Msg::SafeBarrier {
                session: 7,
                correlation: 1,
                sequence: 1,
            },
        ]));
        let mut motors = FpgaLifecycle::new(AckingFpga {
            last_seq: 0,
            sequence_valid: false,
            command_valid: false,
            transfers: 0,
            forced_safe: 0,
            status_override: Some((at, [STATUS_READY | STATUS_COMMAND_VALID, wrong_sequence])),
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
            &MockClock::new(0),
            &mut MockUltrasonic::new(vec![]),
            &mut MockEstop::new(false),
            &mut motors,
            managed_config(100, 7),
            Some(1),
        )
        .unwrap();

        assert_eq!(
            summary.termination,
            RunTermination::Fault(FaultReason::MotorSink)
        );
        assert_eq!(summary.safe_barriers_accepted, 0);
        assert!(io.output.is_empty());
        assert!(!motors.runtime_ready());
    }
}

#[test]
fn managed_fpga_session_zero_then_newer_barrier_one_produces_exact_replies() {
    let session = 21;
    let mut io = MockByteIo::new(frames(&[
        Msg::SessionOffer { session },
        Msg::SafeBarrier {
            session,
            correlation: 33,
            sequence: 1,
        },
    ]));
    let mut motors = FpgaLifecycle::new(AckingFpga {
        last_seq: 0,
        sequence_valid: false,
        command_valid: false,
        transfers: 0,
        forced_safe: 0,
        status_override: None,
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
        &MockClock::new(0),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, session),
        Some(1),
    )
    .unwrap();

    assert_eq!(summary.termination, RunTermination::IterationLimit);
    assert_eq!(summary.safe_barriers_accepted, 1);
    assert_eq!(motors.platform().transfers, 2);
    assert_eq!(
        decoded(&io.output),
        [
            Msg::SessionReady { session },
            Msg::SafeAck {
                session,
                correlation: 33,
                sequence: 1,
            }
        ]
    );
}

#[test]
fn managed_timeout_after_barrier_apply_suppresses_safe_ack() {
    let mut io = MockByteIo::new(frames(&[
        Msg::SessionOffer { session: 7 },
        Msg::SafeBarrier {
            session: 7,
            correlation: 1,
            sequence: 1,
        },
    ]));
    let clock = SequenceClock::new(vec![0, 0, 0, 0, 0, 0, 100]);
    let mut motors = MockMotorPair::new();
    let summary = run(
        &mut io,
        &clock,
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        managed_config(100, 7),
        Some(1),
    )
    .unwrap();

    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::WatchdogExpired)
    );
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

struct BackpressuredIo {
    budget: usize,
    per_iteration: usize,
    fail_after: Option<usize>,
    wire: Vec<u8>,
}
impl shrike_control::ByteIo for BackpressuredIo {
    type Error = ();
    fn read(&mut self) -> Result<Option<u8>, ()> {
        self.budget = self.per_iteration;
        Ok(None)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitFault {
    None,
    Read,
    Write,
    Idle,
    Reset,
    LateWrite,
    LateIdle,
    LateReset,
    ReversedWrite,
    ReversedReset,
    StopWrite,
    StopIdle,
    StopReset,
    FrozenBusy,
    FrozenWrite,
}

struct ExitClock(Cell<u64>);
impl MicrosClock for ExitClock {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
}
struct ExitEstop<'a>(&'a Cell<bool>);
impl shrike_control::EstopLine for ExitEstop<'_> {
    fn asserted(&mut self) -> bool {
        self.0.get()
    }
}

/// Existing wire mock, with one RX pause allowing an old reply to start before
/// the request arrives. Faults occur only after the complete request is read.
struct ExitIo<'a> {
    inner: MockByteIo,
    prefix_len: usize,
    paused: bool,
    first_budget: usize,
    fault: ExitFault,
    clock: &'a ExitClock,
    stopped: &'a Cell<bool>,
    idle_calls: usize,
    idle_waits: usize,
}
impl ExitIo<'_> {
    fn exiting(&self) -> bool {
        self.inner.reads >= self.prefix_len + 10
    }
}
impl shrike_control::ByteIo for ExitIo<'_> {
    type Error = ();
    fn read(&mut self) -> Result<Option<u8>, ()> {
        if self.inner.reads == self.prefix_len && !self.paused {
            self.paused = true;
            return Ok(None);
        }
        if self.exiting() && self.fault == ExitFault::Read {
            return Err(());
        }
        self.inner.read()
    }
    fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if !self.exiting() {
            let n = bytes.len().min(self.first_budget);
            self.first_budget -= n;
            return self.inner.try_write(&bytes[..n]);
        }
        match self.fault {
            ExitFault::Write => return Err(()),
            ExitFault::FrozenWrite => return Ok(0),
            ExitFault::LateWrite => self.clock.0.set(1_000_000),
            ExitFault::ReversedWrite => self.clock.0.set(0),
            ExitFault::StopWrite => self.stopped.set(true),
            _ => {}
        }
        self.inner.try_write(bytes)
    }
    fn tx_idle(&mut self) -> Result<bool, ()> {
        self.idle_calls += 1;
        match self.fault {
            ExitFault::Idle => return Err(()),
            ExitFault::LateIdle => self.clock.0.set(1_000_000),
            ExitFault::StopIdle => self.stopped.set(true),
            ExitFault::FrozenBusy => return Ok(false),
            _ => {}
        }
        Ok(self.idle_calls > self.idle_waits)
    }
    fn reset(&mut self) -> Result<(), ()> {
        match self.fault {
            ExitFault::Reset => self.inner.fail_reset = true,
            ExitFault::LateReset => self.clock.0.set(1_000_000),
            ExitFault::ReversedReset => self.clock.0.set(0),
            ExitFault::StopReset => self.stopped.set(true),
            _ => {}
        }
        self.inner.reset()
    }
}

#[test]
fn requalify_finishes_each_started_reply_offset_and_discards_pending_motion() {
    let prefix = frames(&[
        Msg::SessionOffer { session: 7 },
        Msg::SafeBarrier {
            session: 7,
            correlation: 1,
            sequence: 1,
        },
    ]);
    let ready = frames(&[Msg::SessionReady { session: 7 }]);
    let replies = frames(&[
        Msg::SessionReady { session: 7 },
        Msg::SafeAck {
            session: 7,
            correlation: 1,
            sequence: 1,
        },
    ]);
    for split in 0..=replies.len() {
        let clock = ExitClock(Cell::new(0));
        let stopped = Cell::new(false);
        let mut input = prefix.clone();
        input.extend(frames(&[
            Msg::Requalify { session: 8 },
            Msg::MotorSetpoint {
                seq: 2,
                left: 700,
                right: 700,
            },
        ]));
        let mut io = ExitIo {
            inner: MockByteIo::new(input),
            prefix_len: prefix.len(),
            paused: false,
            first_budget: split,
            fault: ExitFault::None,
            clock: &clock,
            stopped: &stopped,
            idle_calls: 0,
            idle_waits: 2,
        };
        let mut motors = MockMotorPair::new();
        let summary = run(
            &mut io,
            &clock,
            &mut MockUltrasonic::new(vec![]),
            &mut ExitEstop(&stopped),
            &mut motors,
            managed_config(100, 7),
            Some(3),
        )
        .unwrap();
        assert_eq!(
            summary.termination,
            RunTermination::Requalify {
                session: core::num::NonZeroU32::new(8).unwrap()
            },
            "split {split}"
        );
        let expected = if split == 0 {
            &[][..]
        } else if split <= ready.len() {
            &ready[..]
        } else {
            &replies[..]
        };
        assert_eq!(io.inner.output, expected, "split {split}");
        assert_eq!(summary.bytes_written as usize, expected.len());
        assert_eq!(
            summary.telemetry_frames_dropped,
            2 - decoded(expected).len() as u64
        );
        assert_eq!((io.idle_calls, io.inner.resets), (3, 1));
        assert!(!summary.io_reset_failed);
        assert_eq!(summary.motor_pairs_accepted, 2);
        assert_eq!(
            motors.calls,
            [
                MotorPairCall::Apply {
                    seq: 0,
                    left: 0,
                    right: 0
                },
                MotorPairCall::Apply {
                    seq: 1,
                    left: 0,
                    right: 0
                },
                MotorPairCall::Inhibit,
                MotorPairCall::Inhibit,
            ]
        );
        assert_eq!(shrike_control::ByteIo::read(&mut io.inner), Ok(None));
    }
}

#[test]
fn requalify_exit_faults_never_return_outer_owner_eligibility() {
    use shrike_control::transport::TransportError;
    for (fault, expected) in [
        (ExitFault::Read, RunTermination::Fault(FaultReason::Io)),
        (
            ExitFault::Write,
            RunTermination::Fault(FaultReason::Transport(TransportError::Io)),
        ),
        (ExitFault::Idle, RunTermination::Fault(FaultReason::Io)),
        (ExitFault::Reset, RunTermination::Fault(FaultReason::Io)),
        (
            ExitFault::LateWrite,
            RunTermination::Fault(FaultReason::Transport(TransportError::TimedOut)),
        ),
        (
            ExitFault::LateIdle,
            RunTermination::Fault(FaultReason::Transport(TransportError::TimedOut)),
        ),
        (
            ExitFault::LateReset,
            RunTermination::Fault(FaultReason::Transport(TransportError::TimedOut)),
        ),
        (
            ExitFault::ReversedWrite,
            RunTermination::Fault(FaultReason::Transport(TransportError::ClockRegression)),
        ),
        (
            ExitFault::ReversedReset,
            RunTermination::Fault(FaultReason::Transport(TransportError::ClockRegression)),
        ),
        (
            ExitFault::StopWrite,
            RunTermination::Stop(StopReason::HardwareEstop),
        ),
        (
            ExitFault::StopIdle,
            RunTermination::Stop(StopReason::HardwareEstop),
        ),
        (
            ExitFault::StopReset,
            RunTermination::Stop(StopReason::HardwareEstop),
        ),
        (
            ExitFault::FrozenBusy,
            RunTermination::Fault(FaultReason::Transport(TransportError::PollLimit)),
        ),
        (
            ExitFault::FrozenWrite,
            RunTermination::Fault(FaultReason::Transport(TransportError::PollLimit)),
        ),
    ] {
        let start = u64::from(matches!(
            fault,
            ExitFault::ReversedWrite | ExitFault::ReversedReset
        ));
        let clock = ExitClock(Cell::new(start));
        let stopped = Cell::new(false);
        let prefix = frames(&[Msg::SessionOffer { session: 7 }]);
        let mut input = prefix.clone();
        input.extend(frames(&[
            Msg::Requalify { session: 8 },
            Msg::MotorSetpoint {
                seq: 1,
                left: 700,
                right: 700,
            },
        ]));
        let mut io = ExitIo {
            inner: MockByteIo::new(input),
            prefix_len: prefix.len(),
            paused: false,
            first_budget: 3,
            fault,
            clock: &clock,
            stopped: &stopped,
            idle_calls: 0,
            idle_waits: 0,
        };
        let mut motors = MockMotorPair::new();
        let mut cfg = managed_config(100, 7);
        cfg.ping_period_us = u64::MAX;
        cfg.peer_heartbeat_period_us = 0;
        let summary = run(
            &mut io,
            &clock,
            &mut MockUltrasonic::new(vec![]),
            &mut ExitEstop(&stopped),
            &mut motors,
            cfg,
            None,
        )
        .unwrap();
        assert_eq!(summary.termination, expected, "{fault:?}");
        assert_eq!(summary.io_reset_failed, fault == ExitFault::Reset);
        assert_eq!(io.inner.resets, 1);
        assert_eq!(summary.motor_pairs_accepted, 1);
        assert_eq!(summary.motor_inhibit_calls, 2);
        assert_eq!(summary.bytes_written as usize, io.inner.output.len());
        assert!(motors
            .calls
            .iter()
            .all(|call| !matches!(call, MotorPairCall::Apply { left: 700, .. })));
        if fault == ExitFault::FrozenBusy {
            assert_eq!(io.idle_calls, 65_536);
        }
    }
}

#[test]
fn requalify_legacy_rejects_and_buffered_stop_cancels_managed_exit() {
    for managed in [false, true] {
        let mut input = frames(&[Msg::Requalify { session: 8 }]);
        // A complete stop beyond the first bounded RX pass must be observed
        // before reset, even though hardware TX is already idle.
        input.extend(frames(&[Msg::HeartbeatToShrike { seq: 1 }; 10]));
        input.extend(frames(&[
            Msg::Estop { assert: true },
            Msg::MotorSetpoint {
                seq: 1,
                left: 700,
                right: 700,
            },
        ]));
        let mut io = MockByteIo::new(input);
        let mut motors = MockMotorPair::new();
        let summary = run(
            &mut io,
            &MockClock::new(0),
            &mut MockUltrasonic::new(vec![]),
            &mut MockEstop::new(false),
            &mut motors,
            if managed {
                managed_config(100, 7)
            } else {
                config(100)
            },
            Some(1),
        )
        .unwrap();
        assert_eq!(
            summary.termination,
            if managed {
                RunTermination::Stop(StopReason::SoftwareEstop)
            } else {
                RunTermination::Fault(FaultReason::UnexpectedMessage)
            }
        );
        assert_eq!(summary.motor_pairs_accepted, 0);
        assert!(io.output.is_empty());
        assert_eq!(io.resets, 1);
    }
}

#[test]
fn requalify_exit_rejects_deadline_overflow_and_expired_old_command() {
    use shrike_control::transport::TransportError;
    let mut io = MockByteIo::new(frames(&[Msg::Requalify { session: 8 }]));
    let mut motors = MockMotorPair::new();
    let mut cfg = managed_config(100, 7);
    cfg.offer_deadline_us = u64::MAX; // Reach the exit deadline addition, not offer expiry.
    let summary = run(
        &mut io,
        &ExitClock(Cell::new(u64::MAX - 999_999)),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut motors,
        cfg,
        Some(1),
    )
    .unwrap();
    assert_eq!(
        summary.termination,
        RunTermination::Fault(FaultReason::Transport(TransportError::DeadlineOverflow))
    );
    assert_eq!(summary.motor_pairs_accepted, 0);
    assert_eq!(io.resets, 1);

    let mut io = MockByteIo::new(frames(&[
        Msg::SessionOffer { session: 7 },
        Msg::Requalify { session: 8 },
    ]));
    let summary = run(
        &mut io,
        &SequenceClock::new(vec![0, 0, 0, 0, 100]),
        &mut MockUltrasonic::new(vec![]),
        &mut MockEstop::new(false),
        &mut MockMotorPair::new(),
        managed_config(100, 7),
        Some(1),
    )
    .unwrap();
    assert_eq!(
        summary.termination,
        RunTermination::Stop(StopReason::WatchdogExpired)
    );
    assert!(io.output.is_empty());
}
