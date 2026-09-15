extern crate std;

use kernel_bpf::actuation::MotorPairDecision;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::signing::managed::{PrivateArray, EFFECT_MOTOR_PAIR};
use kernel_time::periodic::PeriodicSchedule;

use super::*;
use crate::actuation::{MotorPairSubmission, MotorPairSubmissionOutcome};
use crate::bpf::managed::tests::{artifact_from_program, stateful_managed_program};
use crate::bpf::BpfManager;

fn installed(program: &[BpfInsn]) -> (BpfManager, ControlSlot) {
    let mut manager = BpfManager::new();
    let artifact = artifact_from_program(
        1,
        true,
        EFFECT_MOTOR_PAIR,
        Some(PrivateArray {
            value_size: 8,
            max_entries: 1,
        }),
        program,
    );
    let handle = manager.register_managed_artifact(artifact).unwrap();
    manager.preparation.candidate = Some(handle);
    let mut slot = ControlSlot::new();
    let token = slot.begin(&mut manager, 0, None).unwrap();
    let id = slot.snapshot().pending.unwrap();
    slot.finish_build(&mut manager, token.build()).unwrap();
    slot.enter_handoff(id).unwrap();
    // Explicit host boundary; production still requires correlated sink safety.
    slot.commit_validated_handoff(id).unwrap();
    (manager, slot)
}

fn queued(pair: ManagedMotorPair) -> MotorPairSubmission {
    MotorPairSubmission {
        decision: Some(MotorPairDecision::Allow {
            left: pair.left,
            right: pair.right,
        }),
        outcome: MotorPairSubmissionOutcome::Queued,
    }
}

#[test]
fn verified_controller_reads_frozen_sensor_even_if_producer_publishes_again() {
    let (_manager, mut slot) = installed(&[
        BpfInsn::new(0x79, 0, 1, 0, 0),
        BpfInsn::new(0x79, 1, 0, 40, 0),
        BpfInsn::mov64_reg(2, 1),
        BpfInsn::call(kernel_abi::BPF_HELPER_MANAGED_MOTOR_PAIR_V1),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ]);
    let saved = *SENSOR.lock();
    publish_sensor(SensorSnapshot::received(9, 123, 0, false));
    let frozen = *SENSOR.lock();
    let release = PeriodicSchedule::new(0, 10)
        .unwrap()
        .release(10)
        .unwrap()
        .unwrap();
    let report = slot.run_release(
        release,
        100,
        frozen,
        80_000_000,
        &mut || {
            publish_sensor(SensorSnapshot::received(11, 456, 0, false));
            11
        },
        |pair, _, _, _| {
            assert_eq!(
                pair,
                ManagedMotorPair {
                    left: 123,
                    right: 123
                }
            );
            queued(pair)
        },
    );
    assert_eq!(report.failure, None);
    assert_eq!(report.context.unwrap().sensor_value, 123);
    assert_eq!(SENSOR.lock().echo_us, 456);
    invalidate_sensor();
    assert!(!SENSOR.lock().valid);
    *SENSOR.lock() = saved;
}

#[test]
fn reversal_after_submission_retains_queue_outcome_and_stops() {
    let (_manager, mut slot) = installed(&stateful_managed_program());
    let release = PeriodicSchedule::new(0, 10)
        .unwrap()
        .release(10)
        .unwrap()
        .unwrap();
    let mut ticks = [11, 12, 18, 17].into_iter();
    let report = slot.run_release(
        release,
        100,
        SensorSnapshot::default(),
        80_000_000,
        &mut || ticks.next().unwrap(),
        |pair, not_before, deadline, clock| {
            assert_eq!((not_before, deadline, clock()), (12, 20, 18));
            queued(pair)
        },
    );
    assert_eq!(report.failure, Some(CycleFailure::ClockReversed));
    assert_eq!(
        report.submission.unwrap().outcome,
        MotorPairSubmissionOutcome::Queued
    );
    assert!(slot.snapshot().inhibited);
}

#[test]
fn release_borrows_actual_state_once_and_duplicate_release_inhibits_it() {
    let (_manager, mut slot) = installed(&stateful_managed_program());
    let active = slot.snapshot().active;
    let mut schedule = PeriodicSchedule::new(0, 10_000_000).unwrap();
    let first = schedule.release(10_000_000).unwrap().unwrap();
    let sensor = SensorSnapshot::received(9_000_000, 123, 0, false);
    let mut requests = std::vec::Vec::new();
    let report = slot.run_release(
        first,
        1_000_000_000,
        sensor,
        80_000_000,
        &mut || 11_000_000,
        |pair, _, _, _| {
            requests.push(pair);
            queued(pair)
        },
    );
    assert_eq!(report.failure, None);
    assert_eq!(report.generation, 1);
    assert_eq!(report.context.unwrap().sensor_value, 123);
    assert_eq!(requests, [ManagedMotorPair { left: 0, right: 0 }]);
    let second = schedule.release(20_000_000).unwrap().unwrap();
    let report = slot.run_release(
        second,
        1_000_000_000,
        sensor,
        80_000_000,
        &mut || 21_000_000,
        |pair, _, _, _| {
            requests.push(pair);
            queued(pair)
        },
    );
    assert_eq!(report.failure, None);
    assert_eq!(requests[1], ManagedMotorPair { left: 1, right: 1 });
    let report = slot.run_release(
        second,
        1_000_000_000,
        sensor,
        80_000_000,
        &mut || panic!("duplicate must not execute"),
        |_, _, _, _| panic!("duplicate submit"),
    );
    assert_eq!(report.failure, Some(CycleFailure::InvalidRelease));
    assert!(slot.snapshot().inhibited);
    let third = schedule.release(30_000_000).unwrap().unwrap();
    let report = slot.run_release(
        third,
        1_000_000_000,
        sensor,
        80_000_000,
        &mut || panic!("stopped controller must remain inhibited"),
        |_, _, _, _| panic!(),
    );
    assert!(report.safe_mode);
    assert_eq!(slot.snapshot().active, active);
}

#[test]
fn sensor_receive_time_validity_and_checked_cycle_clock_are_frozen() {
    let mut schedule = PeriodicSchedule::new(0, 10).unwrap();
    let release = schedule.release(11).unwrap().unwrap();
    let sample = SensorSnapshot::received(9, 123, 0, false);
    let context = sample.context(release, 100, 30_000_000).unwrap();
    assert_eq!(
        (context.scheduled_ns, context.actual_ns, context.sensor_ns),
        (100_000_000, 110_000_000, 90_000_000)
    );
    assert_eq!((context.sensor_value, context.sensor_valid), (123, 1));
    assert_eq!(
        sample
            .context(release, 100, 20_000_000)
            .unwrap()
            .sensor_valid,
        0
    );
    for sample in [
        SensorSnapshot::default(),
        SensorSnapshot::received(12, 123, 0, false),
        SensorSnapshot::received(9, 123, 1, false),
        SensorSnapshot::received(9, 123, 0, true),
        SensorSnapshot::received(9, 0, 0, false),
    ] {
        assert_eq!(
            sample
                .context(release, 100, 30_000_000)
                .unwrap()
                .sensor_valid,
            0
        );
    }
    assert!(sample.context(release, 0, 30_000_000).is_err());
}

#[test]
fn missing_request_submits_zero_and_failed_invocation_discards_its_capture() {
    let mut repeated = std::vec![
        BpfInsn::mov64_imm(1, 20),
        BpfInsn::mov64_imm(2, 30),
        BpfInsn::call(kernel_abi::BPF_HELPER_MANAGED_MOTOR_PAIR_V1),
    ];
    repeated.extend_from_within(..);
    repeated.extend([BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
    let empty = [BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
    for (program, fails) in [(&empty[..], false), (&repeated[..], true)] {
        let (_manager, mut slot) = installed(program);
        let release = PeriodicSchedule::new(0, 10)
            .unwrap()
            .release(10)
            .unwrap()
            .unwrap();
        let mut submitted = false;
        let report = slot.run_release(
            release,
            100,
            SensorSnapshot::default(),
            80_000_000,
            &mut || 11,
            |pair, _, _, _| {
                submitted = true;
                assert_eq!(pair, ManagedMotorPair { left: 0, right: 0 });
                queued(pair)
            },
        );
        assert_eq!(submitted, !fails);
        assert_eq!(report.failure.is_some(), fails);
        assert_eq!(slot.snapshot().inhibited, fails);
        assert_eq!(report.requested, None);
    }
}

#[test]
fn missed_deadlines_reversed_clocks_and_queue_failure_never_resume_automatically() {
    for (ticks, expected, queued_before_stop) in [
        ([9, 11, 11], CycleFailure::ClockReversed, false),
        ([20, 20, 20], CycleFailure::Deadline, false),
        ([11, 10, 11], CycleFailure::ClockReversed, false),
        ([11, 20, 20], CycleFailure::Deadline, false),
        ([11, 12, 20], CycleFailure::Deadline, true),
    ] {
        let (_manager, mut slot) = installed(&stateful_managed_program());
        let release = PeriodicSchedule::new(0, 10)
            .unwrap()
            .release(10)
            .unwrap()
            .unwrap();
        let mut ticks = ticks.into_iter();
        let mut submitted = false;
        let report = slot.run_release(
            release,
            100,
            SensorSnapshot::default(),
            80_000_000,
            &mut || ticks.next().unwrap(),
            |pair, _, _, _| {
                submitted = true;
                queued(pair)
            },
        );
        assert_eq!(report.failure, Some(expected));
        assert_eq!(submitted, queued_before_stop);
        assert_eq!(report.submission.is_some(), queued_before_stop);
        assert!(slot.snapshot().inhibited);
    }
    let (_manager, mut slot) = installed(&stateful_managed_program());
    let release = PeriodicSchedule::new(0, 10)
        .unwrap()
        .release(30)
        .unwrap()
        .unwrap();
    let report = slot.run_release(
        release,
        100,
        SensorSnapshot::default(),
        80_000_000,
        &mut || panic!(),
        |_, _, _, _| panic!(),
    );
    assert_eq!(report.failure, Some(CycleFailure::MissedRelease));
    let (_manager, mut slot) = installed(&stateful_managed_program());
    let release = PeriodicSchedule::new(0, 10)
        .unwrap()
        .release(10)
        .unwrap()
        .unwrap();
    let report = slot.run_release(
        release,
        100,
        SensorSnapshot::default(),
        80_000_000,
        &mut || 11,
        |_, _, _, _| MotorPairSubmission {
            decision: None,
            outcome: MotorPairSubmissionOutcome::QueueFailed,
        },
    );
    assert_eq!(
        report.failure,
        Some(CycleFailure::Submission(
            MotorPairSubmissionOutcome::QueueFailed
        ))
    );
    assert!(slot.snapshot().inhibited);
}
