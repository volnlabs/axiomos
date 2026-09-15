//! Trusted producers; payloads describe software observations, never movement.
use kernel_abi::*;
use kernel_bpf::actuation::{AuditSource, MotorPairDecision};
use kernel_bpf::execution::BpfError;
use kernel_time::periodic::PeriodicRelease;
use zerocopy::IntoBytes;

use super::{Record, State};
use crate::actuation::MotorPairSubmissionOutcome;
use crate::bpf::control::{CycleFailure, CycleReport};

impl State {
    fn record_cycle(&mut self, release: PeriodicRelease, report: CycleReport, ticks: u64) {
        if report.safe_mode
            && !report.handoff
            && report.failure.is_none()
            && release.missed_before == 0
        {
            self.window.suppress_unchanged();
            return;
        }
        if !report.safe_mode {
            self.window.leave_stopped_state();
        }
        let (failure, failure_detail) = failure_code(report.failure);
        let mut payload = ManagedAuditCycleV1 {
            cycle_id: release.sequence,
            scheduled_ticks: release.scheduled,
            actual_ticks: release.actual,
            missed_releases: release.missed_before,
            artifact_handle: report.artifact.unwrap_or(0),
            flags: (u32::from(report.artifact.is_some()) * MANAGED_AUDIT_CYCLE_HAS_ARTIFACT)
                | (u32::from(report.safe_mode) * MANAGED_AUDIT_CYCLE_SAFE)
                | (u32::from(report.handoff) * MANAGED_AUDIT_CYCLE_HANDOFF)
                | (u32::from(report.invocation_completed) * MANAGED_AUDIT_CYCLE_REQUEST_KNOWN),
            failure,
            failure_detail,
            ..Default::default()
        };
        if let Some(pair) = report.requested {
            payload.flags |= MANAGED_AUDIT_CYCLE_HAS_REQUEST;
            payload.requested_left = pair.left;
            payload.requested_right = pair.right;
        }
        if let Some(submission) = report.submission {
            payload.queue_outcome = queue_code(submission.outcome);
            if let Some(decision) = submission.decision {
                let (left, right, _) = decision.apply();
                payload.decided_left = left;
                payload.decided_right = right;
                payload.decision = match decision {
                    MotorPairDecision::Allow { .. } => 1,
                    MotorPairDecision::Clamp { .. } => 2,
                    MotorPairDecision::Safe { .. } => 3,
                };
            }
        }
        let _ = self.window.append(Record {
            ticks,
            correlation: report.generation,
            kind: MANAGED_AUDIT_CYCLE,
            payload: payload
                .as_bytes()
                .try_into()
                .expect("64-byte cycle payload"),
            ..Record::EMPTY
        });
        if report.failure.is_some() {
            self.cycle_stop(release, report, ticks, 2, 0);
        }
    }

    fn trusted_stop(&mut self, source: AuditSource, ticks: u64) {
        self.stop(
            ManagedAuditStopV1 {
                category: 1,
                source: source_code(source),
                ..Default::default()
            },
            0,
            ticks,
        );
    }

    fn cycle_stop(
        &mut self,
        release: PeriodicRelease,
        report: CycleReport,
        ticks: u64,
        category: u32,
        observed_ticks: u64,
    ) {
        let (reason, detail) = if category == 4 {
            (5, 0)
        } else {
            failure_code(report.failure)
        };
        self.stop(
            ManagedAuditStopV1 {
                cycle_id: release.sequence,
                observed_ticks,
                deadline_ticks: release.deadline,
                artifact_handle: report.artifact.unwrap_or(0),
                flags: MANAGED_AUDIT_STOP_HAS_CYCLE
                    | (u32::from(report.artifact.is_some()) * MANAGED_AUDIT_STOP_HAS_ARTIFACT),
                category,
                source: source_code(AuditSource::ManagedControl),
                reason,
                detail,
                ..Default::default()
            },
            report.generation,
            ticks,
        );
    }

    fn stop(&mut self, payload: ManagedAuditStopV1, generation: u64, ticks: u64) {
        let _ = self.window.append(Record {
            ticks,
            correlation: generation,
            kind: MANAGED_AUDIT_STOP,
            payload: payload.as_bytes().try_into().expect("64-byte stop payload"),
            ..Record::EMPTY
        });
    }

    fn released(&mut self, source: AuditSource, ticks: u64) {
        let mut record = Record {
            ticks,
            kind: MANAGED_AUDIT_LINK,
            ..Record::EMPTY
        };
        record.payload[..4].copy_from_slice(&2u32.to_le_bytes());
        record.payload[4..8].copy_from_slice(&source_code(source).to_le_bytes());
        let _ = self.window.append(record);
        // Local monitor release does not mean execution or physical rearm.
        // Keep the latest stop and suppression until trusted execution resumes.
    }
}

fn source_code(source: AuditSource) -> u32 {
    match source {
        AuditSource::Operator => 1,
        AuditSource::Watchdog => 2,
        AuditSource::GpioHook => 3,
        AuditSource::LearnedBehavior => 4,
        AuditSource::Mission => 5,
        AuditSource::SyscallPwm => 6,
        AuditSource::ManagedControl => 7,
    }
}

fn queue_code(outcome: MotorPairSubmissionOutcome) -> u32 {
    match outcome {
        MotorPairSubmissionOutcome::Queued => 1,
        MotorPairSubmissionOutcome::OwnershipRejected => 2,
        MotorPairSubmissionOutcome::DeadlineExpired => 3,
        MotorPairSubmissionOutcome::ClockReversed => 4,
        MotorPairSubmissionOutcome::QueueFailed => 5,
    }
}

fn failure_code(failure: Option<CycleFailure>) -> (u32, u32) {
    use shrike_link::handoff::HandoffError;
    let code = match failure {
        None => 0,
        Some(CycleFailure::InvalidRelease) => 1,
        Some(CycleFailure::MissedRelease) => 2,
        Some(CycleFailure::ClockInvalid) => 3,
        Some(CycleFailure::ClockReversed) => 4,
        Some(CycleFailure::Deadline) => 5,
        Some(CycleFailure::Submission(outcome)) => return (6, queue_code(outcome)),
        Some(CycleFailure::PolicyStopped) => 7,
        Some(CycleFailure::Invocation(error)) => match error {
            BpfError::DivisionByZero => 1001,
            BpfError::OutOfBounds => 1002,
            BpfError::StackOverflow => 1003,
            BpfError::InvalidHelper(id) => return (1004, id as u32),
            BpfError::Timeout => 1005,
            BpfError::InvalidInstruction => 1006,
            BpfError::NotLoaded => 1007,
            BpfError::OutOfMemory => 1008,
            BpfError::ResourceLimit => 1009,
            BpfError::ObjectBusy => 1010,
            BpfError::PermissionDenied => 1011,
            BpfError::ReentrantExecution => 1012,
            BpfError::VerificationFailed => 1013,
            BpfError::SignatureRejected => 1014,
            BpfError::AdmissionRejected => 1015,
            BpfError::GpioFanoutExceeded => 1016,
            BpfError::ReadOnlyMap => 1017,
            BpfError::ManagedContextInvalid => 1018,
            BpfError::ManagedRequestDuplicate => 1019,
            BpfError::ManagedRequestInvalid => 1020,
            BpfError::ManagedMapFailure => 1021,
        },
        Some(CycleFailure::Handoff(error)) => match error {
            HandoffError::NotEstablished => 2001,
            HandoffError::Busy => 2002,
            HandoffError::BadIdentity => 2003,
            HandoffError::InvalidTimeout => 2004,
            HandoffError::Exhausted => 2005,
            HandoffError::Stale => 2006,
            HandoffError::TimedOut => 2007,
            HandoffError::ClockReversed => 2008,
            HandoffError::InvalidRelease => 2009,
        },
    };
    (code, 0)
}

// These wrappers never take the slot, manager or actuator locks. Producers in
// those critical sections can safely append without changing lock order.
fn observe(f: impl FnOnce(&mut State, u64)) {
    #[cfg(all(feature = "managed-runtime", target_arch = "aarch64", feature = "rpi5"))]
    let _ = super::with_owner(|state| {
        let ticks = crate::arch::aarch64::interrupts::physical_counter();
        f(state, ticks);
        Ok(())
    });
    #[cfg(not(all(feature = "managed-runtime", target_arch = "aarch64", feature = "rpi5")))]
    let _ = f;
}

pub(crate) fn cycle(release: PeriodicRelease, report: CycleReport) {
    observe(|state, ticks| state.record_cycle(release, report, ticks));
}

pub(crate) fn trusted_stop(source: AuditSource) {
    observe(|state, ticks| state.trusted_stop(source, ticks));
}

pub(crate) fn released(source: AuditSource) {
    observe(|state, ticks| state.released(source, ticks));
}

pub(crate) fn timer_fault(reason: u32) {
    observe(|state, ticks| {
        state.stop(
            ManagedAuditStopV1 {
                category: 3,
                source: source_code(AuditSource::ManagedControl),
                reason,
                ..Default::default()
            },
            0,
            ticks,
        )
    });
}

pub(crate) fn completion_miss(release: PeriodicRelease, report: CycleReport, observed: u64) {
    observe(|state, ticks| state.cycle_stop(release, report, ticks, 4, observed));
}

#[cfg(test)]
mod tests {
    use kernel_bpf::execution::ManagedMotorPair;
    use kernel_time::periodic::PeriodicSchedule;
    use zerocopy::FromBytes;

    use super::*;
    use crate::actuation::MotorPairSubmission;
    use crate::bpf::control::SensorSnapshot;

    #[test]
    fn actual_controller_fault_keeps_queue_outcome_identity_and_stop_window() {
        let (_manager, mut slot) = crate::bpf::control::tests::installed(
            &crate::bpf::managed::tests::stateful_managed_program(),
        );
        let identity = slot.snapshot();
        let mut schedule = PeriodicSchedule::new(0, 10).unwrap();
        let release = schedule.release(10).unwrap().unwrap();
        let mut ticks = [11, 12, 18, 17].into_iter();
        let report = slot.run_release(
            release,
            100,
            SensorSnapshot::default(),
            80_000_000,
            &mut || ticks.next().unwrap(),
            |pair, _, _, clock| {
                assert_eq!(clock(), 18);
                MotorPairSubmission {
                    decision: Some(MotorPairDecision::Allow {
                        left: pair.left,
                        right: pair.right,
                    }),
                    outcome: MotorPairSubmissionOutcome::Queued,
                }
            },
        );
        assert_eq!(report.artifact, identity.active);
        assert_eq!(report.generation, identity.generation);
        assert_eq!(report.failure, Some(CycleFailure::ClockReversed));
        let mut state = State::new();
        state.record_cycle(release, report, 19);
        let batch = state.window.read(0).unwrap();
        assert_eq!(batch.count, 2);
        let cycle = ManagedAuditCycleV1::read_from_bytes(&batch.records[0].payload).unwrap();
        assert_eq!(batch.records[0].correlation, identity.generation);
        assert_eq!(cycle.artifact_handle, identity.active.unwrap());
        assert_eq!((cycle.queue_outcome, cycle.failure), (1, 4));
        let stop = state.window.status().latest_stop.unwrap();
        assert_eq!(stop.0, batch.records[1]);
        for i in 2..=2050 {
            let release = schedule.release(i * 10).unwrap().unwrap();
            let stopped = slot.run_release(
                release,
                100,
                SensorSnapshot::default(),
                80_000_000,
                &mut || panic!("stopped controller ran"),
                |_, _, _, _| panic!("stopped controller submitted"),
            );
            state.record_cycle(release, stopped, release.actual + 1);
        }
        assert_eq!(state.window.status().next, 2);
        assert_eq!(state.window.status().suppressed, 2049);
        assert_eq!(state.window.status().latest_stop, Some(stop));
        // Scheduled safe handoff cycles and missed releases remain visible.
        let mut safe = report;
        safe.safe_mode = true;
        safe.handoff = true;
        safe.failure = None;
        safe.invocation_completed = false;
        safe.requested = None;
        safe.submission = None;
        state.record_cycle(release, safe, 20501);
        assert_eq!(state.window.status().next, 3);
        safe.handoff = false;
        let mut missed = release;
        missed.missed_before = 2;
        state.record_cycle(missed, safe, 20502);
        assert_eq!(state.window.status().next, 4);
    }

    #[test]
    fn global_stops_do_not_invent_identity_and_negative_pairs_stay_signed() {
        let mut state = State::new();
        state.trusted_stop(AuditSource::Operator, 9);
        state.trusted_stop(AuditSource::Operator, 10);
        let summary = state.window.status();
        assert_eq!((summary.next, summary.suppressed), (1, 1));
        let stop = summary.latest_stop.unwrap().0;
        assert_eq!((stop.correlation, stop.ticks), (0, 9));
        let payload = ManagedAuditStopV1::read_from_bytes(&stop.payload).unwrap();
        assert_eq!((payload.flags, payload.source, payload.category), (0, 1, 1));
        let release = PeriodicSchedule::new(0, 10)
            .unwrap()
            .release(10)
            .unwrap()
            .unwrap();
        let report = CycleReport {
            generation: 1 << 40,
            artifact: Some(0),
            handoff: false,
            safe_mode: false,
            context: None,
            invocation_completed: true,
            requested: Some(ManagedMotorPair {
                left: -250,
                right: 300,
            }),
            submission: Some(MotorPairSubmission {
                decision: Some(MotorPairDecision::Clamp {
                    left: -100,
                    right: 100,
                }),
                outcome: MotorPairSubmissionOutcome::QueueFailed,
            }),
            failure: Some(CycleFailure::Submission(
                MotorPairSubmissionOutcome::QueueFailed,
            )),
        };
        state.record_cycle(release, report, 11);
        let record = state.window.read(1).unwrap().records[0];
        let cycle = ManagedAuditCycleV1::read_from_bytes(&record.payload).unwrap();
        assert_eq!((cycle.requested_left, cycle.requested_right), (-250, 300));
        assert_eq!((cycle.decided_left, cycle.decided_right), (-100, 100));
        assert_eq!((cycle.decision, cycle.queue_outcome), (2, 5));
        assert_eq!(
            cycle.flags,
            MANAGED_AUDIT_CYCLE_HAS_REQUEST
                | MANAGED_AUDIT_CYCLE_HAS_ARTIFACT
                | MANAGED_AUDIT_CYCLE_REQUEST_KNOWN
        );
        assert_eq!(record.correlation, 1 << 40);
        // Real execution resets stopped-state suppression; a later operator
        // stop is a new event even with identical source and no global identity.
        state.trusted_stop(AuditSource::Operator, 12);
        assert_eq!(state.window.status().latest_stop.unwrap().0.ticks, 12);
        let stopped = state.window.status().latest_stop;
        state.released(AuditSource::Operator, 13);
        assert_eq!(state.window.status().latest_stop, stopped);
        // The late final timer check overrides the earlier cycle observation;
        // it retains this cycle's identity and actual observed completion time.
        state.cycle_stop(release, report, 21, 4, 20);
        let stopped = state.window.status().latest_stop.unwrap().0;
        let payload = ManagedAuditStopV1::read_from_bytes(&stopped.payload).unwrap();
        assert_eq!(
            (stopped.correlation, payload.category, payload.reason),
            (1 << 40, 4, 5)
        );
        assert_eq!((payload.observed_ticks, payload.deadline_ticks), (20, 20));
        assert_eq!(
            payload.flags,
            MANAGED_AUDIT_STOP_HAS_CYCLE | MANAGED_AUDIT_STOP_HAS_ARTIFACT
        );
    }

    #[test]
    fn failed_invocation_request_is_unknown_and_fault_detail_is_not_truncated() {
        let release = PeriodicSchedule::new(0, 10)
            .unwrap()
            .release(10)
            .unwrap()
            .unwrap();
        let mut report = CycleReport {
            generation: 1,
            artifact: Some(0),
            handoff: false,
            safe_mode: false,
            context: None,
            invocation_completed: false,
            requested: None,
            submission: None,
            failure: Some(CycleFailure::Invocation(BpfError::InvalidHelper(i32::MIN))),
        };
        let mut state = State::new();
        state.record_cycle(release, report, 11);
        let cycle =
            ManagedAuditCycleV1::read_from_bytes(&state.window.read(0).unwrap().records[0].payload)
                .unwrap();
        assert_eq!(
            (cycle.failure, cycle.failure_detail),
            (1004, i32::MIN as u32)
        );
        assert_eq!(cycle.flags & MANAGED_AUDIT_CYCLE_REQUEST_KNOWN, 0);
        assert_eq!((cycle.decision, cycle.queue_outcome), (0, 0));
        report.failure = None;
        report.invocation_completed = true;
        state.record_cycle(release, report, 12);
        let cycle =
            ManagedAuditCycleV1::read_from_bytes(&state.window.read(2).unwrap().records[0].payload)
                .unwrap();
        assert_ne!(cycle.flags & MANAGED_AUDIT_CYCLE_REQUEST_KNOWN, 0);
        assert_eq!(cycle.flags & MANAGED_AUDIT_CYCLE_HAS_REQUEST, 0);
    }
}
