//! Trusted producers; payloads describe software observations, never movement.
use kernel_abi::*;
use kernel_bpf::actuation::{AuditSource, MotorPairDecision};
use kernel_bpf::execution::BpfError;
use kernel_bpf::signing::managed::{ArtifactIdentity, MANIFEST_SIZE};
use kernel_time::periodic::PeriodicRelease;
use zerocopy::IntoBytes;

use super::{Record, State};
use crate::actuation::MotorPairSubmissionOutcome;
use crate::bpf::control::{CycleFailure, CycleReport};

const _: () = assert!(MANIFEST_SIZE + 64 == 4 * 56);

impl State {
    fn record_upload(
        &mut self,
        operation: &ManagedOperationV1,
        identity: Option<(&[u8; MANIFEST_SIZE], &ArtifactIdentity)>,
        cost: Option<u64>,
        ticks: u64,
    ) {
        let payload = ManagedAuditUploadV1 {
            operation_kind: MANAGED_AUDIT_UPLOAD,
            phase: operation.phase,
            error: operation.error,
            flags: (u32::from(identity.is_some()) * MANAGED_AUDIT_UPLOAD_HAS_IDENTITY)
                | (u32::from(operation.phase == MANAGED_OPERATION_RESIDENT)
                    * MANAGED_AUDIT_UPLOAD_HAS_ARTIFACT)
                | (u32::from(cost.is_some()) * MANAGED_AUDIT_UPLOAD_HAS_COST),
            artifact_handle: operation.artifact_handle,
            total_bytes: operation.total_bytes,
            received_bytes: operation.received_bytes,
            workspace_peak: operation.workspace_peak,
            modeled_wcet_cycles: cost.unwrap_or(0),
            ..Default::default()
        };
        let record = Record {
            ticks,
            correlation: operation.id,
            kind: MANAGED_AUDIT_OPERATION,
            payload: payload
                .as_bytes()
                .try_into()
                .expect("64-byte upload payload"),
            ..Record::EMPTY
        };
        let _ = self.window.append(record);
        if let Some((manifest, identity)) = identity {
            let mut bytes = [0u8; MANIFEST_SIZE + 64];
            bytes[..MANIFEST_SIZE].copy_from_slice(manifest);
            bytes[MANIFEST_SIZE..MANIFEST_SIZE + 32]
                .copy_from_slice(identity.bundle_digest.as_bytes());
            bytes[MANIFEST_SIZE + 32..].copy_from_slice(identity.signer_fingerprint.as_bytes());
            for (index, data) in bytes.chunks_exact(56).enumerate() {
                let fragment = ManagedAuditIdentityFragmentV1 {
                    index: index as u32,
                    artifact_handle: operation.artifact_handle,
                    data: data.try_into().expect("56-byte identity fragment"),
                };
                let _ = self.window.append(Record {
                    kind: MANAGED_AUDIT_ARTIFACT,
                    payload: fragment
                        .as_bytes()
                        .try_into()
                        .expect("64-byte identity payload"),
                    ..record
                });
            }
        }
    }

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
            self.link_stop = None;
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
        if source == AuditSource::ManagedControl {
            if let Some((operation, reason, detail)) = self.link_stop {
                self.link_fault(operation, reason, detail, ticks);
                return;
            }
        }
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

    fn stop(&mut self, payload: ManagedAuditStopV1, correlation: u64, ticks: u64) {
        self.link_stop =
            (payload.category == 5).then_some((correlation, payload.reason, payload.detail));
        let _ = self.window.append(Record {
            ticks,
            correlation,
            kind: MANAGED_AUDIT_STOP,
            payload: payload.as_bytes().try_into().expect("64-byte stop payload"),
            ..Record::EMPTY
        });
    }

    fn link_fault(&mut self, operation: u64, reason: u32, detail: u32, ticks: u64) {
        self.stop(
            ManagedAuditStopV1 {
                category: 5,
                source: source_code(AuditSource::ManagedControl),
                flags: u32::from(operation != 0) * MANAGED_AUDIT_STOP_HAS_OPERATION,
                reason,
                detail,
                ..Default::default()
            },
            operation,
            ticks,
        );
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
    #[cfg(test)]
    tests::observe(f);
    #[cfg(all(
        not(test),
        feature = "managed-runtime",
        target_arch = "aarch64",
        feature = "rpi5"
    ))]
    let _ = super::with_owner(|state| {
        let ticks = crate::arch::aarch64::interrupts::physical_counter();
        f(state, ticks);
        Ok(())
    });
    #[cfg(all(
        not(test),
        not(all(feature = "managed-runtime", target_arch = "aarch64", feature = "rpi5"))
    ))]
    let _ = f;
}

pub(crate) fn cycle(release: PeriodicRelease, report: CycleReport) {
    observe(|state, ticks| state.record_cycle(release, report, ticks));
}

/// Worker supplies only a successfully authenticated manifest. One owner
/// critical section keeps the outcome and its four fragments consecutive.
/// Overflow/exhaustion are recorder loss, never preparation failure.
pub(crate) fn upload(
    operation: &ManagedOperationV1,
    identity: Option<(&[u8; MANIFEST_SIZE], &ArtifactIdentity)>,
    cost: Option<u64>,
) {
    observe(|state, ticks| state.record_upload(operation, identity, cost, ticks));
}

pub(crate) fn lifecycle(public_id: u64, payload: ManagedAuditLifecycleV1) {
    observe(|state, ticks| {
        let _ = state.window.append(Record {
            ticks,
            correlation: public_id,
            kind: MANAGED_AUDIT_OPERATION,
            payload: payload
                .as_bytes()
                .try_into()
                .expect("64-byte lifecycle payload"),
            ..Record::EMPTY
        });
    });
}

fn motor_record(
    request: shrike_link::tx::MotorRequest,
    frame: Option<(u8, bool)>,
    event: u32,
    reason: u32,
    ticks: u64,
) -> Record {
    let origin = request.origin;
    let payload = ManagedAuditMotorTxV1 {
        link_kind: MANAGED_AUDIT_MOTOR_TX,
        event,
        cycle_id: origin.map_or(0, |v| v.cycle),
        queued_at_ns: request.queued_at,
        artifact_handle: origin.map_or(0, |v| v.artifact_handle),
        flags: (u32::from(origin.is_some()) * MANAGED_AUDIT_MOTOR_HAS_ORIGIN)
            | (u32::from(frame.is_some_and(|(_, zero)| zero))
                * MANAGED_AUDIT_MOTOR_INTERMEDIATE_ZERO),
        left: request.left,
        right: request.right,
        command_sequence: frame.map_or(0, |(sequence, _)| u32::from(sequence)),
        reason,
        ..Default::default()
    };
    Record {
        ticks,
        correlation: origin.map_or(0, |v| v.generation),
        kind: MANAGED_AUDIT_LINK,
        payload: payload
            .as_bytes()
            .try_into()
            .expect("64-byte motor TX payload"),
        ..Record::EMPTY
    }
}

/// Only a successfully framed command or its final locally accepted byte.
pub(crate) fn motor_tx(frame: shrike_link::tx::MotorFrame, completed: bool) {
    observe(|state, ticks| {
        let _ = state.window.append(motor_record(
            frame.request,
            Some((frame.sequence, frame.intermediate_zero)),
            if completed {
                MANAGED_AUDIT_MOTOR_LOCAL_COMPLETE
            } else {
                MANAGED_AUDIT_MOTOR_FRAMED
            },
            0,
            ticks,
        ));
    });
}

/// At most two directly returned removals, with their original identities.
pub(crate) fn motor_discard(discarded: shrike_link::tx::MotorDiscards, reason: u32) {
    if discarded.pending.is_none() && discarded.frame.is_none() {
        return;
    }
    observe(|state, ticks| {
        if let Some(request) = discarded.pending {
            let _ = state.window.append(motor_record(
                request,
                None,
                MANAGED_AUDIT_MOTOR_PENDING_DISCARDED,
                reason,
                ticks,
            ));
        }
        if let Some(frame) = discarded.frame {
            let _ = state.window.append(motor_record(
                frame.request,
                Some((frame.sequence, frame.intermediate_zero)),
                MANAGED_AUDIT_MOTOR_FRAME_DISCARDED,
                reason,
                ticks,
            ));
        }
    });
}

pub(crate) fn trusted_stop(source: AuditSource) {
    observe(|state, ticks| state.trusted_stop(source, ticks));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkFault {
    Receive(u8),
    Decode(shrike_link::LinkError),
    Overflow(u32),
    PeerEstop,
    InboundTimeout,
    Handoff(shrike_link::handoff::HandoffError),
    Unavailable,
    Quiescence(u32),
}

pub(crate) fn link_fault(operation: Option<u64>, fault: LinkFault) {
    use shrike_link::LinkError;
    let (reason, detail) = match fault {
        LinkFault::Receive(bits) => (1, u32::from(bits)),
        LinkFault::Decode(error) => (
            2,
            match error {
                LinkError::BufTooSmall => 1,
                LinkError::BadLen => 2,
                LinkError::BadCrc => 3,
                LinkError::BadVersion => 4,
                LinkError::BadIdentity => 5,
                LinkError::UnknownType => 6,
            },
        ),
        LinkFault::Overflow(count) => (3, count),
        LinkFault::PeerEstop => (4, 0),
        LinkFault::InboundTimeout => (5, 0),
        LinkFault::Handoff(error) => (6, failure_code(Some(CycleFailure::Handoff(error))).0),
        LinkFault::Unavailable => (7, 0),
        LinkFault::Quiescence(detail) => (8, detail),
    };
    observe(|state, ticks| state.link_fault(operation.unwrap_or(0), reason, detail, ticks));
}

pub(crate) fn handoff(
    event: u32,
    operation: Option<u64>,
    message: shrike_link::Msg,
    observed_ticks: Option<u64>,
    generation: Option<u64>,
    error: Option<shrike_link::handoff::HandoffError>,
) {
    use shrike_link::Msg;
    let (message_kind, session, wire_correlation, command_sequence) = match message {
        Msg::SessionOffer { session } => (1, session, 0, 0),
        Msg::SessionReady { session } => (2, session, 0, 0),
        Msg::SafeBarrier {
            session,
            correlation,
            sequence,
        } => (3, session, correlation, u32::from(sequence)),
        Msg::SafeAck {
            session,
            correlation,
            sequence,
        } => (4, session, correlation, u32::from(sequence)),
        _ => return,
    };
    observe(|state, ticks| {
        let payload = ManagedAuditHandoffV1 {
            link_kind: MANAGED_AUDIT_HANDOFF_LINK,
            event,
            session,
            wire_correlation,
            command_sequence,
            observed_ticks: observed_ticks.unwrap_or(ticks),
            generation: generation.unwrap_or(0),
            message_kind,
            error: failure_code(error.map(CycleFailure::Handoff)).0,
            flags: (u32::from(operation.is_some()) * MANAGED_AUDIT_HANDOFF_HAS_OPERATION)
                | (u32::from(generation.is_some()) * MANAGED_AUDIT_HANDOFF_HAS_GENERATION),
            ..Default::default()
        };
        let _ = state.window.append(Record {
            ticks,
            correlation: operation.unwrap_or(0),
            kind: MANAGED_AUDIT_LINK,
            payload: payload
                .as_bytes()
                .try_into()
                .expect("64-byte handoff payload"),
            ..Record::EMPTY
        });
    });
}

pub(crate) fn handoff_reply(
    operation: Option<u64>,
    message: shrike_link::Msg,
    observed_ticks: u64,
    result: Result<bool, shrike_link::handoff::HandoffError>,
) {
    if !matches!(
        message,
        shrike_link::Msg::SessionReady { .. } | shrike_link::Msg::SafeAck { .. }
    ) {
        return;
    }
    handoff(
        match result {
            Ok(true) => MANAGED_AUDIT_HANDOFF_REPLY_ACCEPTED,
            Ok(false) => MANAGED_AUDIT_HANDOFF_REPLY_IGNORED,
            Err(_) => MANAGED_AUDIT_HANDOFF_REPLY_REJECTED,
        },
        operation,
        message,
        Some(observed_ticks),
        None,
        result.err(),
    );
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
pub(crate) mod tests {
    extern crate std;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use kernel_bpf::execution::ManagedMotorPair;
    use kernel_time::periodic::PeriodicSchedule;
    use zerocopy::FromBytes;

    use super::*;
    use crate::actuation::MotorPairSubmission;
    use crate::bpf::control::SensorSnapshot;

    std::thread_local! {
        static CAPTURE: RefCell<Option<Box<State>>> = const { RefCell::new(None) };
    }

    pub(super) fn observe(f: impl FnOnce(&mut State, u64)) {
        CAPTURE.with(|capture| {
            if let Some(state) = capture.borrow_mut().as_mut() {
                let ticks = state.window.status().next;
                f(state, ticks);
            }
        });
    }

    /// Test-local capture of real producers; no host hardware owner is enabled.
    pub(crate) fn capture_records(f: impl FnOnce()) -> Vec<Record> {
        CAPTURE.with(|capture| {
            assert!(capture.borrow().is_none());
            *capture.borrow_mut() = Some(Box::new(State::new()));
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let state = CAPTURE.with(|capture| capture.borrow_mut().take().unwrap());
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
        assert_eq!(
            state.window.status().oldest,
            0,
            "capture exceeds retained test window"
        );
        let mut records = Vec::new();
        while (records.len() as u64) < state.window.status().next {
            let batch = state.window.read(records.len() as u64).unwrap();
            records.extend_from_slice(&batch.records[..batch.count]);
        }
        records
    }

    #[test]
    fn link_fault_preserves_cause_through_generic_stop_and_suppresses_repetition() {
        use shrike_link::handoff::HandoffError;
        use shrike_link::LinkError;
        let faults = [
            (LinkFault::Receive(15), 1, 15),
            (LinkFault::Decode(LinkError::BadCrc), 2, 3),
            (LinkFault::Overflow(2), 3, 2),
            (LinkFault::PeerEstop, 4, 0),
            (LinkFault::InboundTimeout, 5, 0),
            (LinkFault::Handoff(HandoffError::TimedOut), 6, 2007),
            (LinkFault::Unavailable, 7, 0),
            (LinkFault::Quiescence(6), 8, 6),
        ];
        let records = capture_records(|| {
            for (fault, _, _) in faults {
                link_fault(Some(42), fault);
                trusted_stop(AuditSource::ManagedControl);
                link_fault(Some(42), fault);
            }
            CAPTURE.with(|capture| {
                let state = capture.borrow();
                let status = state.as_ref().unwrap().window.status();
                assert_eq!(status.suppressed, faults.len() as u64 * 2);
                let latest = status.latest_stop.unwrap().0;
                assert_eq!(latest.correlation, 42);
                assert_eq!(
                    u32::from_le_bytes(latest.payload[40..44].try_into().unwrap()),
                    8
                );
            });
            // A different explicit cause must remain visible.
            trusted_stop(AuditSource::Operator);
            trusted_stop(AuditSource::ManagedControl);
        });
        assert_eq!(records.len(), faults.len() + 2);
        for (record, (_, reason, detail)) in records.iter().zip(faults) {
            assert_eq!(record.kind, MANAGED_AUDIT_STOP);
            assert_eq!(record.correlation, 42);
            let p = <ManagedAuditStopV1 as zerocopy::FromBytes>::read_from_bytes(&record.payload)
                .unwrap();
            assert_eq!(
                (p.category, p.source, p.flags, p.reason, p.detail),
                (5, 7, 4, reason, detail)
            );
        }
        assert_eq!(records[faults.len() + 1].correlation, 0);
    }

    #[test]
    fn handoff_records_actual_transmission_and_reply_outcomes() {
        use shrike_link::handoff::Handoff;
        use shrike_link::tx::{FrameCompletion, TxState};
        use shrike_link::Msg;
        let mut h = Handoff::new();
        let mut tx = TxState::new();
        let records = capture_records(|| {
            h.offer_after_drain(0, 80).unwrap();
            let frame = h.enqueue(&mut tx, 0).unwrap().unwrap();
            handoff(
                MANAGED_AUDIT_HANDOFF_FRAMED,
                frame.operation,
                frame.message,
                None,
                None,
                None,
            );
            assert_eq!(h.enqueue(&mut tx, 0).unwrap(), None);
            while let Some((_, complete)) = tx.next_byte_with_completion() {
                if let Some(FrameCompletion::Handoff(frame)) = complete {
                    let result = h.sent(0);
                    handoff(
                        MANAGED_AUDIT_HANDOFF_LOCAL_COMPLETE,
                        frame.operation,
                        frame.message,
                        None,
                        None,
                        result.err(),
                    );
                }
            }
            for session in [2, 1] {
                let msg = Msg::SessionReady { session };
                let op = h.operation();
                let result = h.on_reply(msg, 0);
                handoff_reply(op, msg, 0, result);
            }
            let (identity, _) = h.begin_on_transport(42, 255, 0, 80, &mut tx).unwrap();
            handoff(
                MANAGED_AUDIT_BARRIER_BEGIN,
                Some(42),
                identity.message(),
                None,
                None,
                None,
            );
            let frame = h.enqueue(&mut tx, 0).unwrap().unwrap();
            handoff(
                MANAGED_AUDIT_HANDOFF_FRAMED,
                frame.operation,
                frame.message,
                None,
                None,
                None,
            );
            let ack = Msg::SafeAck {
                session: identity.session,
                correlation: identity.correlation,
                sequence: identity.sequence,
            };
            let result = h.on_reply(ack, 0);
            assert_eq!(result, Ok(false)); // Not sent yet.
            handoff_reply(h.operation(), ack, 0, result);
            while let Some((_, complete)) = tx.next_byte_with_completion() {
                if let Some(FrameCompletion::Handoff(frame)) = complete {
                    let result = h.sent(0);
                    handoff(
                        MANAGED_AUDIT_HANDOFF_LOCAL_COMPLETE,
                        frame.operation,
                        frame.message,
                        None,
                        None,
                        result.err(),
                    );
                }
            }
            let result = h.on_reply(ack, 0);
            assert_eq!(result, Ok(true));
            handoff_reply(h.operation(), ack, 0, result);
            let duplicate = h.on_reply(ack, 0);
            assert_eq!(duplicate, Ok(false));
            handoff_reply(h.operation(), ack, 0, duplicate);
            // Timeout clears eligibility; retain the pre-call operation ID.
            let op = h.operation();
            let late = h.on_reply(ack, 80);
            assert!(late.is_err());
            assert_eq!(h.operation(), None);
            handoff_reply(op, ack, 80, late);
            // Heartbeat/sensor traffic must not become acknowledgement records.
            handoff_reply(None, Msg::HeartbeatToPi { seq: 9 }, 80, Ok(false));
        });
        let events: Vec<_> = records
            .iter()
            .map(|r| ManagedAuditHandoffV1::read_from_bytes(&r.payload).unwrap())
            .collect();
        assert_eq!(
            events.iter().map(|p| p.event).collect::<Vec<_>>(),
            [2, 3, 5, 4, 1, 2, 5, 3, 4, 5, 6]
        );
        for (i, p) in events.iter().enumerate() {
            assert_eq!(p.link_kind, MANAGED_AUDIT_HANDOFF_LINK);
            assert_eq!(p.generation, 0);
            assert_eq!(p.reserved, [0; 12]);
            assert_eq!(p.flags, u32::from(i >= 4));
            assert_eq!(records[i].correlation, if i >= 4 { 42 } else { 0 });
            assert_eq!(p.wire_correlation, if i >= 4 { 1 } else { 0 });
            assert_eq!(p.command_sequence, if i >= 4 { 255 } else { 0 });
            assert_eq!(p.error, if i == 10 { 2007 } else { 0 });
        }
        assert_eq!(events[2].session, 2); // Preserve wrong reply, don't relabel it.
        assert_eq!(events[10].observed_ticks, 80);
    }

    #[test]
    fn motor_discard_records_real_removals_and_suppresses_empty_batches() {
        use shrike_link::tx::{MotorDiscards, MotorOrigin, MotorRequest, TxState};
        let request = MotorRequest {
            left: 200,
            right: -300,
            queued_at: 1,
            origin: Some(MotorOrigin {
                cycle: 30,
                generation: 7,
                artifact_handle: 0,
            }),
        };
        let pending = MotorRequest {
            queued_at: 2,
            origin: Some(MotorOrigin {
                cycle: 31,
                generation: 9,
                artifact_handle: 17,
            }),
            ..request
        };
        for reason in 1..=6 {
            let mut tx = TxState::new();
            tx.replace_motor_request(request);
            tx.start_pending_motor(255).unwrap();
            tx.replace_motor_request(pending);
            let discarded = match reason {
                1 => tx.replace_motor_request(request),
                2 => tx.prioritize_motor_request(MotorRequest {
                    left: 0,
                    right: 0,
                    ..request
                }),
                3 => tx.discard_expired_motor(12, 10),
                4 | 5 => {
                    let mut d = tx.clear_motor();
                    d.frame = tx.cancel_unsent().frame;
                    d
                }
                _ => tx.clear_motor(),
            };
            let records = capture_records(|| {
                motor_discard(discarded, reason);
                motor_discard(MotorDiscards::default(), reason);
            });
            assert_eq!(
                records.len(),
                if reason == 1 || reason == 6 { 1 } else { 2 }
            );
            let p = ManagedAuditMotorTxV1::read_from_bytes(&records[0].payload).unwrap();
            assert_eq!(p.event, MANAGED_AUDIT_MOTOR_PENDING_DISCARDED);
            assert_eq!(p.reason, reason);
            assert_eq!(
                (p.cycle_id, p.artifact_handle, records[0].correlation),
                (31, 17, 9)
            );
            assert_eq!(p.command_sequence, 0);
            assert_eq!(p.flags, MANAGED_AUDIT_MOTOR_HAS_ORIGIN);
            if records.len() == 2 {
                let f = ManagedAuditMotorTxV1::read_from_bytes(&records[1].payload).unwrap();
                assert_eq!(f.event, MANAGED_AUDIT_MOTOR_FRAME_DISCARDED);
                assert_eq!(
                    (f.cycle_id, f.artifact_handle, records[1].correlation),
                    (30, 0, 7)
                );
                assert_eq!(f.command_sequence, 255);
                assert_eq!(f.reason, reason);
                assert_eq!(records[0].ticks, records[1].ticks);
            }
        }
    }

    #[test]
    fn motor_tx_records_exact_frame_origin_and_only_local_completion() {
        use shrike_link::tx::{MotorOrigin, MotorRequest, TxState};
        let origin = MotorOrigin {
            cycle: 1 << 40,
            generation: 1 << 41,
            artifact_handle: 0,
        };
        let mut tx = TxState::new();
        let mut expected = Vec::new();
        let records = capture_records(|| {
            for (sequence, pair, tagged) in [
                (255, (200, 200), true),
                (0, (-200, -200), true),
                (1, (0, 0), false),
            ] {
                tx.replace_motor_request(MotorRequest {
                    left: pair.0,
                    right: pair.1,
                    queued_at: u64::MAX - 10,
                    origin: tagged.then_some(origin),
                });
                let frame = tx.start_pending_motor(sequence).unwrap();
                expected.push(frame);
                motor_tx(frame, false);
                // Busy attempts emit nothing; peeking a backpressured byte does
                // not complete a frame. A newer pending owner cannot relabel it.
                tx.replace_motor_request(MotorRequest {
                    left: 100,
                    right: 100,
                    queued_at: 3,
                    origin: Some(MotorOrigin {
                        generation: 99,
                        ..origin
                    }),
                });
                assert_eq!(tx.start_pending_motor(7), None);
                while let Some(byte) = tx.peek_byte() {
                    assert_eq!(tx.peek_byte(), Some(byte));
                    let (accepted, complete) = tx.next_byte_with_motor_completion().unwrap();
                    assert_eq!(accepted, byte);
                    if let Some(complete) = complete {
                        motor_tx(complete, true);
                    }
                }
            }
        });
        assert_eq!(records.len(), 6);
        for (i, frame) in expected.iter().enumerate() {
            let framed = ManagedAuditMotorTxV1::read_from_bytes(&records[2 * i].payload).unwrap();
            let completed =
                ManagedAuditMotorTxV1::read_from_bytes(&records[2 * i + 1].payload).unwrap();
            assert_eq!(records[2 * i].kind, MANAGED_AUDIT_LINK);
            assert_eq!(
                records[2 * i].correlation,
                frame.request.origin.map_or(0, |v| v.generation)
            );
            assert_eq!(records[2 * i + 1].correlation, records[2 * i].correlation);
            assert_eq!(framed.link_kind, MANAGED_AUDIT_MOTOR_TX);
            assert_eq!(framed.event, MANAGED_AUDIT_MOTOR_FRAMED);
            assert_eq!(
                completed,
                ManagedAuditMotorTxV1 {
                    event: MANAGED_AUDIT_MOTOR_LOCAL_COMPLETE,
                    ..framed
                }
            );
            assert_eq!(framed.cycle_id, frame.request.origin.map_or(0, |v| v.cycle));
            assert_eq!(framed.artifact_handle, 0);
            assert_eq!(
                framed.flags,
                u32::from(frame.request.origin.is_some())
                    | (u32::from(frame.intermediate_zero) << 1)
            );
            assert_eq!(
                (framed.left, framed.right),
                (frame.request.left, frame.request.right)
            );
            assert_eq!(framed.command_sequence, u32::from(frame.sequence));
            assert_eq!(framed.queued_at_ns, u64::MAX - 10);
            assert_eq!(framed.reason, 0);
            assert_eq!(framed.reserved, [0; 20]);
        }
        assert!(expected[1].intermediate_zero);
        assert_eq!(
            (expected[1].request.left, expected[1].request.right),
            (0, 0)
        );
    }

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
        state.link_fault(7, 1, 8, 22);
        state.record_cycle(
            release,
            CycleReport {
                failure: None,
                submission: None,
                requested: None,
                ..report
            },
            23,
        );
        state.trusted_stop(AuditSource::ManagedControl, 24);
        let latest = state.window.status().latest_stop.unwrap().0;
        let p = ManagedAuditStopV1::read_from_bytes(&latest.payload).unwrap();
        // An old link cause cannot be attributed to a later execution's stop.
        assert_eq!(
            (p.category, p.reason, p.flags, latest.correlation),
            (1, 0, 0, 0)
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
