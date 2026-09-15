//! Joined host workflow. UART and safe acknowledgements are modeled; no
//! physical FPGA output, userspace copy boundary or qualified timing is claimed.
use kernel_bpf::actuation::{AuditSource, Authority, Monitor};
use kernel_bpf::profile::ActiveProfile;
use kernel_time::periodic::PeriodicRelease;
use shrike_link::handoff::Handoff;
use shrike_link::installer::{Decoder as InstallerDecoder, Frame, FrameKind, DATA_BYTES};
use shrike_link::tx::{FrameCompletion, MotorOrigin, MotorRequest, TxState};
use shrike_link::{Decoder, Msg};
use signed_bpf_loader::{dispatch, Transport, STOP_COMMAND};

use super::*;
use crate::actuation::{MotorPairSubmission, MotorPairSubmissionOutcome};
use crate::bpf::control::SensorSnapshot;
use crate::bpf::recorder::events;

// Only the host syscall boundary is substituted. These callbacks call the real
// manager; authentication, ownership, preparation and publication are unchanged.
fn bpf_call(
    slot: &spin::Mutex<ControlSlot>,
    manager: &spin::Mutex<BpfManager>,
    command: u32,
    body: &mut [u8],
) -> isize {
    let result = (|| -> Result<usize, Errno> {
        let mut slot = slot.lock();
        let mut manager = manager.lock();
        match command {
            BPF_MANAGED_UPLOAD_BEGIN => {
                let r = ManagedUploadBeginV1::read_from_bytes(body).unwrap();
                manager
                    .managed_upload_begin(7, r.expected_last_id, r.total_bytes)
                    .map(|id| id as usize)
            }
            BPF_MANAGED_UPLOAD_CHUNK => {
                let r = ManagedUploadChunkV1::read_from_bytes(body).unwrap();
                manager
                    .managed_upload_chunk(7, r.id, r.offset, &r.bytes[..r.length as usize])
                    .map(|n| n as usize)
            }
            BPF_MANAGED_UPLOAD_FINALIZE => {
                let r = ManagedOperationRequestV1::read_from_bytes(body).unwrap();
                manager
                    .managed_upload_finalize(7, r.id)
                    .map(|id| id as usize)
            }
            BPF_MANAGED_REARM => {
                let r = ManagedRearmRequestV1::read_from_bytes(body).unwrap();
                manager
                    .request_rearm(&mut slot, r.expected_last_id, r.expected_generation, 1)
                    .map(|id| id as usize)
            }
            BPF_MANAGED_ACTIVATE | BPF_MANAGED_ROLLBACK => {
                let r = ManagedInstallationRequestV1::read_from_bytes(body).unwrap();
                let target = if command == BPF_MANAGED_ACTIVATE {
                    LifecycleTarget::Candidate(r.artifact_handle)
                } else {
                    LifecycleTarget::Previous(r.artifact_handle)
                };
                manager
                    .request_installation(
                        &mut slot,
                        r.expected_last_id,
                        r.expected_generation,
                        target,
                    )
                    .map(|id| id as usize)
            }
            BPF_MANAGED_OPERATION_QUERY => {
                let r = ManagedOperationV1::read_from_bytes(body).unwrap();
                body.copy_from_slice(manager.query_installation(&slot, r.id)?.as_bytes());
                Ok(0)
            }
            BPF_MANAGED_SLOT_QUERY => {
                body.copy_from_slice(manager.managed_slot_query(&slot).as_bytes());
                Ok(0)
            }
            _ => Err(ENOTSUP),
        }
    })();
    result.map_or_else(|error| -isize::from(error), |value| value as isize)
}

struct Wire {
    transport: Transport,
    sequence: u32,
}

impl Wire {
    fn exchange(
        &mut self,
        frame: Frame,
        slot: &spin::Mutex<ControlSlot>,
        manager: &spin::Mutex<BpfManager>,
    ) -> Frame {
        for fragment in frame.encode().chunks(5) {
            self.transport.receive(fragment, |request, response| {
                dispatch(
                    request,
                    response,
                    |cmd, body| bpf_call(slot, manager, cmd, body),
                    || {
                        slot.lock().stop();
                        events::trusted_stop(AuditSource::Operator);
                        0
                    },
                )
            });
        }
        let mut decoder = InstallerDecoder::new();
        let mut result = None;
        while let Some(bytes) = self.transport.pending_reply() {
            let count = bytes.len().min(3);
            for byte in &bytes[..count] {
                result = decoder.push(*byte).or(result);
            }
            self.transport.written(count);
        }
        let result = result.expect("one complete bounded reply");
        assert_eq!(result.sequence, frame.sequence);
        result
    }

    fn command(
        &mut self,
        slot: &spin::Mutex<ControlSlot>,
        manager: &spin::Mutex<BpfManager>,
        command: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let mut bytes = command.to_le_bytes().to_vec();
        bytes.extend_from_slice(body);
        let count = bytes.len().div_ceil(DATA_BYTES);
        for (index, bytes) in bytes.chunks(DATA_BYTES).enumerate() {
            let kind = if index + 1 == count {
                FrameKind::RequestLast
            } else {
                FrameKind::Request
            };
            let frame = Frame::new(kind, self.sequence, bytes).unwrap();
            let reply = self.exchange(frame, slot, manager);
            assert_eq!(reply.kind, FrameKind::Ack);
            // A lost final-fragment reply must not run the management request twice.
            if kind == FrameKind::RequestLast {
                assert_eq!(self.exchange(frame, slot, manager), reply);
            }
            self.sequence += 1;
        }
        let mut response = Vec::new();
        loop {
            let frame = Frame::new(FrameKind::Poll, self.sequence, &[]).unwrap();
            let reply = self.exchange(frame, slot, manager);
            assert!(matches!(
                reply.kind,
                FrameKind::Response | FrameKind::ResponseLast
            ));
            response.extend_from_slice(&reply.data[..reply.len as usize]);
            self.sequence += 1;
            if reply.kind == FrameKind::ResponseLast {
                return response;
            }
        }
    }
}

fn value(reply: &[u8]) -> u64 {
    let result = i64::from_le_bytes(reply[..8].try_into().unwrap());
    assert!(result >= 0, "management error {result}");
    result as u64
}

fn operation(
    wire: &mut Wire,
    slot: &spin::Mutex<ControlSlot>,
    manager: &spin::Mutex<BpfManager>,
    id: u64,
) -> ManagedOperationV1 {
    let reply = wire.command(
        slot,
        manager,
        BPF_MANAGED_OPERATION_QUERY as u16,
        ManagedOperationV1 {
            version: 1,
            size: 200,
            id,
            ..Default::default()
        }
        .as_bytes(),
    );
    assert_eq!(value(&reply), 0);
    ManagedOperationV1::read_from_bytes(&reply[8..]).unwrap()
}

fn upload_wire(
    wire: &mut Wire,
    slot: &spin::Mutex<ControlSlot>,
    manager: &spin::Mutex<BpfManager>,
    last: u64,
    bytes: &[u8],
) -> u64 {
    let id = value(
        &wire.command(
            slot,
            manager,
            BPF_MANAGED_UPLOAD_BEGIN as u16,
            ManagedUploadBeginV1 {
                version: 1,
                size: 24,
                expected_last_id: last,
                total_bytes: bytes.len() as u32,
                reserved: 0,
            }
            .as_bytes(),
        ),
    );
    for (index, bytes) in bytes.chunks(MANAGED_UPLOAD_CHUNK_BYTES).enumerate() {
        let mut request = ManagedUploadChunkV1 {
            version: 1,
            size: 288,
            id,
            offset: (index * MANAGED_UPLOAD_CHUNK_BYTES) as u32,
            length: bytes.len() as u32,
            reserved: 0,
            bytes: [0; MANAGED_UPLOAD_CHUNK_BYTES],
        };
        request.bytes[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            value(&wire.command(
                slot,
                manager,
                BPF_MANAGED_UPLOAD_CHUNK as u16,
                request.as_bytes()
            )),
            u64::from(request.offset + request.length)
        );
    }
    assert_eq!(
        value(
            &wire.command(
                slot,
                manager,
                BPF_MANAGED_UPLOAD_FINALIZE as u16,
                ManagedOperationRequestV1 {
                    version: 1,
                    size: 24,
                    id,
                    reserved: 0,
                }
                .as_bytes()
            )
        ),
        id
    );
    id
}

struct HostControl {
    handoff: Handoff,
    tx: TxState,
    sequence: u64,
    motor_sequence: u8,
    monitor: Monitor<ActiveProfile>,
}

impl HostControl {
    fn release(&mut self) -> PeriodicRelease {
        self.sequence += 1;
        let scheduled = 300 + self.sequence * 10;
        PeriodicRelease {
            sequence: self.sequence,
            scheduled,
            actual: scheduled,
            deadline: scheduled + 10,
            missed_before: 0,
            wake_lateness: 0,
        }
    }

    fn drain_tx(&mut self, ticks: u64) -> Vec<Msg> {
        let mut decoder = Decoder::new();
        let mut messages = Vec::new();
        while let Some((byte, completion)) = self.tx.next_byte_with_completion() {
            if let Some(message) = decoder.push(byte) {
                messages.push(message.unwrap());
            }
            match completion {
                Some(FrameCompletion::Handoff(_)) => self.handoff.sent(ticks).unwrap(),
                Some(FrameCompletion::Motor(frame)) => events::motor_tx(frame, true),
                None => {}
            }
        }
        messages
    }

    fn invoke(
        &mut self,
        slot: &spin::Mutex<ControlSlot>,
        release: PeriodicRelease,
        pair: (i16, i16),
    ) {
        let snapshot = slot.lock().snapshot();
        let report = slot.lock().run_release(
            release,
            1000,
            SensorSnapshot::received(release.actual, 500, 0, false),
            80_000_000,
            &mut || release.actual + 1,
            |requested, _, _, _| {
                let decision = self.monitor.decide_motor_pair(
                    i32::from(requested.left),
                    i32::from(requested.right),
                    Authority::Learned,
                    AuditSource::LearnedBehavior,
                    release.actual * 1_000_000,
                );
                let (left, right, _) = decision.apply();
                self.tx.replace_motor_request(MotorRequest {
                    left,
                    right,
                    queued_at: release.actual * 1_000_000,
                    origin: Some(MotorOrigin {
                        cycle: release.sequence,
                        generation: snapshot.generation,
                        artifact_handle: snapshot.active.unwrap(),
                    }),
                });
                self.motor_sequence = self.motor_sequence.checked_add(1).unwrap();
                let frame = self.tx.start_pending_motor(self.motor_sequence).unwrap();
                events::motor_tx(frame, false);
                MotorPairSubmission {
                    decision: Some(decision),
                    outcome: MotorPairSubmissionOutcome::Queued,
                }
            },
        );
        assert!(report.invocation_completed);
        assert_eq!(report.failure, None);
        assert_eq!(report.requested.map(|p| (p.left, p.right)), Some(pair));
        assert_eq!(report.generation, snapshot.generation);
        events::cycle(release, report);
        let messages = self.drain_tx(release.actual + 2);
        assert_eq!(
            messages,
            alloc::vec![Msg::MotorSetpoint {
                left: pair.0,
                right: pair.1,
                seq: self.motor_sequence
            }]
        );
    }

    fn cycle(&mut self, slot: &spin::Mutex<ControlSlot>, pair: (i16, i16)) {
        let release = self.release();
        self.invoke(slot, release, pair);
    }

    fn publish(&mut self, slot: &spin::Mutex<ControlSlot>, generation: u64, pair: (i16, i16)) {
        let release = self.release();
        assert_eq!(
            slot.lock().handoff_boundary(
                release,
                1000,
                &mut self.handoff,
                &mut self.tx,
                &mut self.motor_sequence,
                release.actual * 1_000_000
            ),
            Ok(None)
        );
        let report = slot.lock().run_release(
            release,
            1000,
            SensorSnapshot::default(),
            80_000_000,
            &mut || release.actual,
            |_, _, _, _| panic!("controller must not submit during safe handoff"),
        );
        assert!(report.safe_mode && report.handoff);
        assert_eq!(report.failure, None);
        events::cycle(release, report);
        self.handoff
            .enqueue(&mut self.tx, release.actual * 1_000_000)
            .unwrap();
        let messages = self.drain_tx(release.actual + 1);
        let [Msg::SafeBarrier {
            session,
            correlation,
            sequence,
        }] = messages.as_slice()
        else {
            panic!("one complete barrier");
        };
        // Only a protocol model acknowledgement: no FPGA output observation.
        assert!(self
            .handoff
            .on_reply(
                Msg::SafeAck {
                    session: *session,
                    correlation: *correlation,
                    sequence: *sequence
                },
                release.actual + 2
            )
            .is_ok());
        let release = self.release();
        assert_eq!(
            slot.lock().handoff_boundary(
                release,
                1000,
                &mut self.handoff,
                &mut self.tx,
                &mut self.motor_sequence,
                release.actual * 1_000_000
            ),
            Ok(Some(generation))
        );
        self.invoke(slot, release, pair);
    }
}

#[test]
fn framed_installer_upload_replace_fresh_rollback_and_stop_produce_one_joined_audit() {
    let (mut worker, slot, manager) = fixture_worker();
    let mut wire = Wire {
        transport: Transport::new(),
        sequence: 2,
    };
    let reset = Frame::new(FrameKind::Reset, 1, b"hosttest").unwrap();
    assert_eq!(wire.exchange(reset, &slot, &manager).kind, FrameKind::Ack);
    let mut artifacts = Vec::new();
    let mut lifecycle_ids = Vec::new();
    let records = events::tests::capture_records(|| {
        let rearm = value(
            &wire.command(
                &slot,
                &manager,
                BPF_MANAGED_REARM as u16,
                ManagedRearmRequestV1 {
                    version: 1,
                    size: 32,
                    expected_last_id: 0,
                    expected_generation: 0,
                    reserved: 0,
                }
                .as_bytes(),
            ),
        );
        assert_eq!(rearm, 1);
        let (mut handoff, receipt) = rearm_ready_fixture(rearm);
        let mut monitor = Monitor::<ActiveProfile>::new();
        monitor.estop_trigger(AuditSource::Operator, 0);
        manager
            .lock()
            .validate_rearm(&slot.lock(), rearm, monitor.latch_epoch())
            .unwrap();
        handoff.commit_rearm(&receipt, 208).unwrap();
        assert!(monitor.operator_rearm_if_unchanged(1, 208_000_000));
        manager
            .lock()
            .finish_rearm(&mut slot.lock(), rearm, Ok(()))
            .unwrap();
        assert!(slot.lock().snapshot().inhibited);
        let mut control = HostControl {
            handoff,
            tx: TxState::new(),
            sequence: 0,
            motor_sequence: 0,
            monitor,
        };
        let manifest = |revision| Manifest {
            behavior_id: [9; 16],
            revision,
            envelope: true,
            effects: EFFECT_MOTOR_PAIR,
            private_array: Some(PrivateArray {
                value_size: 8,
                max_entries: 1,
            }),
        };
        let program_a = crate::bpf::managed::tests::stateful_managed_program();
        let bytes_a = signed_manifest(manifest(1), &program_a).0;
        let upload_a = upload_wire(&mut wire, &slot, &manager, rearm, &bytes_a);
        assert!(service_worker(&mut worker, &slot, &manager));
        let a = operation(&mut wire, &slot, &manager, upload_a);
        assert_eq!(a.phase, MANAGED_OPERATION_RESIDENT);
        artifacts.push((upload_a, a));
        let activate_a = value(
            &wire.command(
                &slot,
                &manager,
                BPF_MANAGED_ACTIVATE as u16,
                ManagedInstallationRequestV1 {
                    version: 1,
                    size: 32,
                    expected_last_id: upload_a,
                    expected_generation: 0,
                    artifact_handle: a.artifact_handle,
                    reserved: 0,
                }
                .as_bytes(),
            ),
        );
        lifecycle_ids.push(activate_a);
        assert!(service_worker(&mut worker, &slot, &manager));
        control.publish(&slot, 1, (0, 0));
        assert!(service_worker(&mut worker, &slot, &manager));

        // B arrives only after A executes. Authentication failure must preserve A.
        let mut program_b = program_a.clone();
        let index = program_b.len() - 4;
        program_b[index] = BpfInsn::mov64_imm(2, 3);
        let bytes_b = signed_manifest(manifest(2), &program_b).0;
        let mut tampered = bytes_b.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let rejected = upload_wire(&mut wire, &slot, &manager, activate_a, &tampered);
        let before = slot.lock().snapshot();
        assert!(service_worker(&mut worker, &slot, &manager));
        let rejection = operation(&mut wire, &slot, &manager, rejected);
        assert_eq!(
            (rejection.phase, rejection.error),
            (MANAGED_OPERATION_FAILED, i32::from(EACCES) as u32)
        );
        assert_eq!(slot.lock().snapshot(), before);
        control.cycle(&slot, (1, 1));
        let upload_b = upload_wire(&mut wire, &slot, &manager, rejected, &bytes_b);
        assert!(service_worker(&mut worker, &slot, &manager));
        let b = operation(&mut wire, &slot, &manager, upload_b);
        assert_eq!(b.phase, MANAGED_OPERATION_RESIDENT);
        assert_ne!(a.bundle_digest, b.bundle_digest);
        assert_ne!(a.payload_digest, b.payload_digest);
        artifacts.push((upload_b, b));
        control.cycle(&slot, (2, 2));
        let activate_b = value(
            &wire.command(
                &slot,
                &manager,
                BPF_MANAGED_ACTIVATE as u16,
                ManagedInstallationRequestV1 {
                    version: 1,
                    size: 32,
                    expected_last_id: upload_b,
                    expected_generation: 1,
                    artifact_handle: b.artifact_handle,
                    reserved: 0,
                }
                .as_bytes(),
            ),
        );
        lifecycle_ids.push(activate_b);
        assert!(service_worker(&mut worker, &slot, &manager));
        control.publish(&slot, 2, (0, 3));
        assert!(service_worker(&mut worker, &slot, &manager));
        control.cycle(&slot, (1, 3));
        assert_eq!(slot.lock().snapshot().previous, Some(a.artifact_handle));
        let rollback = value(
            &wire.command(
                &slot,
                &manager,
                BPF_MANAGED_ROLLBACK as u16,
                ManagedInstallationRequestV1 {
                    version: 1,
                    size: 32,
                    expected_last_id: activate_b,
                    expected_generation: 2,
                    artifact_handle: a.artifact_handle,
                    reserved: 0,
                }
                .as_bytes(),
            ),
        );
        lifecycle_ids.push(rollback);
        assert!(service_worker(&mut worker, &slot, &manager));
        control.publish(&slot, 3, (0, 0));
        assert!(service_worker(&mut worker, &slot, &manager));
        control.cycle(&slot, (1, 1));
        let receipt = operation(&mut wire, &slot, &manager, rollback);
        assert_eq!(receipt.phase, MANAGED_OPERATION_COMMITTED);
        assert_eq!(receipt.bundle_digest, a.bundle_digest);
        assert_eq!(value(&wire.command(&slot, &manager, STOP_COMMAND, &[])), 0);
        let reply = wire.command(
            &slot,
            &manager,
            BPF_MANAGED_SLOT_QUERY as u16,
            ManagedSlotV1 {
                version: 1,
                size: 64,
                ..Default::default()
            }
            .as_bytes(),
        );
        let stopped = ManagedSlotV1::read_from_bytes(&reply[8..]).unwrap();
        assert_eq!(
            (
                stopped.generation,
                stopped.active_artifact,
                stopped.previous_artifact
            ),
            (3, a.artifact_handle, b.artifact_handle)
        );
        assert_ne!(stopped.flags & MANAGED_SLOT_INHIBITED, 0);
    });
    for (id, identity) in artifacts {
        let mut bytes = Vec::new();
        for record in records
            .iter()
            .filter(|r| r.kind == MANAGED_AUDIT_ARTIFACT && r.correlation == id)
        {
            let fragment =
                ManagedAuditIdentityFragmentV1::read_from_bytes(&record.payload).unwrap();
            assert_eq!(fragment.index as usize, bytes.len() / 56);
            assert_eq!(fragment.artifact_handle, identity.artifact_handle);
            bytes.extend_from_slice(&fragment.data);
        }
        assert_eq!(bytes.len(), 224);
        assert_eq!(&bytes[160..192], &identity.bundle_digest);
        assert_eq!(&bytes[192..224], &identity.signer_fingerprint);
    }
    let cycles: Vec<_> = records
        .iter()
        .filter(|r| r.kind == MANAGED_AUDIT_CYCLE)
        .map(|r| {
            (
                r.correlation,
                ManagedAuditCycleV1::read_from_bytes(&r.payload).unwrap(),
            )
        })
        .collect();
    let requests: Vec<_> = cycles
        .iter()
        .filter(|(_, c)| c.flags & MANAGED_AUDIT_CYCLE_HAS_REQUEST != 0)
        .map(|(generation, c)| (*generation, c.requested_left, c.requested_right))
        .collect();
    assert_eq!(
        requests,
        alloc::vec![
            (1, 0, 0),
            (1, 1, 1),
            (1, 2, 2),
            (2, 0, 3),
            (2, 1, 3),
            (3, 0, 0),
            (3, 1, 1)
        ]
    );
    assert_eq!(
        cycles
            .iter()
            .filter(|(_, c)| c.flags & MANAGED_AUDIT_CYCLE_HANDOFF != 0)
            .count(),
        3
    );
    for (index, id) in lifecycle_ids.into_iter().enumerate() {
        assert!(records
            .iter()
            .filter(|r| r.kind == MANAGED_AUDIT_OPERATION && r.correlation == id)
            .any(|r| {
                let p = ManagedAuditLifecycleV1::read_from_bytes(&r.payload).unwrap();
                p.operation_kind == MANAGED_AUDIT_LIFECYCLE
                    && p.phase == MANAGED_OPERATION_COMMITTED
                    && p.observed_generation == index as u64 + 1
            }));
    }
    assert!(records.iter().any(|r| r.kind == MANAGED_AUDIT_STOP));
}
