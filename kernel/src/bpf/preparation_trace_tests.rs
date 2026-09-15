//! Independent host trace from real lifecycle/scheduler results. Ticks and UART
//! acknowledgements are modeled, not physical measurements or recorder output.
extern crate std;

use alloc::format;
use alloc::string::String;
use std::io::Write;

use kernel_time::periodic::{PeriodicRelease, PeriodicSchedule};
use shrike_link::handoff::{Handoff, HandoffError};
use shrike_link::tx::{FrameCompletion, TxState};
use shrike_link::{Decoder, Msg};

use super::*;
use crate::actuation::{MotorPairSubmission, MotorPairSubmissionOutcome};
use crate::bpf::control::SensorSnapshot;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Operation IDs here identify benchmark attempts, including rejected calls
// which deliberately have no kernel operation ID. Accepted attempts below are
// paired with actual returned manager IDs and queried receipts.
struct Trace {
    seq: u64,
    ticks: u64,
    enabled: bool,
}

impl Trace {
    fn event(&mut self, kind: &str, ticks: u64, fields: String) {
        assert!(ticks >= self.ticks);
        self.ticks = ticks;
        self.seq += 1;
        if self.enabled {
            std::println!(
                "V05_TRACE {{\"type\":\"{kind}\",\"seq\":{},\"ticks\":{ticks},{fields}}}",
                self.seq
            );
        }
    }

    fn stage(&mut self, kind: &str, ticks: u64, attempt: u64, generation: u64, digest: &str) {
        self.event(kind, ticks, format!("\"operation_id\":{attempt},\"generation\":{generation},\"artifact_id\":\"{digest}\""));
    }

    fn request(&mut self, operation: &str, attempt: u64, generation: u64, digest: &str) {
        self.event("operation_request", self.ticks, format!("\"operation_id\":{attempt},\"operation\":\"{operation}\",\"generation\":{generation},\"artifact_id\":\"{digest}\""));
    }

    fn response(&mut self, attempt: u64, outcome: &str) {
        self.event(
            "operation_response",
            self.ticks,
            format!("\"operation_id\":{attempt},\"outcome\":\"{outcome}\""),
        );
    }

    fn terminal(&self) {
        if self.enabled {
            std::println!("V05_TRACE {{\"type\":\"terminal\",\"seq\":{},\"ticks\":{},\"event_count\":{},\"last_event_seq\":{}}}", self.seq + 1, self.ticks, self.seq, self.seq);
        }
    }
}

struct Control {
    schedule: PeriodicSchedule,
    handoff: Handoff,
    tx: TxState,
    motor_sequence: u8,
}

impl Control {
    fn next(&mut self, delay: u64) -> PeriodicRelease {
        let now = self.schedule.next_deadline() + delay;
        let release = self.schedule.release(now).unwrap().unwrap();
        assert_eq!(
            self.schedule.release(now).unwrap(),
            None,
            "no catch-up burst"
        );
        release
    }

    fn boundary(
        &mut self,
        slot: &spin::Mutex<ControlSlot>,
        release: PeriodicRelease,
    ) -> Result<Option<u64>, HandoffError> {
        slot.lock().handoff_boundary(
            release,
            1000,
            &mut self.handoff,
            &mut self.tx,
            &mut self.motor_sequence,
            release.actual * 1_000_000,
        )
    }

    fn invoke(
        &mut self,
        trace: &mut Trace,
        slot: &spin::Mutex<ControlSlot>,
        release: PeriodicRelease,
        digest: &str,
        commit: Option<u64>,
    ) {
        let snapshot = slot.lock().snapshot();
        let mode = if snapshot.inhibited {
            "safe"
        } else {
            "controller"
        };
        trace.event(
            "cycle_release",
            release.actual,
            format!(
                "\"cycle\":{},\"scheduled_ticks\":{},\"mode\":\"{mode}\",\"generation\":{}",
                release.sequence, release.scheduled, snapshot.generation
            ),
        );
        if let Some(attempt) = commit {
            trace.event("operation_committed", release.actual, format!("\"operation_id\":{attempt},\"cycle\":{},\"generation\":{},\"artifact_id\":\"{digest}\"", release.sequence, snapshot.generation));
        }
        let mut reads = 0;
        let report = slot.lock().run_release(
            release,
            1000,
            SensorSnapshot::default(),
            80_000_000,
            &mut || {
                reads += 1;
                let ticks = release.actual + reads;
                // These are the actual before/after interpreter callbacks, not
                // timestamps recovered later from recorder summaries.
                if reads <= 2 {
                    trace.event(
                        if reads == 1 {
                            "behavior_enter"
                        } else {
                            "behavior_exit"
                        },
                        ticks,
                        format!(
                            "\"cycle\":{},\"generation\":{},\"artifact_id\":\"{digest}\"",
                            release.sequence, snapshot.generation
                        ),
                    );
                }
                ticks
            },
            |pair, _, _, _| {
                assert_eq!((pair.left, pair.right), (0, 0));
                MotorPairSubmission {
                    decision: None,
                    outcome: MotorPairSubmissionOutcome::Queued,
                }
            },
        );
        assert_eq!(report.failure, None);
        assert_eq!(report.invocation_completed, mode == "controller");
        assert_eq!(reads, if mode == "controller" { 3 } else { 0 });
        trace.event(
            "cycle_complete",
            release.actual + reads,
            format!(
                "\"cycle\":{},\"mode\":\"{mode}\",\"generation\":{}",
                release.sequence, report.generation
            ),
        );
    }

    fn cycle(&mut self, trace: &mut Trace, slot: &spin::Mutex<ControlSlot>, digest: &str) {
        let release = self.next(0);
        assert_eq!(self.boundary(slot, release), Ok(None));
        self.invoke(trace, slot, release, digest, None);
    }

    fn begin(
        &mut self,
        trace: &mut Trace,
        slot: &spin::Mutex<ControlSlot>,
        attempt: u64,
        generation: u64,
        old_digest: &str,
        digest: &str,
    ) -> (PeriodicRelease, Msg) {
        let release = self.next(0);
        assert_eq!(self.boundary(slot, release), Ok(None));
        assert!(slot.lock().snapshot().inhibited);
        trace.stage("handoff_enter", release.actual, attempt, generation, digest);
        self.invoke(trace, slot, release, old_digest, None);
        self.handoff
            .enqueue(&mut self.tx, release.actual * 1_000_000)
            .unwrap();
        let mut decoder = Decoder::new();
        let mut message = None;
        while let Some((byte, completion)) = self.tx.next_byte_with_completion() {
            if let Some(result) = decoder.push(byte) {
                assert!(message.is_none());
                message = Some(result.unwrap());
            }
            if matches!(completion, Some(FrameCompletion::Handoff(_))) {
                self.handoff.sent(release.actual + 1).unwrap();
            }
        }
        (release, message.unwrap())
    }

    fn publish(
        &mut self,
        trace: &mut Trace,
        slot: &spin::Mutex<ControlSlot>,
        attempt: u64,
        generation: u64,
        old_digest: &str,
        digest: &str,
    ) {
        let (release, barrier) = self.begin(trace, slot, attempt, generation, old_digest, digest);
        let Msg::SafeBarrier {
            session,
            correlation,
            sequence,
        } = barrier
        else {
            panic!("complete barrier")
        };
        self.handoff
            .on_reply(
                Msg::SafeAck {
                    session,
                    correlation,
                    sequence,
                },
                release.actual + 2,
            )
            .unwrap();
        trace.stage(
            "sink_safe_ready",
            release.actual + 2,
            attempt,
            generation,
            digest,
        );
        let release = self.next(0);
        assert_eq!(self.boundary(slot, release), Ok(Some(generation)));
        self.invoke(trace, slot, release, digest, Some(attempt));
    }
}

fn retain_bundle(name: &str, bytes: &[u8]) {
    if let Ok(directory) = std::env::var("AXIOM_V05_TRACE_ARTIFACT_DIR") {
        let path = std::path::Path::new(&directory).join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }
}

#[test]
fn managed_host_benchmark_trace() {
    let (mut worker, slot, manager) = fixture_worker();
    let program = [BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
    let bytes_a = signed_bundle(1, &program).0;
    retain_bundle("a.bundle", &bytes_a);
    let (upload_a, a) = resident_via_worker(&mut worker, &slot, &manager, 0, 1);
    let digest_a = hex(&manager
        .lock()
        .managed_operation_query(upload_a)
        .unwrap()
        .bundle_digest);
    let active = manager
        .lock()
        .request_installation(&mut slot.lock(), upload_a, 0, a)
        .unwrap();
    assert!(service_worker(&mut worker, &slot, &manager));
    host_commit(&slot);
    assert!(service_worker(&mut worker, &slot, &manager));
    // Seed A's private state, then release the lease before replacement. The
    // retained previous artifact must not preserve this value on rollback.
    {
        let manager = manager.lock();
        let map = manager
            .maps
            .iter()
            .flatten()
            .find(|map| map.owner == super::super::super::ObjectOwner::KernelManaged)
            .unwrap();
        let _lease = map.runtime.try_lease().unwrap();
        map.runtime
            .map
            .update(&0u32.to_ne_bytes(), &42u64.to_ne_bytes(), 0)
            .unwrap();
    }
    let (mut handoff, receipt) = rearm_ready_fixture(41);
    handoff.commit_rearm(&receipt, 206).unwrap();
    let mut control = Control {
        schedule: PeriodicSchedule::new(300, 10).unwrap(),
        handoff,
        tx: TxState::new(),
        motor_sequence: 0,
    };
    let scenario = std::env::var("AXIOM_V05_TRACE_SCENARIO").unwrap_or_else(|_| "normal".into());
    assert!(scenario == "normal" || scenario == "legacy-stall");
    let source = std::env::var("AXIOM_V05_TRACE_SOURCE").unwrap_or_else(|_| "0".repeat(40));
    let config = std::env::var("AXIOM_V05_TRACE_CONFIG").unwrap_or_else(|_| "0".repeat(64));
    assert!(
        source.len() == 40
            && source
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert!(
        config.len() == 64
            && config
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let mut trace = Trace {
        seq: 0,
        ticks: 300,
        enabled: std::env::var_os("AXIOM_V05_TRACE_SOURCE").is_some(),
    };
    if trace.enabled {
        std::println!("V05_TRACE {{\"type\":\"header\",\"schema\":\"axiomos.v05.trace.v1\",\"evidence_kind\":\"synthetic\",\"boot_id\":\"{scenario}\",\"clock_hz\":1000,\"source_id\":\"{source}\",\"artifact_id\":\"{digest_a}\",\"acceptance_config_sha256\":\"{config}\"}}");
    }
    control.cycle(&mut trace, &slot, &digest_a);
    let bytes_b = signed_bundle(2, &program).0;
    retain_bundle("b.bundle", &bytes_b);
    let (upload_b, b) = resident_via_worker(&mut worker, &slot, &manager, active, 2);
    let digest_b = hex(&manager
        .lock()
        .managed_operation_query(upload_b)
        .unwrap()
        .bundle_digest);
    assert_ne!(digest_a, digest_b);
    trace.request("activate", 1, 2, &digest_b);
    let replace = manager
        .lock()
        .request_installation(&mut slot.lock(), upload_b, 1, b)
        .unwrap();
    trace.stage("operation_accepted", trace.ticks, 1, 2, &digest_b);
    // Deliberately withhold the preparation worker for two actual releases.
    control.cycle(&mut trace, &slot, &digest_a);
    control.cycle(&mut trace, &slot, &digest_a);
    assert_eq!(slot.lock().snapshot().generation, 1);
    assert!(service_worker(&mut worker, &slot, &manager));
    control.publish(&mut trace, &slot, 1, 2, &digest_a, &digest_b);
    assert!(service_worker(&mut worker, &slot, &manager));
    assert_eq!(
        manager
            .lock()
            .managed_operation_query(replace)
            .unwrap()
            .phase,
        MANAGED_OPERATION_COMMITTED
    );
    trace.response(1, "successful");
    trace.request("rollback", 2, 3, &digest_a);
    let rollback = manager
        .lock()
        .request_installation(
            &mut slot.lock(),
            replace,
            2,
            LifecycleTarget::Previous(a.handle()),
        )
        .unwrap();
    trace.stage("operation_accepted", trace.ticks, 2, 3, &digest_a);
    assert!(service_worker(&mut worker, &slot, &manager));
    control.publish(&mut trace, &slot, 2, 3, &digest_b, &digest_a);
    assert!(service_worker(&mut worker, &slot, &manager));
    let receipt = manager.lock().managed_operation_query(rollback).unwrap();
    assert_eq!(receipt.phase, MANAGED_OPERATION_COMMITTED);
    assert_eq!(hex(&receipt.bundle_digest), digest_a);
    {
        let manager = manager.lock();
        let map = manager
            .maps
            .iter()
            .flatten()
            .find(|map| map.owner == super::super::super::ObjectOwner::KernelManaged)
            .unwrap();
        let _lease = map.runtime.try_lease().unwrap();
        assert_eq!(
            map.runtime.map.lookup(&0u32.to_ne_bytes()).unwrap(),
            0u64.to_ne_bytes()
        );
    }
    trace.response(2, "successful");
    if scenario == "legacy-stall" {
        // Model a non-preemptible syscall occupying three release periods.
        let release = control.next(30);
        assert_eq!((release.sequence, release.missed_before), (11, 3));
        assert_eq!(
            control.boundary(&slot, release),
            Err(HandoffError::InvalidRelease)
        );
        assert!(slot.lock().snapshot().inhibited);
        control.invoke(&mut trace, &slot, release, &digest_a, None);
        assert_eq!(
            (
                control.schedule.stats().serviced,
                control.schedule.stats().missed
            ),
            (8, 3)
        );
        assert_eq!(trace.seq, 38);
        trace.terminal();
        return;
    }
    trace.request("rollback", 3, 99, &digest_b);
    assert_eq!(
        manager.lock().request_installation(
            &mut slot.lock(),
            rollback,
            98,
            LifecycleTarget::Previous(b.handle())
        ),
        Err(ESTALE)
    );
    trace.response(3, "rejected");
    trace.request("rollback", 4, 4, &digest_b);
    let failed = manager
        .lock()
        .request_installation(
            &mut slot.lock(),
            rollback,
            3,
            LifecycleTarget::Previous(b.handle()),
        )
        .unwrap();
    trace.stage("operation_accepted", trace.ticks, 4, 4, &digest_b);
    assert!(service_worker(&mut worker, &slot, &manager));
    let (started, barrier) = control.begin(&mut trace, &slot, 4, 4, &digest_a, &digest_b);
    assert!(matches!(barrier, Msg::SafeBarrier { .. }));
    // Withhold the acknowledgement while servicing every safe release.
    for _ in 0..7 {
        control.cycle(&mut trace, &slot, &digest_a);
    }
    let release = control.next(0);
    assert_eq!(release.actual - started.actual, 80);
    assert_eq!(
        control.boundary(&slot, release),
        Err(HandoffError::TimedOut)
    );
    assert!(slot.lock().snapshot().inhibited);
    control.invoke(&mut trace, &slot, release, &digest_a, None);
    assert!(service_worker(&mut worker, &slot, &manager));
    let receipt = manager.lock().managed_operation_query(failed).unwrap();
    assert_eq!(receipt.phase, MANAGED_OPERATION_FAILED);
    assert_eq!(receipt.error, i32::from(ETIMEDEOUT) as u32);
    trace.response(4, "failed");
    assert_eq!(
        (
            control.schedule.stats().serviced,
            control.schedule.stats().missed
        ),
        (16, 0)
    );
    assert_eq!(slot.lock().snapshot().generation, 3);
    assert_eq!(trace.seq, 60);
    trace.terminal();
}
