use kernel_bpf::actuation::{AuditRecord, MotorPairState};

use super::*;

const NOW_NS: u64 = 1_000_000;
const DEADLINE: u64 = 100;
const MANAGED: MotorPairCaller = MotorPairCaller::Managed {
    not_before_ticks: 1,
    deadline_ticks: DEADLINE,
};

#[test]
fn ownership_rejects_before_monitor_clock_or_queue_even_with_managed_source() {
    let monitor = Mutex::new(Monitor::<ActiveProfile>::new());
    let before = monitor.lock().snapshot_motor_pair_state();
    for (owned, caller) in [
        (
            true,
            MotorPairCaller::Ordinary(Authority::Learned, AuditSource::LearnedBehavior),
        ),
        (
            true,
            MotorPairCaller::Ordinary(Authority::Safety, AuditSource::ManagedControl),
        ),
        (false, MANAGED),
    ] {
        let result = decide_and_queue_motor_pair(
            &monitor,
            owned,
            (700, -700),
            caller,
            || panic!("rejected request read policy clock"),
            || panic!("rejected request read deadline clock"),
            |_| panic!("rejected request reached queue"),
        );
        assert_eq!(
            result,
            MotorPairSubmission {
                decision: None,
                outcome: MotorPairSubmissionOutcome::OwnershipRejected,
            }
        );
    }
    let monitor = monitor.lock();
    assert_eq!(monitor.snapshot_motor_pair_state(), before);
    assert_eq!(monitor.audit_snapshot(&mut [AuditRecord::EMPTY; 4]), 0);
}

#[test]
fn managed_clamp_is_distinct_from_queue_acceptance_and_preserves_attribution() {
    #[cfg(feature = "embedded-profile")]
    const LIMITED: i16 = 200;
    #[cfg(not(feature = "embedded-profile"))]
    const LIMITED: i16 = 800;
    let monitor = Mutex::new(Monitor::<ActiveProfile>::new());
    let mut queued = None;
    let mut clock_reads = 0;
    let result = decide_and_queue_motor_pair(
        &monitor,
        true,
        (1000, -1000),
        MANAGED,
        || NOW_NS,
        || {
            clock_reads += 1;
            clock_reads
        },
        |decision| {
            assert!(
                monitor.try_lock().is_some(),
                "queue must not nest under monitor lock"
            );
            assert!(
                queued.replace(decision).is_none(),
                "only one complete pair is queued"
            );
            true
        },
    );
    assert_eq!(clock_reads, 2);
    assert_eq!(
        result.decision,
        Some(MotorPairDecision::Clamp {
            left: LIMITED,
            right: -LIMITED
        })
    );
    assert_eq!(queued, result.decision);
    assert_eq!(result.outcome, MotorPairSubmissionOutcome::Queued);
    let monitor = monitor.lock();
    assert_eq!(monitor.snapshot_motor_pair_state().left, LIMITED);
    let mut audit = [AuditRecord::EMPTY; 4];
    assert_eq!(monitor.audit_snapshot(&mut audit), 2);
    assert!(audit[..2]
        .iter()
        .all(|r| r.source == AuditSource::ManagedControl && r.authority == Authority::Learned));
}

#[test]
fn managed_deadline_and_reversed_clock_never_enqueue_or_consume_slew_credit() {
    for (ticks, outcome, decided) in [
        ([0, 1], MotorPairSubmissionOutcome::ClockReversed, false),
        (
            [DEADLINE, DEADLINE],
            MotorPairSubmissionOutcome::DeadlineExpired,
            false,
        ),
        (
            [1, DEADLINE],
            MotorPairSubmissionOutcome::DeadlineExpired,
            true,
        ),
        ([2, 1], MotorPairSubmissionOutcome::ClockReversed, true),
    ] {
        let monitor = Mutex::new(Monitor::<ActiveProfile>::new());
        let before = monitor.lock().snapshot_motor_pair_state();
        let mut samples = ticks.into_iter();
        let result = decide_and_queue_motor_pair(
            &monitor,
            true,
            (100, -100),
            MANAGED,
            || NOW_NS,
            || samples.next().expect("at most two physical clock reads"),
            |_| panic!("expired or reversed clock reached queue"),
        );
        assert_eq!(result.outcome, outcome);
        assert_eq!(result.decision.is_some(), decided);
        let monitor = monitor.lock();
        assert_eq!(monitor.snapshot_motor_pair_state(), before);
        assert_eq!(
            monitor.audit_snapshot(&mut [AuditRecord::EMPTY; 4]),
            if decided { 2 } else { 0 }
        );
    }
}

#[test]
fn failed_queue_restores_managed_allow_clamp_and_safe_pair_state() {
    for (request, latched) in [
        ((100, -100), false),
        ((1000, -1000), false),
        ((100, -100), true),
    ] {
        let monitor = Mutex::new(Monitor::<ActiveProfile>::new());
        if latched {
            monitor
                .lock()
                .estop_trigger(AuditSource::Watchdog, NOW_NS - 1);
        }
        let before = monitor.lock().snapshot_motor_pair_state();
        let mut queued = None;
        let result = decide_and_queue_motor_pair(
            &monitor,
            true,
            request,
            MANAGED,
            || NOW_NS,
            || 1,
            |decision| {
                queued = Some(decision);
                false
            },
        );
        assert_eq!(result.outcome, MotorPairSubmissionOutcome::QueueFailed);
        assert_eq!(result.decision, queued);
        assert_eq!(monitor.lock().snapshot_motor_pair_state(), before);
        assert_eq!(monitor.lock().is_latched(), latched);
        assert!(matches!(result.decision, Some(MotorPairDecision::Safe { .. })) == latched);
    }
}

#[test]
fn ordinary_path_keeps_signed_input_queue_rollback_and_safe_semantics() {
    let monitor = Mutex::new(Monitor::<ActiveProfile>::new());
    let ordinary = MotorPairCaller::Ordinary(Authority::Learned, AuditSource::LearnedBehavior);
    let before = monitor.lock().snapshot_motor_pair_state();
    let failed = decide_and_queue_motor_pair(
        &monitor,
        false,
        (i32::MAX, i32::MIN),
        ordinary,
        || NOW_NS,
        || panic!("ordinary request read managed clock"),
        |decision| {
            let (left, right, code) = decision.apply();
            assert!(left > 0 && right < 0 && code == 0);
            false
        },
    );
    assert_eq!(failed.outcome, MotorPairSubmissionOutcome::QueueFailed);
    assert_eq!(monitor.lock().snapshot_motor_pair_state(), before);
    monitor.lock().estop_trigger(AuditSource::Watchdog, NOW_NS);
    let safe = decide_and_queue_motor_pair(
        &monitor,
        false,
        (100, 100),
        ordinary,
        || NOW_NS + 1,
        || panic!("ordinary request read managed clock"),
        |decision| {
            assert_eq!(decision, MotorPairDecision::Safe { left: 0, right: 0 });
            false
        },
    );
    assert_eq!(safe.outcome, MotorPairSubmissionOutcome::QueueFailed);
    assert_eq!(
        monitor.lock().snapshot_motor_pair_state(),
        MotorPairState {
            left: 0,
            right: 0,
            last_update_ns: NOW_NS + 1
        }
    );
}

// This is the sole test that mutates global actuator ownership/output state;
// decision tests use their own monitor. Restore it before returning.
#[test]
fn private_entry_requires_owner_legacy_cannot_claim_it_and_trusted_stop_remains_available() {
    let saved = core::mem::replace(&mut *ACTUATION_MONITOR.lock(), Monitor::new());
    let saved_owner = managed_motor_pair_owned();
    set_managed_motor_pair_owner(false);
    let pair = ManagedMotorPair {
        left: 100,
        right: -100,
    };
    assert_eq!(
        submit_managed_motor_pair(pair, NOW_NS, 1, DEADLINE, || panic!(
            "unowned entry read clock"
        ))
        .outcome,
        MotorPairSubmissionOutcome::OwnershipRejected
    );
    set_managed_motor_pair_owner(true);
    assert!(managed_motor_pair_owned());
    assert_eq!(
        guard_motor_pair_with(100, -100, Authority::Learned, AuditSource::ManagedControl),
        -1
    );
    assert_eq!(
        ACTUATION_MONITOR
            .lock()
            .audit_snapshot(&mut [AuditRecord::EMPTY; 4]),
        0
    );
    // Host has no real link; the managed wrapper must not fabricate a queue ack.
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    assert_eq!(
        submit_managed_motor_pair(pair, NOW_NS, 1, DEADLINE, || 1).outcome,
        MotorPairSubmissionOutcome::QueueFailed
    );
    assert_eq!(
        trigger_estop_with_clock(AuditSource::ManagedControl, || NOW_NS),
        0
    );
    assert!(ACTUATION_MONITOR.lock().is_latched());
    assert!(
        managed_motor_pair_owned(),
        "stopping must not release ownership"
    );
    assert_eq!(guard_motor_pair(100, 100), -1);
    *ACTUATION_MONITOR.lock() = saved;
    set_managed_motor_pair_owner(saved_owner);
}
