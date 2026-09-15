//! One borrowed controller invocation per absolute release. No hook fanout,
//! manager access, allocation or instance destruction belongs on this path.

use kernel_abi::ManagedControlContextV1;
use kernel_bpf::actuation::MotorPairDecision;
use kernel_bpf::execution::{BpfError, ManagedMotorPair};
use kernel_time::checked_frequency_ticks_to_nanoseconds as ticks_to_ns;
use kernel_time::periodic::PeriodicRelease;

use super::installation::ControlSlot;
use crate::actuation::{MotorPairSubmission, MotorPairSubmissionOutcome};

/// The UART frame has no acquisition timestamp. This is the Pi's physical
/// counter at complete CRC-validated receive, with the adapter's raw echo µs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SensorSnapshot {
    received_ticks: u64,
    echo_us: u16,
    valid: bool,
}

impl SensorSnapshot {
    pub(crate) const fn received(ticks: u64, echo_us: u16, flags: u8, estop: bool) -> Self {
        Self {
            received_ticks: ticks,
            echo_us,
            valid: flags == 0 && echo_us != 0 && !estop,
        }
    }

    fn context(
        self,
        release: PeriodicRelease,
        frequency: u64,
        max_age_ns: u64,
    ) -> Result<ManagedControlContextV1, CycleFailure> {
        let scheduled_ns =
            ticks_to_ns(release.scheduled, frequency).ok_or(CycleFailure::ClockInvalid)?;
        let actual_ns = ticks_to_ns(release.actual, frequency).ok_or(CycleFailure::ClockInvalid)?;
        let sensor_ns =
            ticks_to_ns(self.received_ticks, frequency).ok_or(CycleFailure::ClockInvalid)?;
        Ok(ManagedControlContextV1 {
            version: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_VERSION,
            size: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_SIZE,
            cycle_id: release.sequence,
            scheduled_ns,
            actual_ns,
            sensor_ns,
            sensor_value: i64::from(self.echo_us),
            sensor_valid: u32::from(
                self.valid
                    && actual_ns
                        .checked_sub(sensor_ns)
                        .is_some_and(|age| age < max_age_ns),
            ),
            reserved: 0,
        })
    }
}

static SENSOR: spin::Mutex<SensorSnapshot> = spin::Mutex::new(SensorSnapshot {
    received_ticks: 0,
    echo_us: 0,
    valid: false,
});

pub(crate) fn publish_sensor(sample: SensorSnapshot) {
    crate::mcore::context::with_interrupts_masked(|| {
        let mut current = SENSOR.lock();
        *current = if sample.received_ticks < current.received_ticks {
            SensorSnapshot {
                valid: false,
                ..*current
            }
        } else {
            sample
        };
    });
}

pub(crate) fn invalidate_sensor() {
    crate::mcore::context::with_interrupts_masked(|| SENSOR.lock().valid = false);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CycleFailure {
    InvalidRelease,
    MissedRelease,
    ClockInvalid,
    ClockReversed,
    Deadline,
    Invocation(BpfError),
    Submission(MotorPairSubmissionOutcome),
    PolicyStopped,
    Handoff(shrike_link::handoff::HandoffError),
}

/// One bounded latest result for the timer; the rolling recorder is separate.
/// A retained Queued outcome followed by Deadline is not a physical rollback.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CycleReport {
    pub generation: u64,
    pub artifact: Option<u32>,
    pub handoff: bool,
    pub safe_mode: bool,
    pub context: Option<ManagedControlContextV1>,
    pub invocation_completed: bool,
    pub requested: Option<ManagedMotorPair>,
    pub submission: Option<MotorPairSubmission>,
    pub failure: Option<CycleFailure>,
}

fn check_time(now: u64, not_before: u64, deadline: u64) -> Result<(), CycleFailure> {
    if now < not_before {
        Err(CycleFailure::ClockReversed)
    } else if now >= deadline {
        Err(CycleFailure::Deadline)
    } else {
        Ok(())
    }
}

impl ControlSlot {
    pub(crate) fn run_release(
        &mut self,
        release: PeriodicRelease,
        frequency: u64,
        sensor: SensorSnapshot,
        max_sensor_age_ns: u64,
        read_ticks: &mut impl FnMut() -> u64,
        submit: impl FnOnce(ManagedMotorPair, u64, u64, &mut dyn FnMut() -> u64) -> MotorPairSubmission,
    ) -> CycleReport {
        let slot = self.snapshot();
        let mut report = CycleReport {
            generation: slot.generation,
            artifact: slot.active,
            handoff: slot.pending.is_some_and(|id| {
                self.operation_phase(id) == Some(kernel_abi::MANAGED_OPERATION_HANDOFF)
            }),
            safe_mode: slot.inhibited || slot.active.is_none(),
            context: None,
            invocation_completed: false,
            requested: None,
            submission: None,
            failure: None,
        };
        let result = (|| {
            if release.sequence <= self.last_control_release
                || release.scheduled > release.actual
                || release.actual >= release.deadline
            {
                return Err(CycleFailure::InvalidRelease);
            }
            self.last_control_release = release.sequence;
            if report.safe_mode {
                return Ok(());
            }
            if release.missed_before != 0 {
                return Err(CycleFailure::MissedRelease);
            }
            let context = sensor.context(release, frequency, max_sensor_age_ns)?;
            report.context = Some(context);
            let started = read_ticks();
            check_time(started, release.actual, release.deadline)?;
            let invocation = self.execute(&context).map_err(CycleFailure::Invocation)?;
            report.invocation_completed = true;
            report.requested = invocation.request;
            let finished = read_ticks();
            check_time(finished, started, release.deadline)?;
            let mut last_checked = finished;
            let submission = submit(
                invocation.motor_pair(),
                finished,
                release.deadline,
                &mut || {
                    last_checked = read_ticks();
                    last_checked
                },
            );
            report.submission = Some(submission);
            if submission.outcome != MotorPairSubmissionOutcome::Queued {
                return Err(CycleFailure::Submission(submission.outcome));
            }
            check_time(read_ticks(), last_checked, release.deadline)?;
            if matches!(submission.decision, Some(MotorPairDecision::Safe { .. })) {
                return Err(CycleFailure::PolicyStopped);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.stop();
            report.failure = Some(error);
        }
        report
    }
}

/// Called only by the qualified CPU0 timer. Snapshot copied before borrowing the
/// slot, so neither the interpreter nor any observer can change its input.
#[cfg(all(target_arch = "aarch64", feature = "rpi5", feature = "managed-runtime"))]
pub(crate) fn on_release(
    release: PeriodicRelease,
    frequency: u64,
) -> Result<CycleReport, BpfError> {
    let sensor = *SENSOR.try_lock().ok_or(BpfError::ObjectBusy)?;
    let report = super::installation::try_release_boundary(|slot| {
        let handoff = crate::arch::aarch64::platform::rpi5::control_link::handoff_boundary(
            slot, release, frequency,
        );
        if handoff.is_err() {
            slot.stop();
        }
        let mut report = slot.run_release(
            release,
            frequency,
            sensor,
            crate::arch::aarch64::platform::rpi5::control_link::LINK_TIMEOUT_NS,
            &mut crate::arch::aarch64::interrupts::physical_counter,
            |pair, not_before, deadline, clock| {
                crate::actuation::submit_managed_motor_pair(
                    pair,
                    crate::time::get_kernel_time_ns(),
                    not_before,
                    deadline,
                    clock,
                )
            },
        );
        if let Err(error) = handoff {
            report.failure = Some(CycleFailure::Handoff(error));
        }
        report
    })?;
    if report.failure.is_some() {
        crate::actuation::trigger_estop(kernel_bpf::actuation::AuditSource::ManagedControl);
    }
    super::recorder::events::cycle(release, report);
    Ok(report)
}

#[cfg(test)]
#[path = "control_tests.rs"]
pub(super) mod tests;
