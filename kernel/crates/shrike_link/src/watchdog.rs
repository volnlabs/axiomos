//! Shrike-side link safety state machine.
//!
//! The codec ([`crate`]) turns bytes into [`Msg`]s; this turns a stream of
//! Pi5->Shrike messages into a motor [`Output`] that is **fail-safe by
//! construction**:
//!
//! - **Command silence:** if no fresh Pi5 motor command arrives within
//!   `timeout` ticks, the output is [`Output::SafeStop`]. Heartbeats cannot
//!   extend or restore motor authority. Expiry requires explicit release and
//!   then a fresh motor command; peer liveness is a separate concern.
//! - **E-stop latch:** a soft `Estop{assert:true}` latches `SafeStop` until an
//!   explicit `Estop{assert:false}` — assert dominates everything, including a
//!   simultaneously-fresh setpoint. (The hard e-stop is still the independent
//!   FPGA line; this is defense in depth.)
//! - **Anti-replay:** a `MotorSetpoint` whose `seq` is not newer than the last
//!   accepted one is rejected — it neither updates the setpoint nor refreshes
//!   liveness, so a replayed/stale frame cannot keep a dead link "alive".
//! - **Cold start:** before the first fresh setpoint, the output is `SafeStop`.
//!
//! Time is caller-supplied monotonic `u64` ticks (ns, us, ms — your choice, as
//! long as `now` and `timeout` share a unit). Pure logic, no clock, no alloc.

use crate::Msg;

/// What the motors should do right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// Drive at this signed per-mille duty (NOT clamped here — the kernel
    /// actuation monitor / FPGA envelope clamp).
    Drive { left: i16, right: i16 },
    /// Force motors to neutral/off.
    SafeStop,
}

/// Shrike-side link watchdog. Feed it Pi5->Shrike messages with timestamps;
/// ask it for the [`Output`] at any later time.
#[derive(Debug, Clone, Copy)]
pub struct Watchdog {
    timeout: u64,
    deadline: u64,
    // Physical stop disarming must not erase a pending command timeout.
    command_deadline_active: bool,
    /// Have we ever accepted a setpoint? Gates the anti-replay seq compare and
    /// persists across an e-stop so a pre-estop seq cannot be replayed after.
    seq_valid: bool,
    last_seq: u8,
    left: i16,
    right: i16,
    /// Is there a usable, post-any-estop setpoint to drive on? Cleared on
    /// e-stop assert and only re-set by a setpoint accepted while NOT latched,
    /// so releasing an e-stop never resumes a stale pre-estop command.
    setpoint_armed: bool,
    estop_latched: bool,
    hardware_estop: bool,
}

impl Watchdog {
    /// `timeout` = max ticks between fresh motor commands before failing safe.
    #[must_use]
    pub const fn new(timeout: u64) -> Self {
        Self {
            timeout,
            deadline: 0,
            command_deadline_active: false,
            seq_valid: false,
            last_seq: 0,
            left: 0,
            right: 0,
            setpoint_armed: false,
            estop_latched: false,
            hardware_estop: false,
        }
    }

    /// Feed one decoded Pi5->Shrike message observed at `now`.
    ///
    /// Returns `true` for an accepted message (not proof of motor application).
    /// Only a fresh setpoint refreshes the command deadline. Shrike->Pi5
    /// messages and stale/replayed setpoints return `false`.
    pub fn on_msg(&mut self, msg: &Msg, now: u64) -> bool {
        // Observe expiry before processing a new message: neither a heartbeat
        // nor a delayed newer setpoint may silently resume timed-out motion.
        if self.command_deadline_active && self.expired(now) {
            self.command_deadline_active = false;
            self.setpoint_armed = false;
            self.estop_latched = true;
        }
        match *msg {
            Msg::MotorSetpoint { seq, left, right } => {
                if self.seq_valid && !seq_newer(seq, self.last_seq) {
                    return false; // stale / replay: no update, no liveness refresh
                }
                self.seq_valid = true;
                self.last_seq = seq;
                self.left = left;
                self.right = right;
                // Only a setpoint received while NOT latched arms driving; this
                // is what forces a *fresh* setpoint after an e-stop release
                // rather than resuming a possibly-ancient stored command.
                self.setpoint_armed = !self.estop_latched && !self.hardware_estop;
                if self.setpoint_armed {
                    self.refresh(now);
                    self.command_deadline_active = true;
                }
                true
            }
            Msg::Estop { assert } => {
                self.estop_latched = assert;
                // Even a redundant release requires a new complete setpoint.
                self.setpoint_armed = false;
                self.command_deadline_active = false;
                true
            }
            Msg::HeartbeatToShrike { .. } => true,
            // Shrike->Pi5 telemetry is not a watchdog input.
            Msg::Sensor { .. } | Msg::HeartbeatToPi { .. } => false,
        }
    }

    /// Sample physical stop independently of operator/timeout latches.
    /// Neither edge clears an operator stop; either edge discards old motion.
    pub fn set_hardware_estop(&mut self, asserted: bool) {
        if asserted != self.hardware_estop || asserted {
            self.setpoint_armed = false;
        }
        self.hardware_estop = asserted;
    }

    /// The motor output at `now`. Fail-safe wins: e-stop latch, then arming,
    /// then command age.
    #[must_use]
    pub fn output(&self, now: u64) -> Output {
        if self.estop_latched || self.hardware_estop || !self.setpoint_armed || self.expired(now) {
            Output::SafeStop
        } else {
            Output::Drive {
                left: self.left,
                right: self.right,
            }
        }
    }

    /// True if the motor command has expired as of `now`.
    #[must_use]
    pub fn expired(&self, now: u64) -> bool {
        now >= self.deadline
    }

    fn refresh(&mut self, now: u64) {
        // Saturating so a near-u64::MAX `now` can't wrap the deadline backwards.
        self.deadline = now.saturating_add(self.timeout);
    }
}

/// Inbound-direction link liveness: is the *peer* still talking to us?
///
/// Separate from [`Watchdog`] (which is the Shrike-side command authority and
/// deliberately ignores telemetry frames). This is what the Pi5 runs to detect
/// an RP2040 that has gone silent: refreshed by ANY inbound frame, `alive()`
/// goes false once `timeout` ticks pass with no inbound. The Pi uses this to
/// stop sending heartbeats and command a safe state, so the RP2040's own
/// watchdog also trips (closing the one-way RX-dead/TX-alive fault). Symmetric
/// — usable on either end. Caller supplies monotonic ticks (same unit as `timeout`).
#[derive(Debug, Clone, Copy)]
pub struct LinkLiveness {
    timeout: u64,
    deadline: u64,
    seen: bool,
}

impl LinkLiveness {
    #[must_use]
    pub const fn new(timeout: u64) -> Self {
        Self {
            timeout,
            deadline: 0,
            seen: false,
        }
    }

    /// Record an inbound frame at `now` — refreshes liveness.
    pub fn on_inbound(&mut self, now: u64) {
        self.seen = true;
        self.deadline = now.saturating_add(self.timeout);
    }

    /// True iff at least one inbound frame has arrived and the peer has not gone
    /// silent past `timeout`. False before the first frame (cold) and once dead.
    #[must_use]
    pub fn alive(&self, now: u64) -> bool {
        self.seen && now < self.deadline
    }
}

/// RFC-1982-style serial comparison over `u8`: is `new` strictly newer than
/// `last`, tolerating wraparound (255 -> 0 is newer)?
fn seq_newer(new: u8, last: u8) -> bool {
    let d = new.wrapping_sub(last);
    d != 0 && d < 128
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(seq: u8, l: i16, r: i16) -> Msg {
        Msg::MotorSetpoint {
            seq,
            left: l,
            right: r,
        }
    }

    #[test]
    fn cold_start_is_safe_stop() {
        let wd = Watchdog::new(100);
        assert_eq!(wd.output(0), Output::SafeStop);
        assert_eq!(wd.output(50), Output::SafeStop);
    }

    #[test]
    fn fresh_setpoint_drives_then_times_out() {
        let mut wd = Watchdog::new(100);
        assert!(wd.on_msg(&sp(1, 200, -200), 1000));
        assert_eq!(
            wd.output(1050),
            Output::Drive {
                left: 200,
                right: -200
            }
        );
        assert_eq!(wd.output(1100), Output::SafeStop); // now >= deadline (1100)
        assert_eq!(wd.output(2000), Output::SafeStop);
    }

    #[test]
    fn heartbeats_never_extend_motor_command_lifetime() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 50, 50), 0);
        assert!(wd.on_msg(&Msg::HeartbeatToShrike { seq: 7 }, 90));
        assert_eq!(wd.output(100), Output::SafeStop);
        assert!(wd.on_msg(&Msg::HeartbeatToShrike { seq: 7 }, 110));
        assert_eq!(wd.output(110), Output::SafeStop);
        assert!(wd.on_msg(&Msg::HeartbeatToShrike { seq: 8 }, 120));
        assert_eq!(wd.output(120), Output::SafeStop);
    }

    #[test]
    fn timeout_requires_release_then_a_fresh_command() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 50, 50), 0);
        assert_eq!(wd.output(100), Output::SafeStop);
        wd.on_msg(&sp(2, 60, 60), 101);
        assert_eq!(wd.output(101), Output::SafeStop);
        wd.on_msg(&Msg::Estop { assert: false }, 102);
        assert_eq!(wd.output(102), Output::SafeStop);
        wd.on_msg(&sp(3, 20, 20), 103);
        assert_eq!(
            wd.output(103),
            Output::Drive {
                left: 20,
                right: 20
            }
        );
    }

    #[test]
    fn physical_stop_cycle_does_not_erase_timeout_rearm_requirement() {
        for assert_at in [90, 100] {
            let mut wd = Watchdog::new(100);
            wd.on_msg(&sp(1, 50, 50), 0);
            assert_eq!(
                wd.output(assert_at),
                if assert_at < 100 {
                    Output::Drive {
                        left: 50,
                        right: 50,
                    }
                } else {
                    Output::SafeStop
                }
            );
            wd.set_hardware_estop(true);
            wd.set_hardware_estop(false);
            wd.on_msg(&sp(2, 60, 60), 101);
            assert_eq!(wd.output(101), Output::SafeStop);
            wd.on_msg(&Msg::Estop { assert: false }, 102);
            wd.on_msg(&sp(3, 20, 20), 103);
            assert_eq!(
                wd.output(103),
                Output::Drive {
                    left: 20,
                    right: 20
                }
            );
        }
    }

    #[test]
    fn redundant_release_does_not_refresh_an_old_command() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 50, 50), 0);
        wd.on_msg(&Msg::Estop { assert: false }, 90);
        assert_eq!(wd.output(100), Output::SafeStop);
    }

    #[test]
    fn stale_or_replayed_setpoint_rejected_and_no_liveness() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(5, 10, 10), 0);
        // Replay of seq 5 with different values at t=90: rejected entirely.
        assert!(!wd.on_msg(&sp(5, 999, 999), 90));
        assert_eq!(
            wd.output(50),
            Output::Drive {
                left: 10,
                right: 10
            }
        );
        // Replay did NOT refresh liveness, so it still times out at 100.
        assert_eq!(wd.output(100), Output::SafeStop);
    }

    #[test]
    fn older_seq_rejected() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(10, 1, 1), 0);
        assert!(!wd.on_msg(&sp(9, 2, 2), 10)); // 9 older than 10
        assert_eq!(wd.output(50), Output::Drive { left: 1, right: 1 });
    }

    #[test]
    fn seq_wraps_around() {
        let mut wd = Watchdog::new(100);
        assert!(wd.on_msg(&sp(254, 1, 1), 0));
        assert!(wd.on_msg(&sp(255, 2, 2), 10));
        assert!(wd.on_msg(&sp(0, 3, 3), 20)); // 255 -> 0 is newer
        assert!(wd.on_msg(&sp(1, 4, 4), 30));
        assert_eq!(wd.output(40), Output::Drive { left: 4, right: 4 });
    }

    #[test]
    fn estop_latches_and_dominates_fresh_setpoint() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 100, 100), 0);
        wd.on_msg(&Msg::Estop { assert: true }, 10);
        assert_eq!(wd.output(20), Output::SafeStop);
        // A setpoint while latched does not override the e-stop, and does NOT
        // arm driving (it was received while latched).
        wd.on_msg(&sp(2, 100, 100), 30);
        assert_eq!(wd.output(40), Output::SafeStop);
        // Release alone does NOT resume — a fresh post-release setpoint is
        // required, so we never drive on a possibly-stale stored command.
        wd.on_msg(&Msg::Estop { assert: false }, 50);
        assert_eq!(wd.output(60), Output::SafeStop);
        // A fresh setpoint after release arms driving again.
        wd.on_msg(&sp(3, 70, 70), 70);
        assert_eq!(
            wd.output(80),
            Output::Drive {
                left: 70,
                right: 70
            }
        );
    }

    #[test]
    fn estop_release_with_no_setpoint_during_latch_requires_fresh() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 9, 9), 0);
        wd.on_msg(&Msg::Estop { assert: true }, 10);
        wd.on_msg(&Msg::Estop { assert: false }, 20);
        assert_eq!(wd.output(25), Output::SafeStop); // no fresh setpoint yet
        wd.on_msg(&sp(2, 4, 4), 30);
        assert_eq!(wd.output(35), Output::Drive { left: 4, right: 4 });
    }

    #[test]
    fn replay_after_estop_release_is_still_rejected() {
        // seq tracking persists across e-stop: a replay of the pre-estop seq
        // must not arm driving after release.
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(5, 1, 1), 0);
        wd.on_msg(&Msg::Estop { assert: true }, 10);
        wd.on_msg(&Msg::Estop { assert: false }, 20);
        assert!(!wd.on_msg(&sp(5, 1, 1), 30)); // replay rejected
        assert_eq!(wd.output(35), Output::SafeStop);
    }

    #[test]
    fn seq_newer_half_window_boundary() {
        assert!(!seq_newer(128, 0)); // d == 128 rejected (ambiguous half-window)
        assert!(seq_newer(127, 0)); // d == 127 newer
        assert!(!seq_newer(0, 128)); // d == 0-128 == 128 -> rejected
        assert!(seq_newer(200, 100)); // d == 100 newer
        assert!(!seq_newer(0, 0)); // equal rejected
    }

    #[test]
    fn seq_newer_matches_rfc1982_over_all_pairs() {
        for last in 0u8..=255 {
            for new in 0u8..=255 {
                let d = new.wrapping_sub(last);
                let expected = d != 0 && d < 128;
                assert_eq!(seq_newer(new, last), expected, "new={new} last={last}");
            }
        }
    }

    #[test]
    fn timeout_zero_always_expires() {
        let mut wd = Watchdog::new(0);
        wd.on_msg(&sp(1, 5, 5), 100);
        // deadline == now == 100, expired uses >=, so immediately safe.
        assert_eq!(wd.output(100), Output::SafeStop);
    }

    #[test]
    fn link_liveness_cold_dead_until_first_inbound() {
        let l = LinkLiveness::new(100);
        assert!(!l.alive(0));
        assert!(!l.alive(50));
    }

    #[test]
    fn link_liveness_alive_then_times_out() {
        let mut l = LinkLiveness::new(100);
        l.on_inbound(1000);
        assert!(l.alive(1050));
        assert!(!l.alive(1100)); // now >= deadline
        assert!(!l.alive(2000));
    }

    #[test]
    fn link_liveness_refresh_extends() {
        let mut l = LinkLiveness::new(100);
        l.on_inbound(0);
        assert!(l.alive(90));
        l.on_inbound(90); // refresh before timeout
        assert!(l.alive(150));
        assert!(!l.alive(190));
    }

    #[test]
    fn backwards_now_is_caller_contract_not_defended() {
        // Documents the monotonic-`now` contract: the watchdog has no internal
        // clock, so a caller that passes a decreasing `now` makes the link look
        // MORE alive (now < deadline => not expired). The caller MUST supply a
        // monotonic clock; this test pins that assumption so a future regression
        // in the caller is visible rather than silent.
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 5, 5), 1000); // deadline = 1100
        assert_eq!(wd.output(500), Output::Drive { left: 5, right: 5 });
    }

    #[test]
    fn deadline_saturates_near_u64_max() {
        let mut wd = Watchdog::new(u64::MAX);
        wd.on_msg(&sp(1, 5, 5), u64::MAX - 1);
        // saturating_add keeps deadline at u64::MAX; not expired before then.
        assert_eq!(wd.output(u64::MAX - 1), Output::Drive { left: 5, right: 5 });
        assert_eq!(wd.output(u64::MAX), Output::SafeStop);
    }

    #[test]
    fn estop_dominates_even_when_not_expired() {
        let mut wd = Watchdog::new(1_000_000);
        wd.on_msg(&sp(1, 5, 5), 0);
        wd.on_msg(&Msg::Estop { assert: true }, 1);
        assert_eq!(wd.output(2), Output::SafeStop);
    }

    #[test]
    fn telemetry_messages_are_not_inputs() {
        let mut wd = Watchdog::new(100);
        wd.on_msg(&sp(1, 7, 7), 0);
        assert!(!wd.on_msg(
            &Msg::Sensor {
                ultrasonic_echo_us: 1,
                estop_line: false,
                flags: 0
            },
            50
        ));
        assert!(!wd.on_msg(&Msg::HeartbeatToPi { seq: 1 }, 50));
        // Those did not refresh liveness.
        assert_eq!(wd.output(100), Output::SafeStop);
    }
}
