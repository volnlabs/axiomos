//! Pi5-side link session: turns inbound liveness + the clock into the outbound
//! action the transport should take (heartbeat the peer, or fail safe). Pure,
//! host-tested — the safety-critical heartbeat/fail-safe decisions live here,
//! not in the kernel `poll()`, so they can be unit-tested.
//!
//! Fault model closed: while the RP2040 is alive, heartbeat it on a cadence.
//! When inbound goes silent (link dead), STOP heartbeating (so the RP2040's own
//! watchdog trips) and command a one-shot e-stop. The e-stop is retried every
//! tick until the caller confirms it was actually sent ([`LinkSession::estop_sent`]),
//! so a momentarily-full TX ring cannot swallow the fail-safe command.

use crate::watchdog::LinkLiveness;

/// What the transport should emit this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAction {
    /// Nothing to send.
    Idle,
    /// Send a `HeartbeatToShrike` with this sequence number.
    Heartbeat(u16),
    /// Link is dead — command an e-stop (and the caller must NOT heartbeat).
    SafeStop,
}

pub struct LinkSession {
    live: LinkLiveness,
    hb_period: u64,
    hb_seq: u16,
    last_hb: u64,
    alive_prev: bool,
    estop_done: bool,
}

impl LinkSession {
    /// `timeout` = inbound-silence -> dead; `hb_period` = heartbeat cadence
    /// while alive. Same tick unit throughout. `timeout` MUST exceed the
    /// RP2040 firmware's own link timeout so the peer fails safe first.
    #[must_use]
    pub const fn new(timeout: u64, hb_period: u64) -> Self {
        Self {
            live: LinkLiveness::new(timeout),
            hb_period,
            hb_seq: 0,
            last_hb: 0,
            alive_prev: false,
            estop_done: false,
        }
    }

    /// Record an inbound frame (refreshes liveness).
    pub fn on_inbound(&mut self, now: u64) {
        self.live.on_inbound(now);
    }

    /// Is the peer currently alive?
    #[must_use]
    pub fn alive(&self, now: u64) -> bool {
        self.live.alive(now)
    }

    /// Decide the outbound action for this tick.
    pub fn tick(&mut self, now: u64) -> LinkAction {
        if self.live.alive(now) {
            self.alive_prev = true;
            self.estop_done = false;
            if now.wrapping_sub(self.last_hb) >= self.hb_period {
                self.last_hb = now;
                let seq = self.hb_seq;
                self.hb_seq = self.hb_seq.wrapping_add(1);
                return LinkAction::Heartbeat(seq);
            }
            return LinkAction::Idle;
        }
        // Dead. On the alive->dead edge, arm a fresh e-stop.
        if self.alive_prev {
            self.alive_prev = false;
            self.estop_done = false;
        }
        if !self.estop_done {
            LinkAction::SafeStop
        } else {
            LinkAction::Idle
        }
    }

    /// Confirm the e-stop emitted by a `SafeStop` action was actually sent, so
    /// it is not re-emitted next tick. (Until called, `tick` keeps returning
    /// `SafeStop` on each dead tick — the fail-safe is never silently dropped.)
    pub fn estop_sent(&mut self) {
        self.estop_done = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // timeout 100, heartbeat every 20.
    fn sess() -> LinkSession {
        LinkSession::new(100, 20)
    }

    #[test]
    fn cold_link_is_dead_and_commands_safestop() {
        let mut s = sess();
        // No inbound ever -> not alive -> SafeStop (until sent).
        assert_eq!(s.tick(0), LinkAction::SafeStop);
        s.estop_sent();
        assert_eq!(s.tick(1), LinkAction::Idle);
    }

    #[test]
    fn heartbeats_on_cadence_while_alive() {
        let mut s = sess();
        s.on_inbound(0);
        // last_hb starts at 0, so at now=0 nothing is due yet.
        assert_eq!(s.tick(0), LinkAction::Idle);
        assert_eq!(s.tick(20), LinkAction::Heartbeat(0)); // period elapsed
        assert_eq!(s.tick(30), LinkAction::Idle); // < period since last hb
        s.on_inbound(40);
        assert_eq!(s.tick(40), LinkAction::Heartbeat(1)); // 40-20 >= 20
    }

    #[test]
    fn exactly_one_safestop_on_death_then_idle() {
        let mut s = sess();
        s.on_inbound(0);
        let _ = s.tick(20); // alive heartbeat (consume)
                            // No further inbound; at now=100 liveness expires (deadline = 0+100).
        assert_eq!(s.tick(100), LinkAction::SafeStop);
        s.estop_sent();
        assert_eq!(s.tick(120), LinkAction::Idle); // not re-spammed
        assert_eq!(s.tick(200), LinkAction::Idle);
    }

    #[test]
    fn safestop_retried_until_estop_sent() {
        let mut s = sess();
        s.on_inbound(0);
        s.tick(0);
        // Dead and the caller could NOT send (ring full) -> keeps asking.
        assert_eq!(s.tick(100), LinkAction::SafeStop);
        assert_eq!(s.tick(110), LinkAction::SafeStop);
        assert_eq!(s.tick(120), LinkAction::SafeStop);
        s.estop_sent();
        assert_eq!(s.tick(130), LinkAction::Idle);
    }

    #[test]
    fn models_poll_integration_enqueue_fail_then_success() {
        // Mirrors control_link::poll(): on SafeStop the caller tries to enqueue
        // an e-stop and only calls estop_sent() if the enqueue SUCCEEDED. Here
        // we simulate the TX ring being full for two ticks (enqueue fails -> do
        // NOT call estop_sent) then having room (success -> estop_sent).
        let mut s = sess();
        s.on_inbound(0);
        let _ = s.tick(20);
        let mut tx_ring_full = true;
        for now in [100u64, 110] {
            assert_eq!(s.tick(now), LinkAction::SafeStop);
            if !tx_ring_full {
                s.estop_sent();
            }
        }
        // Ring frees up: this tick's SafeStop enqueue succeeds.
        assert_eq!(s.tick(120), LinkAction::SafeStop);
        tx_ring_full = false;
        if !tx_ring_full {
            s.estop_sent();
        }
        // E-stop confirmed sent: no further SafeStop spam.
        assert_eq!(s.tick(130), LinkAction::Idle);
    }

    #[test]
    fn no_heartbeat_while_dead() {
        let mut s = sess();
        s.on_inbound(0);
        s.tick(0);
        // dead from 100 on; must never emit Heartbeat
        for t in [100u64, 120, 140, 200, 400] {
            assert!(!matches!(s.tick(t), LinkAction::Heartbeat(_)));
            s.estop_sent(); // simulate it gets sent
        }
    }

    #[test]
    fn heartbeats_resume_only_after_inbound_refresh() {
        let mut s = sess();
        s.on_inbound(0);
        s.tick(0);
        assert_eq!(s.tick(100), LinkAction::SafeStop); // dead
        s.estop_sent();
        assert_eq!(s.tick(150), LinkAction::Idle); // still dead, no HB
        s.on_inbound(160); // peer came back
                           // seq continues from before the outage; assert the variant, not value.
        assert!(matches!(s.tick(160), LinkAction::Heartbeat(_)));
    }
}
