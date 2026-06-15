//! ARM-A — the Actuation Reference Monitor (pure decision core).
//!
//! Untrusted, hot-loaded BPF logic proposes actuations; this monitor decides
//! whether each one may reach hardware, clamping magnitude and slew into a
//! per-profile safety envelope. The decision logic is pure (no MMIO) so the
//! "0 escapes" safety invariant is proven by host tests; the kernel binary
//! crate maps a `Decision` onto RP1 MMIO (see `kernel/src/actuation.rs`).

use crate::profile::PhysicalProfile;
use core::sync::atomic::{AtomicU64, Ordering};

/// What kind of actuator a request targets. Determines the safe state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActuationKind {
    /// PWM duty cycle, percent 0..=100.
    PwmDuty,
    /// GPIO output level, 0 or 1.
    GpioLevel,
}

/// Identifies a physical output channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId {
    pub kind: ActuationKind,
    /// PWM: controller id (0|1). GPIO: 0.
    pub chip: u8,
    /// PWM: channel (1|2). GPIO: pin (0..=27).
    pub channel: u8,
}

/// A requested actuation, before the monitor decides.
#[derive(Debug, Clone, Copy)]
pub struct ActuationRequest {
    pub ch: ChannelId,
    pub value: u32,
}

/// Trusted authority stamped by kernel call-sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authority {
    Learned,
    Mission,
    Operator,
    Safety,
}

/// Trusted source attribution stamped by kernel call-sites for audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditSource {
    Operator,
    Watchdog,
    GpioHook,
    LearnedBehavior,
    Mission,
    SyscallPwm,
}

/// The safety envelope for a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub min: u32,
    pub max: u32,
    /// Max change in output per `window_ns`. 0 disables slew limiting.
    pub max_step: u32,
    /// Rate-limit window in nanoseconds. 0 disables slew limiting.
    pub window_ns: u64,
}

impl Envelope {
    /// Build the Spec-1 envelope for a channel kind. `PwmDuty` reads the profile
    /// constants; `GpioLevel` is the fixed `{0,1,1,0}` envelope (slew is not
    /// meaningful on a binary line).
    pub fn from_profile<P: PhysicalProfile>(kind: ActuationKind) -> Self {
        match kind {
            ActuationKind::PwmDuty => Envelope {
                min: 0,
                max: P::ACT_DUTY_MAX,
                max_step: P::ACT_DUTY_MAX_STEP,
                window_ns: P::ACT_RATE_WINDOW_NS,
            },
            ActuationKind::GpioLevel => Envelope {
                min: 0,
                max: 1,
                max_step: 1,
                window_ns: 0,
            },
        }
    }
}

/// Why a request was structurally refused (distinct from a policy-safe outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// No envelope exists for this channel (deny-by-default).
    UnknownChannel,
}

/// Audit reason code shape shared by governance and ARM-A decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    None,
    UnknownChannel,
    Governance,
}

impl From<RejectReason> for ReasonCode {
    fn from(reason: RejectReason) -> Self {
        match reason {
            RejectReason::UnknownChannel => ReasonCode::UnknownChannel,
        }
    }
}

/// Compact decision tag for fixed-size audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionTag {
    Allow,
    Clamp,
    Safe,
    Reject,
    EstopTrigger,
    EstopRelease,
    ReleaseDenied,
}

/// The monitor's decision — four distinguishable outcomes so audit logs,
/// authority decisions, and incident replay (Spec 2) can tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Inside the envelope; apply `value` unchanged.
    Allow(u32),
    /// Clamped (magnitude and/or slew); apply the bounded value.
    Clamp(u32),
    /// Policy forced the channel to its safe value (safe-hold / e-stop / veto).
    Safe(u32),
    /// Structurally invalid; the caller drives the universal safe (0).
    Reject(RejectReason),
}

impl Decision {
    fn tag(self) -> DecisionTag {
        match self {
            Decision::Allow(_) => DecisionTag::Allow,
            Decision::Clamp(_) => DecisionTag::Clamp,
            Decision::Safe(_) => DecisionTag::Safe,
            Decision::Reject(_) => DecisionTag::Reject,
        }
    }

    fn reason(self) -> ReasonCode {
        match self {
            Decision::Reject(reason) => reason.into(),
            Decision::Safe(_) => ReasonCode::Governance,
            Decision::Allow(_) | Decision::Clamp(_) => ReasonCode::None,
        }
    }
}

impl Decision {
    /// Map a decision to `(mmio_value_to_write, return_code_for_caller)`.
    /// `Reject` writes the universal safe value 0 (an unknown channel must not be
    /// wired to a live actuator). `Safe` returns -1 to signal policy intervention.
    pub fn apply(self) -> (u32, i64) {
        match self {
            Decision::Allow(v) | Decision::Clamp(v) => (v, 0),
            Decision::Safe(v) => (v, -1),
            Decision::Reject(_) => (0, -1),
        }
    }
}

const EMPTY_CHANNEL: ChannelId = ChannelId {
    kind: ActuationKind::PwmDuty,
    chip: 0,
    channel: 0,
};

/// Fixed-size audit record emitted by the actuation monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub t_ns: u64,
    pub source: AuditSource,
    pub channel: ChannelId,
    pub authority: Authority,
    pub req_value: u32,
    pub decision: DecisionTag,
    pub reason: ReasonCode,
}

impl AuditRecord {
    pub const EMPTY: Self = Self {
        seq: 0,
        t_ns: 0,
        source: AuditSource::LearnedBehavior,
        channel: EMPTY_CHANNEL,
        authority: Authority::Learned,
        req_value: 0,
        decision: DecisionTag::Allow,
        reason: ReasonCode::None,
    };
}

pub struct AuditSlot {
    seq: AtomicU64,
    body: AuditRecord,
}

impl AuditSlot {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(u64::MAX),
            body: AuditRecord::EMPTY,
        }
    }
}

/// Single-writer, overwrite-oldest audit ring.
pub struct AuditRing<const N: usize> {
    buf: [AuditSlot; N],
    head: AtomicU64,
}

impl<const N: usize> AuditRing<N> {
    pub const fn new() -> Self {
        Self {
            buf: [const { AuditSlot::new() }; N],
            head: AtomicU64::new(0),
        }
    }

    pub fn emit(&mut self, mut record: AuditRecord) {
        let seq = self.head.load(Ordering::Relaxed);
        record.seq = seq;
        if N > 0 {
            let idx = (seq as usize) % N;
            self.buf[idx].body = record;
            self.buf[idx].seq.store(seq, Ordering::Release);
        }
        self.head.store(seq.wrapping_add(1), Ordering::Release);
    }

    pub fn snapshot(&self, out: &mut [AuditRecord]) -> usize {
        if N == 0 || out.is_empty() {
            return 0;
        }

        let head = self.head.load(Ordering::Acquire);
        let start = head.saturating_sub(N as u64);
        let mut copied = 0;

        for seq in start..head {
            if copied == out.len() {
                break;
            }
            let idx = (seq as usize) % N;
            let slot = &self.buf[idx];
            let before = slot.seq.load(Ordering::Acquire);
            if before != seq {
                continue;
            }
            let body = slot.body;
            let after = slot.seq.load(Ordering::Acquire);
            if before == after && body.seq == seq {
                out[copied] = body;
                copied += 1;
            }
        }

        copied
    }

    pub fn dropped_since(&self, last_seq: u64) -> u64 {
        let head = self.head.load(Ordering::Acquire);
        let oldest_live = head.saturating_sub(N as u64);
        oldest_live.saturating_sub(last_seq)
    }
}

impl<const N: usize> Default for AuditRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-channel mutable state. Modeled explicitly: slew-rate limiting,
/// auditability, and Spec 2 extensions all depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelState {
    pub last_output: u32,
    pub last_update_ns: u64,
    /// When set, every request resolves to `Safe(min)`.
    pub safe_hold: bool,
}

impl ChannelState {
    pub(crate) const DEFAULT: ChannelState = ChannelState {
        last_output: 0,
        last_update_ns: 0,
        safe_hold: false,
    };
}

use core::marker::PhantomData;

/// Number of GPIO pins addressable on RP1 bank 0 (mirrors `Rp1Gpio::NUM_PINS`).
const GPIO_PINS: usize = 28;
pub const AUDIT_CAPACITY: usize = 128;

/// The actuation reference monitor. Holds per-channel state for the two PWM
/// controllers (2 channels each) and the GPIO output pins.
pub struct Monitor<P: PhysicalProfile> {
    /// `[chip 0..2][channel 0..2]` where index = channel_number - 1.
    pwm: [[ChannelState; 2]; 2],
    /// `[pin 0..28]`.
    gpio: [ChannelState; GPIO_PINS],
    audit: AuditRing<AUDIT_CAPACITY>,
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> Monitor<P> {
    /// Create an empty monitor with every channel at the safe default.
    pub const fn new() -> Self {
        Self {
            pwm: [[ChannelState::DEFAULT; 2]; 2],
            gpio: [ChannelState::DEFAULT; GPIO_PINS],
            audit: AuditRing::new(),
            _profile: PhantomData,
        }
    }

    /// The envelope for a channel, or `None` if the channel is unknown.
    fn envelope(&self, ch: ChannelId) -> Option<Envelope> {
        if self.slot_index(ch).is_some() {
            Some(Envelope::from_profile::<P>(ch.kind))
        } else {
            None
        }
    }

    /// Validate a channel and return its `(is_pwm, i, j)` index, or `None`.
    fn slot_index(&self, ch: ChannelId) -> Option<(bool, usize, usize)> {
        match ch.kind {
            ActuationKind::PwmDuty => {
                if ch.chip < 2 && (1..=2).contains(&ch.channel) {
                    Some((true, ch.chip as usize, (ch.channel - 1) as usize))
                } else {
                    None
                }
            }
            ActuationKind::GpioLevel => {
                if ch.chip == 0 && (ch.channel as usize) < GPIO_PINS {
                    Some((false, ch.channel as usize, 0))
                } else {
                    None
                }
            }
        }
    }

    fn slot_mut(&mut self, ch: ChannelId) -> Option<&mut ChannelState> {
        let (is_pwm, i, j) = self.slot_index(ch)?;
        Some(if is_pwm {
            &mut self.pwm[i][j]
        } else {
            &mut self.gpio[i]
        })
    }

    /// Decide the fate of one actuation request.
    ///
    /// `now_ns` MUST be monotonically non-decreasing per channel; slew semantics
    /// are otherwise undefined. The implementation is defensive — `elapsed` is a
    /// `saturating_sub`, so backward time collapses to 0 (strictest slew limit),
    /// never widening the allowance.
    pub fn decide(
        &mut self,
        req: ActuationRequest,
        authority: Authority,
        source: AuditSource,
        now_ns: u64,
    ) -> Decision {
        let Some(env) = self.envelope(req.ch) else {
            let decision = Decision::Reject(RejectReason::UnknownChannel);
            self.audit_decision(req, authority, source, now_ns, decision);
            return decision;
        };
        let slot = self.slot_mut(req.ch).expect("known channel has a slot");
        let st = *slot;

        if st.safe_hold {
            slot.last_output = env.min;
            slot.last_update_ns = now_ns;
            let decision = Decision::Safe(env.min);
            self.audit_decision(req, authority, source, now_ns, decision);
            return decision;
        }

        let mut v = req.value.clamp(env.min, env.max);
        let mut clamped = v != req.value;

        if env.window_ns > 0 {
            let elapsed = now_ns.saturating_sub(st.last_update_ns);
            if elapsed < env.window_ns {
                let lo = st.last_output.saturating_sub(env.max_step).max(env.min);
                let hi = st.last_output.saturating_add(env.max_step).min(env.max);
                let nv = v.clamp(lo, hi);
                if nv != v {
                    clamped = true;
                    v = nv;
                }
            }
        }

        slot.last_output = v;
        slot.last_update_ns = now_ns;
        let decision = if clamped {
            Decision::Clamp(v)
        } else {
            Decision::Allow(v)
        };
        self.audit_decision(req, authority, source, now_ns, decision);
        decision
    }

    fn audit_decision(
        &mut self,
        req: ActuationRequest,
        authority: Authority,
        source: AuditSource,
        now_ns: u64,
        decision: Decision,
    ) {
        self.audit.emit(AuditRecord {
            seq: 0,
            t_ns: now_ns,
            source,
            channel: req.ch,
            authority,
            req_value: req.value,
            decision: decision.tag(),
            reason: decision.reason(),
        });
    }

    pub fn audit_snapshot(&self, out: &mut [AuditRecord]) -> usize {
        self.audit.snapshot(out)
    }

    pub fn audit_dropped_since(&self, last_seq: u64) -> u64 {
        self.audit.dropped_since(last_seq)
    }

    /// Latch a channel into safe-hold; subsequent `decide` calls return
    /// `Safe(min)`. A no-op on an unknown channel. (Spec 2 wires the production
    /// callers: the kernel e-stop latch and authority veto.)
    pub fn hold_safe(&mut self, ch: ChannelId) {
        if let Some(slot) = self.slot_mut(ch) {
            slot.safe_hold = true;
        }
    }

    /// Release a safe-hold. A no-op on an unknown channel.
    pub fn release(&mut self, ch: ChannelId) {
        if let Some(slot) = self.slot_mut(ch) {
            slot.safe_hold = false;
        }
    }
}

impl<P: PhysicalProfile> Default for Monitor<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{CloudProfile, EmbeddedProfile};

    #[test]
    fn pwm_envelope_from_embedded_profile() {
        let e = Envelope::from_profile::<EmbeddedProfile>(ActuationKind::PwmDuty);
        assert_eq!(
            e,
            Envelope {
                min: 0,
                max: 90,
                max_step: 20,
                window_ns: 1_000_000
            }
        );
    }

    #[test]
    fn gpio_envelope_is_fixed() {
        let e = Envelope::from_profile::<CloudProfile>(ActuationKind::GpioLevel);
        assert_eq!(
            e,
            Envelope {
                min: 0,
                max: 1,
                max_step: 1,
                window_ns: 0
            }
        );
    }

    #[test]
    fn decision_apply_mapping() {
        assert_eq!(Decision::Allow(42).apply(), (42, 0));
        assert_eq!(Decision::Clamp(90).apply(), (90, 0));
        assert_eq!(Decision::Safe(0).apply(), (0, -1));
        assert_eq!(
            Decision::Reject(RejectReason::UnknownChannel).apply(),
            (0, -1)
        );
    }

    fn pwm(chip: u8, channel: u8, value: u32) -> ActuationRequest {
        ActuationRequest {
            ch: ChannelId {
                kind: ActuationKind::PwmDuty,
                chip,
                channel,
            },
            value,
        }
    }

    fn decide(m: &mut Monitor<EmbeddedProfile>, req: ActuationRequest, now_ns: u64) -> Decision {
        m.decide(
            req,
            Authority::Learned,
            AuditSource::LearnedBehavior,
            now_ns,
        )
    }

    /// A timestamp far enough past 0 that a fresh channel's first decision is not
    /// slew-limited: elapsed from the default last_update_ns=0 exceeds the 1 ms
    /// window, so magnitude clamping is tested in isolation.
    const T0: u64 = 10_000_000; // 10 ms >> 1 ms window

    #[test]
    fn authority_ordering_is_total_safety_highest() {
        assert!(Authority::Learned < Authority::Mission);
        assert!(Authority::Mission < Authority::Operator);
        assert!(Authority::Operator < Authority::Safety);
    }

    #[test]
    fn decide_requires_authority_and_source_without_behavior_change() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        assert_eq!(
            m.decide(
                pwm(0, 1, 50),
                Authority::Learned,
                AuditSource::LearnedBehavior,
                T0
            ),
            Decision::Allow(50)
        );
    }

    #[test]
    fn decide_emits_attributed_audit_record() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        let req = pwm(0, 1, 50);
        assert_eq!(
            m.decide(req, Authority::Operator, AuditSource::SyscallPwm, T0),
            Decision::Allow(50)
        );

        let mut out = [AuditRecord::EMPTY; 4];
        assert_eq!(m.audit_snapshot(&mut out), 1);
        assert_eq!(out[0].seq, 0);
        assert_eq!(out[0].source, AuditSource::SyscallPwm);
        assert_eq!(out[0].authority, Authority::Operator);
        assert_eq!(out[0].channel, req.ch);
        assert_eq!(out[0].req_value, 50);
        assert_eq!(out[0].decision, DecisionTag::Allow);
        assert_eq!(out[0].reason, ReasonCode::None);
    }

    #[test]
    fn audit_ring_keeps_live_window_and_derives_dropped() {
        let mut ring = AuditRing::<2>::new();
        let mut record = AuditRecord {
            source: AuditSource::LearnedBehavior,
            authority: Authority::Learned,
            channel: pwm(0, 1, 0).ch,
            decision: DecisionTag::Allow,
            ..AuditRecord::EMPTY
        };

        record.req_value = 10;
        ring.emit(record);
        record.req_value = 20;
        ring.emit(record);
        record.req_value = 30;
        ring.emit(record);

        let mut out = [AuditRecord::EMPTY; 2];
        assert_eq!(ring.snapshot(&mut out), 2);
        assert_eq!(out[0].seq, 1);
        assert_eq!(out[0].req_value, 20);
        assert_eq!(out[1].seq, 2);
        assert_eq!(out[1].req_value, 30);
        assert_eq!(ring.dropped_since(0), 1);
    }

    #[test]
    fn in_range_request_is_allowed() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        assert_eq!(decide(&mut m, pwm(0, 1, 50), T0), Decision::Allow(50));
    }

    #[test]
    fn over_max_is_clamped() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        // 100 > ACT_DUTY_MAX (90) -> clamp to 90
        assert_eq!(decide(&mut m, pwm(0, 1, 100), T0), Decision::Clamp(90));
    }

    #[test]
    fn unknown_channel_is_rejected() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        // PWM channel 3 does not exist (valid channels are 1,2)
        assert_eq!(
            decide(&mut m, pwm(0, 3, 10), T0),
            Decision::Reject(RejectReason::UnknownChannel)
        );
        // PWM chip 2 does not exist
        assert_eq!(
            decide(&mut m, pwm(2, 1, 10), T0),
            Decision::Reject(RejectReason::UnknownChannel)
        );
    }

    #[test]
    fn slew_clamps_a_fast_jump() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        // establish baseline last_output = 10 (first call at T0 is not slew-limited)
        assert_eq!(decide(&mut m, pwm(0, 1, 10), T0), Decision::Allow(10));
        // 0.5 ms later (< 1 ms window): jump to 80 -> clamp to 10 + max_step(20) = 30
        assert_eq!(
            decide(&mut m, pwm(0, 1, 80), T0 + 500_000),
            Decision::Clamp(30)
        );
    }

    #[test]
    fn slew_allows_after_window_elapses() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        assert_eq!(decide(&mut m, pwm(0, 1, 10), T0), Decision::Allow(10));
        // 2 ms later (>= 1 ms window): full jump to 80 permitted (still <= max 90)
        assert_eq!(
            decide(&mut m, pwm(0, 1, 80), T0 + 2_000_000),
            Decision::Allow(80)
        );
    }

    #[test]
    fn backward_time_applies_strictest_slew() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        assert_eq!(decide(&mut m, pwm(0, 1, 10), T0), Decision::Allow(10));
        // now_ns moves backward: elapsed saturates to 0 (< window) -> slew clamp applies
        assert_eq!(
            decide(&mut m, pwm(0, 1, 80), T0 - 1),
            Decision::Clamp(30)
        );
    }

    #[test]
    fn safe_hold_forces_safe_then_releases() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        let ch = ChannelId {
            kind: ActuationKind::PwmDuty,
            chip: 0,
            channel: 1,
        };
        m.hold_safe(ch);
        assert_eq!(decide(&mut m, pwm(0, 1, 80), T0), Decision::Safe(0));
        m.release(ch);
        // a full window later so the post-release command is not slew-limited
        assert_eq!(
            decide(&mut m, pwm(0, 1, 50), T0 + 2_000_000),
            Decision::Allow(50)
        );
    }

    #[test]
    fn hold_safe_on_unknown_channel_is_a_noop() {
        let mut m = Monitor::<EmbeddedProfile>::new();
        // must not panic on an invalid channel
        m.hold_safe(ChannelId {
            kind: ActuationKind::PwmDuty,
            chip: 9,
            channel: 9,
        });
    }
}
